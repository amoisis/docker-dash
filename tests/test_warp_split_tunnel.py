"""Tests for Warp split-tunnel support."""

import threading
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import cloudflare_client
import docker_client


class DummyManager:
    def __init__(self):
        self.cf_client = MagicMock()
        self.account_id = "acct-123"
        self._cache_lock = threading.RLock()
        tunnel = SimpleNamespace(id="tunnel-123", name="EvoT1Server")
        self.tunnel_cache = {tunnel.id: {"tunnel_object": tunnel}}


def test_parse_warp_labels_enabled_and_profiles():
    labels = {
        "docker.dash.warp": "true",
        "docker.dash.warp.profiles": "ProfileA,ProfileB",
        "docker.dash.tunnel": "EvoT1Server",
    }
    result = docker_client.parse_warp_labels(labels)
    assert result["enabled"] is True
    assert result["profiles"] == "ProfileA,ProfileB"
    assert result["tunnel"] == "EvoT1Server"


def test_extract_traefik_hostnames_from_host_rules():
    labels = {
        "traefik.http.routers.web.rule": "Host(`app.example.com`) && PathPrefix(`/`)",
        "traefik.http.routers.api.rule": "Host(`api.example.com`, `app.example.com`)",
    }
    assert docker_client.extract_traefik_hostnames(labels) == ["api.example.com", "app.example.com"]


def test_warp_state_db_upsert_and_delete_by_container(tmp_path):
    db = cloudflare_client.WarpStateDB(str(tmp_path / "warp.db"))
    db.upsert_route("container-1", "profile-1", "app.example.com")
    db.upsert_route("container-1", "profile-1", "api.example.com")

    routes = set(db.get_routes_for_container("container-1"))
    assert routes == {("profile-1", "app.example.com"), ("profile-1", "api.example.com")}

    removed = set(db.delete_routes_for_container("container-1"))
    assert removed == routes
    assert db.get_routes_for_container("container-1") == []


def test_warp_state_db_private_hostname_claims_are_shared(tmp_path):
    db = cloudflare_client.WarpStateDB(str(tmp_path / "warp.db"))
    db.upsert_private_hostname_claim(
        "owner-1", "EvoT1Server", "app.example.com"
    )
    db.upsert_private_hostname_claim(
        "owner-2", "EvoT1Server", "app.example.com"
    )

    assert db.get_private_hostname_claims("owner-1") == [
        ("EvoT1Server", "app.example.com")
    ]
    assert (
        db.count_private_hostname_claims("EvoT1Server", "app.example.com")
        == 2
    )

    db.remove_private_hostname_claim(
        "owner-1", "EvoT1Server", "app.example.com"
    )
    assert (
        db.count_private_hostname_claims("EvoT1Server", "app.example.com")
        == 1
    )


def test_resolve_device_policy_ids_by_name_and_uuid():
    manager = DummyManager()

    policy = MagicMock()
    policy.name = "ProfileA"
    policy.id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"

    manager.cf_client.zero_trust.devices.policies.custom.list.return_value = [policy]

    resolved = cloudflare_client.resolve_device_policy_ids(
        "ProfileA,bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
        manager,
    )

    assert resolved == [
        "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
        "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
    ]


def test_reconcile_warp_profile_keeps_manual_entries_and_updates_managed(tmp_path):
    manager = DummyManager()
    db = cloudflare_client.WarpStateDB(str(tmp_path / "warp.db"))

    db.upsert_route("container-1", "profile-1", "managed.example.com")

    manual_entry = {"host": "manual.example.com", "description": "custom"}
    stale_managed = {"host": "old-managed.example.com", "description": cloudflare_client.WARP_MANAGED_DESCRIPTION}
    manager.cf_client.zero_trust.devices.policies.custom.includes.get.return_value = [manual_entry, stale_managed]

    with patch("cloudflare_client.get_warp_state_db", return_value=db):
        cloudflare_client._reconcile_warp_profile("profile-1", manager)

    update_call = manager.cf_client.zero_trust.devices.policies.custom.includes.update.call_args
    payload = update_call.kwargs["body"]

    assert {entry.get("host") for entry in payload if entry.get("host")} == {
        "manual.example.com",
        "managed.example.com",
    }
    assert {entry.get("description") for entry in payload if entry.get("host") and entry.get("host") == "managed.example.com"} == {
        cloudflare_client.WARP_MANAGED_DESCRIPTION
    }


def test_reconcile_container_warp_state_disables_and_cleans_existing(tmp_path):
    db = cloudflare_client.WarpStateDB(str(tmp_path / "warp.db"))
    db.upsert_private_hostname_claim(
        "container-1", "EvoT1Server", "managed.example.com"
    )

    with patch("docker_client.get_warp_state_db", return_value=db):
        state = docker_client._reconcile_container_warp_state(
            "container-1",
            "svc",
            {},
            {"docker.dash.warp": "false"},
        )

    assert state["enabled"] is False
    assert db.get_private_hostname_claims("container-1") == []


def test_reconcile_warp_creates_private_hostname_route():
    warp_db = MagicMock()
    warp_db.get_private_hostname_claims.return_value = []
    warp_db.get_routes_for_owner.return_value = []
    container_db = MagicMock()
    dash_labels = {
        "docker.dash.warp": "true",
        "docker.dash.tunnel": "test-tunnel",
    }
    labels = {
        **dash_labels,
        "traefik.http.routers.web.rule": "Host(`a.example.com`)",
    }
    result = SimpleNamespace(
        success=True,
        ownership="created",
        remote_id="route-1",
        outcome="created",
        original_state=None,
    )

    with (
        patch("docker_client.get_warp_state_db", return_value=warp_db),
        patch("docker_client.get_container_state_db", return_value=container_db),
        patch(
            "docker_client.ensure_private_hostname_route",
            return_value=result,
        ) as ensure_mock,
        patch("docker_client._record_managed_resource") as record_mock,
    ):
        state = docker_client._reconcile_container_warp_state(
            "owner-1", "svc", labels, dash_labels
        )

    assert state["active"] is True
    ensure_mock.assert_called_once_with("a.example.com", "test-tunnel")
    record_mock.assert_called_once()
    warp_db.upsert_private_hostname_claim.assert_called_once_with(
        "owner-1", "test-tunnel", "a.example.com"
    )


def test_reconcile_warp_requires_tunnel_but_not_service():
    warp_db = MagicMock()
    warp_db.get_private_hostname_claims.return_value = []
    warp_db.get_routes_for_owner.return_value = []
    labels = {
        "docker.dash.warp": "true",
        "traefik.http.routers.web.rule": "Host(`a.example.com`)",
    }

    with patch("docker_client.get_warp_state_db", return_value=warp_db):
        state = docker_client._reconcile_container_warp_state(
            "owner-1", "svc", labels, labels
        )

    assert state["active"] is False
    assert state["misconfigured"] is True
    assert "docker.dash.tunnel" in state["reason"]


def test_ensure_private_hostname_route_creates_exact_route():
    manager = DummyManager()
    manager.cf_client.zero_trust.networks.hostname_routes.list.return_value = []
    manager.cf_client.zero_trust.networks.hostname_routes.create.return_value = (
        SimpleNamespace(id="route-1")
    )

    result = cloudflare_client.ensure_private_hostname_route(
        "app.example.com", "EvoT1Server", manager
    )

    assert result.success is True
    assert result.ownership == "created"
    assert result.remote_id == "route-1"
    manager.cf_client.zero_trust.networks.hostname_routes.create.assert_called_once_with(
        account_id="acct-123",
        hostname="app.example.com",
        tunnel_id="tunnel-123",
        comment=cloudflare_client.WARP_MANAGED_DESCRIPTION,
    )


def test_ensure_private_hostname_route_adopts_matching_route():
    manager = DummyManager()
    existing = SimpleNamespace(
        id="route-1",
        hostname="app.example.com",
        tunnel_id="tunnel-123",
        tunnel_name="EvoT1Server",
    )
    manager.cf_client.zero_trust.networks.hostname_routes.list.return_value = [
        existing
    ]

    result = cloudflare_client.ensure_private_hostname_route(
        "app.example.com", "EvoT1Server", manager
    )

    assert result.success is True
    assert result.outcome == "unchanged"
    assert result.ownership == "adopted"
    manager.cf_client.zero_trust.networks.hostname_routes.create.assert_not_called()


def test_private_hostname_cleanup_waits_for_last_owner(tmp_path):
    warp_db = cloudflare_client.WarpStateDB(str(tmp_path / "warp.db"))
    state_db = cloudflare_client.ContainerStateDB(str(tmp_path / "state.db"))
    for owner_id in ("owner-1", "owner-2"):
        warp_db.upsert_private_hostname_claim(
            owner_id, "EvoT1Server", "app.example.com"
        )
    key = state_db.resource_key(
        "hostname_route", "app.example.com", tunnel_name="EvoT1Server"
    )
    state_db.upsert_resource(
        key,
        "hostname_route",
        "app.example.com",
        tunnel_name="EvoT1Server",
        remote_id="route-1",
        ownership="created",
    )

    with (
        patch("docker_client.get_warp_state_db", return_value=warp_db),
        patch("docker_client.get_container_state_db", return_value=state_db),
    ):
        docker_client._cleanup_warp_for_container("owner-1")
        assert state_db.list_due_cleanup_jobs() == []

        docker_client._cleanup_warp_for_container("owner-2")
        jobs = state_db.list_due_cleanup_jobs()

    assert len(jobs) == 1
    assert jobs[0]["action"] == "remove_hostname_route"
    assert jobs[0]["remote_id"] == "route-1"


def test_private_hostname_cleanup_preserves_adopted_route(tmp_path):
    warp_db = cloudflare_client.WarpStateDB(str(tmp_path / "warp.db"))
    state_db = cloudflare_client.ContainerStateDB(str(tmp_path / "state.db"))
    warp_db.upsert_private_hostname_claim(
        "owner-1", "EvoT1Server", "app.example.com"
    )
    key = state_db.resource_key(
        "hostname_route", "app.example.com", tunnel_name="EvoT1Server"
    )
    state_db.upsert_resource(
        key,
        "hostname_route",
        "app.example.com",
        tunnel_name="EvoT1Server",
        remote_id="route-1",
        ownership="adopted",
    )

    with (
        patch("docker_client.get_warp_state_db", return_value=warp_db),
        patch("docker_client.get_container_state_db", return_value=state_db),
    ):
        docker_client._cleanup_warp_for_container("owner-1")

    assert state_db.list_due_cleanup_jobs() == []


def test_cleanup_worker_deletes_owned_private_hostname_route(tmp_path):
    warp_db = cloudflare_client.WarpStateDB(str(tmp_path / "warp.db"))
    state_db = cloudflare_client.ContainerStateDB(str(tmp_path / "state.db"))
    key = state_db.resource_key(
        "hostname_route", "app.example.com", tunnel_name="EvoT1Server"
    )
    state_db.upsert_resource(
        key,
        "hostname_route",
        "app.example.com",
        tunnel_name="EvoT1Server",
        remote_id="route-1",
        ownership="created",
    )
    state_db.mark_resource_cleanup_pending(key, "remove_hostname_route")
    removed = SimpleNamespace(
        success=True, confirmed_absent=False, outcome="removed"
    )

    with (
        patch("docker_client.get_warp_state_db", return_value=warp_db),
        patch("docker_client.get_container_state_db", return_value=state_db),
        patch(
            "docker_client.remove_private_hostname_route",
            return_value=removed,
        ) as remove_mock,
    ):
        docker_client._run_due_cleanup_jobs()

    remove_mock.assert_called_once_with(
        "app.example.com",
        "EvoT1Server",
        remote_id="route-1",
    )
    assert state_db.get_resource(key) is None
