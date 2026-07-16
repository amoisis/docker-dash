"""Tests for Warp split-tunnel support."""

import threading
from unittest.mock import MagicMock, patch

import cloudflare_client
import docker_client


class DummyManager:
    def __init__(self):
        self.cf_client = MagicMock()
        self.account_id = "acct-123"
        self._cache_lock = threading.RLock()


def test_parse_warp_labels_enabled_and_profiles():
    labels = {
        "docker.dash.warp": "true",
        "docker.dash.warp.profiles": "ProfileA,ProfileB",
    }
    result = docker_client.parse_warp_labels(labels)
    assert result["enabled"] is True
    assert result["profiles"] == "ProfileA,ProfileB"


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
    db.upsert_route("container-1", "profile-1", "managed.example.com")

    with patch("docker_client.get_warp_state_db", return_value=db), patch("docker_client.reconcile_warp_profiles") as reconcile_mock:
        state = docker_client._reconcile_container_warp_state(
            "container-1",
            "svc",
            {},
            {"docker.dash.warp": "false"},
        )

    assert state["enabled"] is False
    assert db.get_routes_for_container("container-1") == []
    reconcile_mock.assert_called_once_with(["profile-1"])


def test_reconcile_warp_tunnel_routes_adds_ingress_for_each_hostname():
    dash_labels = {
        "docker.dash.tunnel": "test-tunnel",
        "docker.dash.service": "http://svc:8080/",
    }
    warp_state = {
        "enabled": True,
        "hostnames": ["a.example.com", "b.example.com"],
    }

    with patch("docker_client.add_or_update_ingress_rule") as ingress_mock:
        docker_client._reconcile_warp_tunnel_routes("svc", dash_labels, warp_state)

    assert ingress_mock.call_count == 2
    ingress_mock.assert_any_call("test-tunnel", {"hostname": "a.example.com", "service": "http://svc:8080"})
    ingress_mock.assert_any_call("test-tunnel", {"hostname": "b.example.com", "service": "http://svc:8080"})


def test_reconcile_warp_tunnel_routes_skips_without_tunnel_or_service():
    dash_labels = {"docker.dash.tunnel": "test-tunnel"}
    warp_state = {"enabled": True, "hostnames": ["a.example.com"]}

    with patch("docker_client.add_or_update_ingress_rule") as ingress_mock:
        docker_client._reconcile_warp_tunnel_routes("svc", dash_labels, warp_state)

    ingress_mock.assert_not_called()
