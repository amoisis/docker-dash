import json
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from src.cloudflare_client import ContainerStateDB


@pytest.fixture
def state_db(tmp_path):
    return ContainerStateDB(str(tmp_path / "state.db"))


def test_migrates_legacy_routes_idempotently_with_safe_defaults(tmp_path):
    path = tmp_path / "legacy.db"
    with sqlite3.connect(path) as conn:
        conn.execute(
            """
            CREATE TABLE managed_container_routes (
                container_id TEXT PRIMARY KEY,
                tunnel_name TEXT NOT NULL,
                hostname TEXT NOT NULL,
                service TEXT,
                updated_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            INSERT INTO managed_container_routes
                (container_id, tunnel_name, hostname, service, updated_at)
            VALUES ('old', 'tunnel', 'app.example.com', 'http://old', 'then')
            """
        )

    db = ContainerStateDB(str(path))
    ContainerStateDB(str(path))

    assert db.get_container_route("old") == {
        "container_id": "old",
        "owner_id": "old",
        "owner_kind": "container",
        "tunnel_name": "tunnel",
        "hostname": "app.example.com",
        "service": "http://old",
        "access_desired": False,
        "lifecycle_state": "active",
        "updated_at": "then",
    }


def test_route_upsert_remains_backwards_compatible_and_reactivates_claim(state_db):
    state_db.upsert_container_route(
        "one", "tunnel", "app.example.com", "http://one"
    )
    state_db.retire_container_route("one")
    state_db.upsert_container_route(
        "one", "tunnel", "app.example.com", "http://new", access_desired=True
    )

    claim = state_db.get_container_route("one")
    assert claim["service"] == "http://new"
    assert claim["access_desired"] is True
    assert claim["lifecycle_state"] == "active"


def test_retiring_and_counting_route_and_access_claims(state_db):
    state_db.upsert_container_route(
        "one", "tunnel", "app.example.com", access_desired=True
    )
    state_db.upsert_container_route(
        "two", "tunnel", "app.example.com", access_desired=False
    )
    state_db.upsert_container_route(
        "three", "other", "app.example.com", access_desired=True
    )

    assert state_db.count_active_route_claims("tunnel", "app.example.com") == 2
    assert state_db.count_active_route_claims(
        "tunnel", "app.example.com", exclude_container_id="one"
    ) == 1
    assert state_db.count_active_access_claims("app.example.com") == 2

    retired = state_db.retire_container_route("one")
    assert retired["lifecycle_state"] == "retired"
    assert state_db.count_active_route_claims("tunnel", "app.example.com") == 1
    assert state_db.count_active_access_claims("app.example.com") == 1


def test_resource_ledger_round_trip_and_identity_constraint(state_db):
    resource = state_db.upsert_resource(
        "ingress:tunnel:app.example.com",
        "ingress",
        "app.example.com",
        tunnel_name="tunnel",
        remote_id="remote",
        ownership="created",
        original_state_json={"service": "http://old"},
    )

    assert resource["ownership"] == "created"
    assert resource["original_state_json"] == '{"service": "http://old"}'
    assert resource["state"] == "active"

    updated = state_db.upsert_resource(
        "ingress:tunnel:app.example.com",
        "ingress",
        "app.example.com",
        tunnel_name="tunnel",
        remote_id="new",
        ownership="adopted",
    )
    assert updated["remote_id"] == "new"
    assert updated["ownership"] == "adopted"

    with pytest.raises(sqlite3.IntegrityError):
        state_db.upsert_resource(
            "different-key",
            "ingress",
            "app.example.com",
            tunnel_name="tunnel",
        )


def test_resource_default_ownership_is_conservative(state_db):
    resource = state_db.upsert_resource(
        "access:app.example.com", "access", "app.example.com"
    )
    assert resource["ownership"] == "legacy_unknown"


def test_cleanup_outbox_lifecycle_and_due_filtering(state_db):
    state_db.upsert_resource(
        "dns:app.example.com",
        "dns",
        "app.example.com",
        ownership="created",
    )
    state_db.mark_resource_cleanup_pending(
        "dns:app.example.com", "remove_cname"
    )

    jobs = state_db.list_due_cleanup_jobs(
        datetime.now(timezone.utc) + timedelta(seconds=1)
    )
    assert len(jobs) == 1
    assert jobs[0]["resource_key"] == "dns:app.example.com"
    assert jobs[0]["action"] == "remove_cname"
    assert jobs[0]["attempts"] == 0
    assert jobs[0]["resource_state"] == "cleanup_pending"

    retry_at = datetime.now(timezone.utc) + timedelta(hours=1)
    state_db.record_cleanup_failure(
        "dns:app.example.com", "temporary failure", retry_at
    )
    assert state_db.get_resource("dns:app.example.com")["state"] == "cleanup_failed"
    assert state_db.list_due_cleanup_jobs(
        datetime.now(timezone.utc) + timedelta(minutes=1)
    ) == []

    jobs = state_db.list_due_cleanup_jobs(retry_at + timedelta(seconds=1))
    assert jobs[0]["attempts"] == 1
    assert jobs[0]["last_error"] == "temporary failure"

    state_db.complete_cleanup("dns:app.example.com")
    assert state_db.get_resource("dns:app.example.com") is None
    assert state_db.list_due_cleanup_jobs(
        datetime.now(timezone.utc) + timedelta(days=1)
    ) == []


def test_mark_pending_is_idempotent_and_preserves_attempt_count(state_db):
    state_db.upsert_resource("access:app", "access", "app.example.com")
    state_db.mark_resource_cleanup_pending("access:app", "remove_access")
    state_db.record_cleanup_failure(
        "access:app",
        "failed",
        datetime.now(timezone.utc) - timedelta(seconds=1),
    )

    state_db.mark_resource_cleanup_pending("access:app", "restore_access")
    job = state_db.list_due_cleanup_jobs(
        datetime.now(timezone.utc) + timedelta(seconds=1)
    )[0]
    assert job["action"] == "restore_access"
    assert job["attempts"] == 1
    assert job["last_error"] is None


def test_unknown_cleanup_operations_fail_explicitly(state_db):
    with pytest.raises(KeyError):
        state_db.mark_resource_cleanup_pending("missing", "remove")


def test_owner_claim_aliases_and_hostname_claim_count(state_db):
    state_db.upsert_route_claim(
        "swarm-service:one",
        "swarm_service",
        "tunnel-a",
        "shared.example.com",
    )
    state_db.upsert_route_claim(
        "swarm-service:two",
        "swarm_service",
        "tunnel-b",
        "shared.example.com",
    )

    claim = state_db.get_route_claim("swarm-service:one")
    assert claim["owner_id"] == "swarm-service:one"
    assert claim["owner_kind"] == "swarm_service"
    assert state_db.count_active_hostname_claims("shared.example.com") == 2
    assert (
        state_db.count_active_hostname_claims(
            "shared.example.com", exclude_owner_id="swarm-service:one"
        )
        == 1
    )

    state_db.retire_route_claim("swarm-service:one")
    assert state_db.count_active_hostname_claims("shared.example.com") == 1
    with pytest.raises(KeyError):
        state_db.record_cleanup_failure("missing", "error", "later")


def test_delete_retired_claims_keeps_claims_with_related_jobs(state_db):
    state_db.upsert_container_route("keep", "tunnel", "keep.example.com")
    state_db.upsert_container_route("delete", "tunnel", "delete.example.com")
    state_db.retire_container_route("keep")
    state_db.retire_container_route("delete")
    state_db.upsert_resource(
        "dns:keep",
        "dns",
        "keep.example.com",
        ownership="created",
    )
    state_db.mark_resource_cleanup_pending("dns:keep", "remove_cname")

    assert state_db.delete_retired_claims_without_jobs() == 1
    assert state_db.get_container_route("keep") is not None
    assert state_db.get_container_route("delete") is None

    state_db.complete_cleanup("dns:keep")
    assert state_db.delete_retired_claims_without_jobs() == 1
    assert state_db.get_container_route("keep") is None


def test_existing_delete_and_list_apis_include_new_claim_fields(state_db):
    state_db.upsert_container_route(
        "one", "tunnel", "app.example.com", access_desired=True
    )

    listed = state_db.list_container_routes()
    assert listed[0]["access_desired"] is True
    assert listed[0]["lifecycle_state"] == "active"
    deleted = state_db.delete_container_route("one")
    assert deleted["container_id"] == "one"
    assert state_db.list_container_routes() == []


def test_canonical_resource_key_helpers():
    assert (
        ContainerStateDB.resource_key(
            "ingress", "app.example.com", tunnel_name="main"
        )
        == "ingress:main:app.example.com"
    )
    assert (
        ContainerStateDB.resource_key("dns", "app.example.com")
        == "dns:app.example.com"
    )
    assert (
        ContainerStateDB.resource_key("access", "app.example.com")
        == "access:app.example.com"
    )
    with pytest.raises(ValueError):
        ContainerStateDB.resource_key("ingress", "app.example.com")
    with pytest.raises(ValueError):
        ContainerStateDB.resource_key("unknown", "app.example.com")


def test_cancel_cleanup_is_atomic_and_idempotent(state_db):
    key = "dns:app.example.com"
    state_db.upsert_resource(key, "dns", "app.example.com", ownership="created")
    state_db.mark_resource_cleanup_pending(key, "remove_cname")

    assert state_db.cancel_cleanup(key) is True
    assert state_db.get_resource(key)["state"] == "active"
    assert state_db.list_due_cleanup_jobs(
        datetime.now(timezone.utc) + timedelta(days=1)
    ) == []
    assert state_db.cancel_cleanup(key) is True
    assert state_db.cancel_cleanup("missing") is False


def test_reactivating_resource_removes_stale_cleanup_job(state_db):
    key = "dns:app.example.com"
    state_db.upsert_resource(key, "dns", "app.example.com", ownership="created")
    state_db.mark_resource_cleanup_pending(key, "remove_cname")

    state_db.upsert_resource(
        key,
        "dns",
        "app.example.com",
        remote_id="current",
        ownership="created",
        state="active",
    )

    assert state_db.get_resource(key)["state"] == "active"
    assert state_db.list_due_cleanup_jobs(
        datetime.now(timezone.utc) + timedelta(days=1)
    ) == []


def test_resource_original_state_serializes_nested_datetimes(state_db):
    created_at = datetime(2026, 7, 30, 4, 55, tzinfo=timezone.utc)
    modified_at = datetime(2026, 7, 30, 4, 56, 1)

    state_db.upsert_resource(
        "dns:app.example.com",
        "dns",
        "app.example.com",
        remote_id="dns-record-id",
        ownership="adopted",
        original_state_json={
            "created_on": created_at,
            "metadata": {"modified_on": modified_at},
        },
    )

    stored = state_db.get_resource("dns:app.example.com")
    assert json.loads(stored["original_state_json"]) == {
        "created_on": created_at.isoformat(),
        "metadata": {"modified_on": modified_at.isoformat()},
    }


def test_foreign_keys_are_enabled_and_cleanup_jobs_cascade(state_db):
    key = "dns:app.example.com"
    state_db.upsert_resource(key, "dns", "app.example.com")
    state_db.mark_resource_cleanup_pending(key, "remove_cname")

    with state_db._connect() as conn:
        assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        conn.execute(
            "DELETE FROM managed_cloudflare_resources WHERE resource_key = ?",
            (key,),
        )
        jobs = conn.execute(
            "SELECT COUNT(*) FROM cloudflare_cleanup_jobs WHERE resource_key = ?",
            (key,),
        ).fetchone()[0]
    assert jobs == 0


def test_lifecycle_triggers_protect_fresh_and_migrated_tables(state_db):
    state_db.upsert_container_route("one", "tunnel", "app.example.com")
    with state_db._connect() as conn:
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                """
                UPDATE managed_container_routes
                SET lifecycle_state = 'invalid'
                WHERE container_id = 'one'
                """
            )


def test_resource_and_action_validation(state_db):
    with pytest.raises(ValueError):
        state_db.upsert_resource(
            "dns:app.example.com",
            "dns",
            "app.example.com",
            ownership="unowned",
        )
    with pytest.raises(ValueError):
        state_db.upsert_resource(
            "dns:app.example.com",
            "dns",
            "app.example.com",
            state="unknown",
        )

    state_db.upsert_resource(
        "dns:app.example.com", "dns", "app.example.com"
    )
    with pytest.raises(ValueError):
        state_db.mark_resource_cleanup_pending("dns:app.example.com", "")
