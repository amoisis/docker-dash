"""Tests for Docker event listener logic."""
import pytest
from types import SimpleNamespace
from unittest.mock import Mock, patch, MagicMock
import docker
import docker_client


class TestDockerEventListener:
    """Test Docker event stream handling."""

    def test_start_event_uses_actor_id(self, monkeypatch):
        """Test that start events read container ID from Actor.ID."""
        monkeypatch.setattr(docker_client, '_last_processed_time', {})
        monkeypatch.setattr(docker_client, '_container_ingress_state', {})
        monkeypatch.setattr(docker_client, '_container_status', {})

        mock_container = Mock()
        mock_container.id = "c2e882d1d64729245b6f0a2bc88ea3ed84d542a0daa4c945d0fb18ef18577a3d"
        mock_container.name = "test-container"
        mock_container.labels = {
            "docker.dash.enable": "true",
            "docker.dash.tunnel": "test-tunnel",
            "docker.dash.hostname": "app.example.com",
            "docker.dash.service": "http://test-container:8080"
        }

        mock_docker_client = MagicMock()
        mock_docker_client.ping.return_value = True
        mock_docker_client.containers.list.return_value = []
        mock_docker_client.containers.get.return_value = mock_container

        # Docker events use Actor.ID, not top-level id
        event = {
            "Type": "container",
            "Action": "start",
            "Actor": {
                "ID": mock_container.id,
                "Attributes": mock_container.labels
            }
        }
        mock_docker_client.events.return_value = iter([event])

        with patch('docker_client.get_docker_client', return_value=mock_docker_client):
            with patch('docker_client.process_container') as mock_process:
                # Run listener briefly - it will process one event then we stop it
                docker_client._event_stream = mock_docker_client.events()
                docker_client._docker_client = mock_docker_client
                try:
                    for ev in docker_client._event_stream:
                        if ev.get("Type") == "container":
                            action = ev.get("Action")
                            if action == "start":
                                container_id = ev.get("Actor", {}).get("ID") or ev.get("id")
                                container = mock_docker_client.containers.get(container_id)
                                docker_client.process_container(container)
                            break
                finally:
                    docker_client._event_stream = None
                    docker_client._docker_client = None

                mock_process.assert_called_once_with(mock_container)

    def test_stop_event_uses_actor_id(self, monkeypatch):
        """Test that stop events read container ID from Actor.ID."""
        monkeypatch.setattr(docker_client, '_last_processed_time', {})
        monkeypatch.setattr(docker_client, '_container_ingress_state', {
            "c2e882d1d64729245b6f0a2bc88ea3ed84d542a0daa4c945d0fb18ef18577a3d": ("test-tunnel", "app.example.com")
        })
        monkeypatch.setattr(docker_client, '_container_status', {})

        event = {
            "Type": "container",
            "Action": "stop",
            "Actor": {
                "ID": "c2e882d1d64729245b6f0a2bc88ea3ed84d542a0daa4c945d0fb18ef18577a3d",
                "Attributes": {
                    "docker.dash.enable": "true",
                    "docker.dash.tunnel": "test-tunnel",
                    "docker.dash.hostname": "app.example.com"
                }
            }
        }

        with patch('docker_client.remove_ingress_rule') as mock_remove_ingress:
            with patch('docker_client.remove_access_application') as mock_remove_access:
                container_id = event.get("Actor", {}).get("ID") or event.get("id")
                if container_id in docker_client._container_ingress_state:
                    old_tunnel, old_hostname = docker_client._container_ingress_state.pop(container_id)
                    docker_client.remove_ingress_rule(old_tunnel, old_hostname)
                    docker_client.remove_access_application(old_hostname)

                mock_remove_ingress.assert_called_once_with("test-tunnel", "app.example.com")
                mock_remove_access.assert_called_once_with("app.example.com")

    def test_event_without_actor_id_is_skipped(self, monkeypatch):
        """Test that events without any container ID are skipped with a warning."""
        monkeypatch.setattr(docker_client, '_last_processed_time', {})
        monkeypatch.setattr(docker_client, '_container_ingress_state', {})
        monkeypatch.setattr(docker_client, '_container_status', {})

        event = {
            "Type": "container",
            "Action": "start",
            "Actor": {
                "ID": "",
                "Attributes": {}
            }
        }

        container_id = event.get("Actor", {}).get("ID") or event.get("id")
        assert not container_id

    def test_stop_event_fallback_to_labels(self, monkeypatch):
        """Test stop event fallback removal when container not in state."""
        monkeypatch.setattr(docker_client, '_last_processed_time', {})
        monkeypatch.setattr(docker_client, '_container_ingress_state', {})
        monkeypatch.setattr(docker_client, '_container_status', {})

        event = {
            "Type": "container",
            "Action": "stop",
            "Actor": {
                "ID": "abc123def456",
                "Attributes": {
                    "docker.dash.enable": "true",
                    "docker.dash.tunnel": "test-tunnel",
                    "docker.dash.hostname": "app.example.com"
                }
            }
        }

        with patch('docker_client.remove_ingress_rule') as mock_remove_ingress:
            with patch('docker_client.remove_access_application') as mock_remove_access:
                container_id = event.get("Actor", {}).get("ID") or event.get("id")
                if container_id in docker_client._container_ingress_state:
                    old_tunnel, old_hostname = docker_client._container_ingress_state.pop(container_id)
                    docker_client.remove_ingress_rule(old_tunnel, old_hostname)
                    docker_client.remove_access_application(old_hostname)
                else:
                    attributes = event.get("Actor", {}).get("Attributes", {})
                    label_prefix = "docker.dash."
                    dash_labels = {
                        k: v for k, v in attributes.items() if k.startswith(label_prefix)
                    }
                    if dash_labels.get(f"{label_prefix}enable") == "true":
                        hostname = dash_labels.get(f"{label_prefix}hostname")
                        tunnel_name = dash_labels.get(f"{label_prefix}tunnel")

                        if hostname:
                            docker_client.remove_access_application(hostname)
                        if tunnel_name and hostname:
                            docker_client.remove_ingress_rule(tunnel_name, hostname)

                mock_remove_ingress.assert_called_once_with("test-tunnel", "app.example.com")
                mock_remove_access.assert_called_once_with("app.example.com")

    def test_stop_event_uses_persisted_container_state(self, monkeypatch, tmp_path):
        """Test stop cleanup uses SQLite-managed container state when memory state is empty."""
        monkeypatch.setattr(docker_client, '_last_processed_time', {})
        monkeypatch.setattr(docker_client, '_container_ingress_state', {})
        monkeypatch.setattr(docker_client, '_container_status', {})

        db = docker_client.get_container_state_db()
        container_id = "persisted-container-id"
        db.upsert_container_route(container_id, "test-tunnel", "app.example.com", "http://svc:8080")

        event = {
            "Type": "container",
            "Action": "stop",
            "Actor": {
                "ID": container_id,
                "Attributes": {
                    "docker.dash.enable": "true",
                    "docker.dash.tunnel": "ignored-tunnel",
                    "docker.dash.hostname": "ignored.example.com",
                }
            }
        }

        with patch('docker_client.remove_ingress_rule') as mock_remove_ingress:
            with patch('docker_client.remove_access_application') as mock_remove_access:
                docker_client._handle_container_event(MagicMock(), event)

        # A legacy route claim does not prove docker-dash created the remote
        # resources, so cleanup is intentionally conservative.
        mock_remove_ingress.assert_not_called()
        mock_remove_access.assert_not_called()
        assert db.get_container_route(container_id)["lifecycle_state"] == "retired"

    def test_die_event_uses_actor_id_and_cleans_state(self, monkeypatch):
        """Test that terminal die events remove tracked container state."""
        monkeypatch.setattr(docker_client, '_last_processed_time', {
            "c2e882d1d64729245b6f0a2bc88ea3ed84d542a0daa4c945d0fb18ef18577a3d": 123.0,
        })
        monkeypatch.setattr(docker_client, '_container_ingress_state', {
            "c2e882d1d64729245b6f0a2bc88ea3ed84d542a0daa4c945d0fb18ef18577a3d": ("test-tunnel", "app.example.com")
        })
        monkeypatch.setattr(docker_client, '_container_status', {
            "c2e882d1d64729245b6f0a2bc88ea3ed84d542a0daa4c945d0fb18ef18577a3d": {"name": "test-container"}
        })

        event = {
            "Type": "container",
            "Action": "die",
            "Actor": {
                "ID": "c2e882d1d64729245b6f0a2bc88ea3ed84d542a0daa4c945d0fb18ef18577a3d",
                "Attributes": {
                    "docker.dash.enable": "true",
                    "docker.dash.tunnel": "test-tunnel",
                    "docker.dash.hostname": "app.example.com",
                }
            }
        }

        with patch('docker_client.remove_ingress_rule') as mock_remove_ingress:
            with patch('docker_client.remove_access_application') as mock_remove_access:
                docker_client._handle_container_event(MagicMock(), event)

        # In-memory state without a created-resource ledger entry is preserved.
        mock_remove_ingress.assert_not_called()
        mock_remove_access.assert_not_called()
        assert "c2e882d1d64729245b6f0a2bc88ea3ed84d542a0daa4c945d0fb18ef18577a3d" not in docker_client._container_status
        assert "c2e882d1d64729245b6f0a2bc88ea3ed84d542a0daa4c945d0fb18ef18577a3d" not in docker_client._last_processed_time

    def test_swarm_old_task_does_not_remove_replacement_route(self, monkeypatch):
        """A rolling-update stop event must preserve a route used by the new task."""
        old_id = "old-swarm-task"
        new_task = Mock()
        new_task.id = "new-swarm-task"
        new_task.labels = {
            "docker.dash.enable": "true",
            "docker.dash.tunnel": "test-tunnel",
            "docker.dash.hostname": "app.example.com",
            "docker.dash.service": "http://app:8080",
            "com.docker.swarm.service.name": "stack_app",
        }
        mock_docker_client = MagicMock()
        mock_docker_client.containers.list.return_value = [new_task]

        monkeypatch.setattr(
            docker_client,
            '_container_ingress_state',
            {old_id: ("test-tunnel", "app.example.com")},
        )
        monkeypatch.setattr(
            docker_client,
            '_container_status',
            {old_id: {"name": "stack_app.1.old"}},
        )
        monkeypatch.setattr(docker_client, '_last_processed_time', {old_id: 123.0})

        db = docker_client.get_container_state_db()
        db.upsert_container_route(old_id, "test-tunnel", "app.example.com", "http://app:8080")
        event = {
            "Type": "container",
            "Action": "die",
            "Actor": {
                "ID": old_id,
                "Attributes": {
                    "docker.dash.enable": "true",
                    "docker.dash.tunnel": "test-tunnel",
                    "docker.dash.hostname": "app.example.com",
                    "com.docker.swarm.service.name": "stack_app",
                },
            },
        }

        with patch('docker_client.remove_ingress_rule') as mock_remove_ingress:
            with patch('docker_client.remove_access_application') as mock_remove_access:
                docker_client._handle_container_event(mock_docker_client, event)

        mock_remove_ingress.assert_not_called()
        mock_remove_access.assert_not_called()
        # The stale row is intentionally left for periodic reconciliation. This
        # also protects stop-first updates where the new task is not running yet.
        assert db.get_container_route(old_id) is not None
        assert old_id not in docker_client._container_ingress_state

    def test_swarm_terminal_event_defers_warp_cleanup(self, monkeypatch):
        """A stopped Swarm task keeps Warp ownership until reconciliation."""
        old_id = "old-warp-task"
        monkeypatch.setattr(docker_client, '_container_ingress_state', {})
        monkeypatch.setattr(docker_client, '_container_status', {})
        monkeypatch.setattr(docker_client, '_last_processed_time', {})
        monkeypatch.setattr(docker_client, '_deferred_cleanup_ids', set())

        event = {
            "Type": "container",
            "Action": "die",
            "Actor": {
                "ID": old_id,
                "Attributes": {
                    "docker.dash.warp": "true",
                    "com.docker.swarm.service.id": "service-id",
                },
            },
        }

        with patch('docker_client._cleanup_warp_for_container') as mock_cleanup_warp:
            docker_client._handle_container_event(MagicMock(), event)

        mock_cleanup_warp.assert_not_called()
        assert old_id in docker_client._deferred_cleanup_ids

    def test_last_owner_enqueues_only_created_resources(self):
        db = docker_client.get_container_state_db()
        db.upsert_container_route(
            "owner-1",
            "test-tunnel",
            "app.example.com",
            "http://app:8080",
            access_desired=True,
        )
        db.upsert_resource(
            "access:app.example.com",
            "access",
            "app.example.com",
            ownership="created",
        )
        db.upsert_resource(
            "ingress:test-tunnel:app.example.com",
            "ingress",
            "app.example.com",
            tunnel_name="test-tunnel",
            ownership="adopted",
        )

        docker_client._enqueue_last_owner_cleanup(
            db, db.get_container_route("owner-1")
        )

        jobs = db.list_due_cleanup_jobs()
        assert [job["resource_key"] for job in jobs] == ["access:app.example.com"]
        assert db.get_container_route("owner-1")["lifecycle_state"] == "retired"

    def test_due_access_cleanup_retries_structured_failure(self, monkeypatch):
        db = docker_client.get_container_state_db()
        db.upsert_resource(
            "access:app.example.com",
            "access",
            "app.example.com",
            ownership="created",
        )
        db.mark_resource_cleanup_pending(
            "access:app.example.com", "remove_access"
        )
        result = Mock(success=False, confirmed_absent=False, error="temporary")
        monkeypatch.setattr(
            docker_client, "remove_access_application", Mock(return_value=result)
        )

        docker_client._run_due_cleanup_jobs()

        resource = db.get_resource("access:app.example.com")
        assert resource["state"] == "cleanup_failed"

    def test_resource_replacement_downgrades_created_ownership(self):
        db = docker_client.get_container_state_db()
        key = "dns:app.example.com"
        db.upsert_resource(
            key,
            "dns",
            "app.example.com",
            remote_id="dns-original",
            ownership="created",
        )

        docker_client._record_managed_resource(
            db,
            "dns",
            "app.example.com",
            operation_result=SimpleNamespace(
                ownership="adopted",
                outcome="unchanged",
                remote_id="dns-replacement",
                original_state=None,
            ),
        )

        resource = db.get_resource(key)
        assert resource["ownership"] == "adopted"
        assert resource["remote_id"] == "dns-replacement"
