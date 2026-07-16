"""Tests for Docker event listener logic."""
import pytest
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

        mock_remove_ingress.assert_called_once_with("test-tunnel", "app.example.com")
        mock_remove_access.assert_called_once_with("app.example.com")
        assert db.get_container_route(container_id) is None

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

        mock_remove_ingress.assert_called_once_with("test-tunnel", "app.example.com")
        mock_remove_access.assert_called_once_with("app.example.com")
        assert "c2e882d1d64729245b6f0a2bc88ea3ed84d542a0daa4c945d0fb18ef18577a3d" not in docker_client._container_status
        assert "c2e882d1d64729245b6f0a2bc88ea3ed84d542a0daa4c945d0fb18ef18577a3d" not in docker_client._last_processed_time
