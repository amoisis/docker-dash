"""Tests for Docker event listener reconnect and reconciliation logic."""
import pytest
import threading
import time
from unittest.mock import Mock, patch, MagicMock
import docker
import docker_client


class TestDockerReconnect:
    """Test event stream reconnect behavior."""

    def test_event_stream_reconnects_after_error(self, monkeypatch):
        """Test that the listener reconnects when the event stream fails."""
        monkeypatch.setattr(docker_client, '_last_processed_time', {})
        monkeypatch.setattr(docker_client, '_container_ingress_state', {})
        monkeypatch.setattr(docker_client, '_container_status', {})
        monkeypatch.setattr(docker_client, '_reconcile_interval_seconds', 0)

        mock_container = Mock()
        mock_container.id = "abc123"
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

        # First stream raises, second stream yields one event then ends
        event = {
            "Type": "container",
            "Action": "start",
            "Actor": {"ID": mock_container.id, "Attributes": mock_container.labels}
        }

        class BrokenStream:
            def __iter__(self):
                raise Exception("stream broken")
            def close(self):
                pass

        class WorkingStream:
            def __iter__(self):
                return iter([event])
            def close(self):
                pass

        call_count = [0]
        def events_side_effect(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return BrokenStream()
            return WorkingStream()

        mock_docker_client.events.side_effect = events_side_effect
        mock_docker_client.containers.get.return_value = mock_container

        with patch('docker_client.get_docker_client', return_value=mock_docker_client):
            with patch('docker_client.process_container') as mock_process:
                # Start listener in a thread, stop after a short delay
                docker_client._listener_stop_event.clear()
                listener_thread = threading.Thread(
                    target=docker_client._listen_for_events,
                    args=(mock_docker_client,),
                    daemon=True
                )
                listener_thread.start()
                # Wait long enough for reconnect delay (1s) + event processing
                time.sleep(1.5)
                docker_client._listener_stop_event.set()
                listener_thread.join(timeout=3)

                # Should have processed the event from the second stream
                mock_process.assert_called_once_with(mock_container)


class TestDockerReconciliation:
    """Test periodic reconciliation logic."""

    def test_reconciliation_adds_missing_containers(self, monkeypatch):
        """Test that reconciliation processes running containers not in state."""
        monkeypatch.setattr(docker_client, '_last_processed_time', {})
        monkeypatch.setattr(docker_client, '_container_ingress_state', {})
        monkeypatch.setattr(docker_client, '_container_status', {})
        monkeypatch.setattr(docker_client, '_reconcile_interval_seconds', 1)

        mock_container = Mock()
        mock_container.id = "abc123"
        mock_container.name = "test-container"
        mock_container.labels = {
            "docker.dash.enable": "true",
            "docker.dash.tunnel": "test-tunnel",
            "docker.dash.hostname": "app.example.com",
            "docker.dash.service": "http://test-container:8080"
        }

        mock_docker_client = MagicMock()
        mock_docker_client.containers.list.return_value = [mock_container]

        with patch('docker_client.process_container') as mock_process:
            docker_client._listener_stop_event.clear()
            reconcile_thread = threading.Thread(
                target=docker_client._reconcile_loop,
                args=(mock_docker_client,),
                daemon=True
            )
            reconcile_thread.start()
            time.sleep(1.5)
            docker_client._listener_stop_event.set()
            reconcile_thread.join(timeout=2)

            mock_process.assert_called_once_with(mock_container)

    def test_reconciliation_removes_stale_containers(self, monkeypatch):
        """Test that reconciliation removes ingress rules for stopped containers."""
        monkeypatch.setattr(docker_client, '_last_processed_time', {})
        monkeypatch.setattr(docker_client, '_container_ingress_state', {
            "stale-id": ("test-tunnel", "app.example.com")
        })
        monkeypatch.setattr(docker_client, '_container_status', {})
        monkeypatch.setattr(docker_client, '_reconcile_interval_seconds', 1)

        mock_docker_client = MagicMock()
        mock_docker_client.containers.list.return_value = []

        with patch('docker_client.remove_ingress_rule') as mock_remove_ingress:
            with patch('docker_client.remove_access_application') as mock_remove_access:
                docker_client._listener_stop_event.clear()
                reconcile_thread = threading.Thread(
                    target=docker_client._reconcile_loop,
                    args=(mock_docker_client,),
                    daemon=True
                )
                reconcile_thread.start()
                time.sleep(1.5)
                docker_client._listener_stop_event.set()
                reconcile_thread.join(timeout=2)

                mock_remove_ingress.assert_called_once_with("test-tunnel", "app.example.com")
                mock_remove_access.assert_called_once_with("app.example.com")
