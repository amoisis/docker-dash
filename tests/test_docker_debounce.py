"""Tests for Docker event debouncing logic."""
import pytest
from unittest.mock import Mock, patch
import time
import docker_client


class TestDockerDebouncing:
    """Test debounce logic to prevent rapid event processing."""
    
    def test_debounce_prevents_rapid_processing(self, mock_container, monkeypatch):
        """Test that rapid events for same container are debounced."""
        # Setup
        monkeypatch.setattr(docker_client, '_last_processed_time', {})
        monkeypatch.setattr(docker_client, '_container_ingress_state', {})
        monkeypatch.setattr(docker_client, '_debounce_delay_seconds', 5)
        
        # Mock Cloudflare functions
        with patch('docker_client.add_or_update_ingress_rule') as mock_add:
            # First call - should process
            docker_client.process_container(mock_container)
            assert mock_add.call_count == 1
            
            # Immediate second call - should be debounced
            docker_client.process_container(mock_container)
            assert mock_add.call_count == 1  # Still 1, not 2
            
            # Wait for debounce period
            docker_client._last_processed_time[mock_container.id] = time.time() - 10
            
            # Third call after debounce - should process
            docker_client.process_container(mock_container)
            assert mock_add.call_count == 2
    
    def test_different_containers_not_debounced(self, monkeypatch):
        """Test that different containers are processed independently."""
        # Setup
        monkeypatch.setattr(docker_client, '_last_processed_time', {})
        monkeypatch.setattr(docker_client, '_container_ingress_state', {})
        
        container1 = Mock()
        container1.id = "container-1"
        container1.name = "app1"
        container1.labels = {
            "docker.dash.enable": "true",
            "docker.dash.tunnel": "tunnel1",
            "docker.dash.hostname": "app1.example.com",
            "docker.dash.service": "http://app1:8080"
        }
        
        container2 = Mock()
        container2.id = "container-2"
        container2.name = "app2"
        container2.labels = {
            "docker.dash.enable": "true",
            "docker.dash.tunnel": "tunnel2",
            "docker.dash.hostname": "app2.example.com",
            "docker.dash.service": "http://app2:8080"
        }
        
        # Mock Cloudflare functions
        with patch('docker_client.add_or_update_ingress_rule') as mock_add:
            # Process both containers rapidly
            docker_client.process_container(container1)
            docker_client.process_container(container2)
            
            # Both should be processed (different containers)
            assert mock_add.call_count == 2
    
    def test_state_tracking_prevents_duplicate_rules(self, mock_container, monkeypatch):
        """Test that state tracking remembers container ingress mappings."""
        # Setup
        monkeypatch.setattr(docker_client, '_last_processed_time', {})
        monkeypatch.setattr(docker_client, '_container_ingress_state', {})
        monkeypatch.setattr(docker_client, '_debounce_delay_seconds', 0)  # Disable debounce for this test
        
        with patch('docker_client.add_or_update_ingress_rule') as mock_add:
            # First processing - creates state
            docker_client.process_container(mock_container)
            
            assert mock_container.id in docker_client._container_ingress_state
            assert docker_client._container_ingress_state[mock_container.id] == (
                "test-tunnel",
                "app.example.com"
            )
    
    def test_disabled_container_not_processed(self, mock_container, monkeypatch):
        """Test that containers with enable=false are not processed."""
        # Setup
        monkeypatch.setattr(docker_client, '_last_processed_time', {})
        monkeypatch.setattr(docker_client, '_container_ingress_state', {})
        
        # Disable the container
        mock_container.labels["docker.dash.enable"] = "false"
        
        with patch('docker_client.add_or_update_ingress_rule') as mock_add:
            docker_client.process_container(mock_container)
            
            # Should not process
            assert not mock_add.called
    
    def test_missing_labels_not_processed(self, monkeypatch):
        """Test that containers with incomplete labels are not processed."""
        # Setup
        monkeypatch.setattr(docker_client, '_last_processed_time', {})
        monkeypatch.setattr(docker_client, '_container_ingress_state', {})
        
        incomplete_container = Mock()
        incomplete_container.id = "incomplete"
        incomplete_container.name = "incomplete-app"
        incomplete_container.labels = {
            "docker.dash.enable": "true",
            "docker.dash.tunnel": "test-tunnel"
            # Missing hostname and service
        }
        
        with patch('docker_client.add_or_update_ingress_rule') as mock_add:
            docker_client.process_container(incomplete_container)
            
            # Should not process (missing required labels)
            assert not mock_add.called
