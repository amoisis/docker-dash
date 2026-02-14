"""Tests for Cloudflare ingress rule management."""
import pytest
from unittest.mock import Mock, patch, MagicMock
import cloudflare_client


class TestIngressRuleManagement:
    """Test ingress rule add/update/remove operations."""
    
    def test_add_new_ingress_rule(self, reset_cloudflare_state, mock_cloudflare_client, mock_tunnel, mock_ingress_rule):
        """Test adding a new ingress rule to a tunnel."""
        # Setup
        cloudflare_client._manager.cf_client = mock_cloudflare_client
        cloudflare_client._manager.account_id = "test-account"
        
        # Create mock tunnel with existing connection
        existing_rule = Mock()
        existing_rule.hostname = "existing.example.com"
        existing_rule.service = "http://existing:8080"
        existing_rule.dict = lambda: {"hostname": "existing.example.com", "service": "http://existing:8080"}
        
        cloudflare_client._manager.tunnel_cache[mock_tunnel.id] = {
            "tunnel_object": mock_tunnel,
            "connections": [existing_rule]
        }
        
        # Mock API response
        updated_config = Mock()
        updated_config.config = Mock()
        updated_config.config.ingress = [existing_rule, mock_ingress_rule]
        mock_cloudflare_client.zero_trust.tunnels.cloudflared.configurations.update.return_value = updated_config
        
        # Mock DNS operations
        mock_cloudflare_client.dns.records.list.return_value = []
        mock_cloudflare_client.dns.records.create.return_value = Mock()
        
        # Add zone to cache
        zone = Mock()
        zone.id = "zone-123"
        zone.name = "example.com"
        cloudflare_client._manager.zones_cache["example.com"] = zone
        
        # Execute
        new_rule = {"hostname": "app.example.com", "service": "http://app:8080"}
        cloudflare_client.add_or_update_ingress_rule("test-tunnel", new_rule)
        
        # Verify tunnel update was called
        assert mock_cloudflare_client.zero_trust.tunnels.cloudflared.configurations.update.called
        
        # Verify cache was updated
        assert len(cloudflare_client._manager.tunnel_cache[mock_tunnel.id]["connections"]) == 2
    
    def test_update_existing_ingress_rule(self, reset_cloudflare_state, mock_cloudflare_client, mock_tunnel):
        """Test updating an existing ingress rule (same hostname, different service)."""
        # Setup
        cloudflare_client._manager.cf_client = mock_cloudflare_client
        cloudflare_client._manager.account_id = "test-account"
        
        # Create mock tunnel with existing rule
        existing_rule = Mock()
        existing_rule.hostname = "app.example.com"
        existing_rule.service = "http://old-service:8080"
        existing_rule.dict = lambda: {"hostname": "app.example.com", "service": "http://old-service:8080"}
        
        cloudflare_client._manager.tunnel_cache[mock_tunnel.id] = {
            "tunnel_object": mock_tunnel,
            "connections": [existing_rule]
        }
        
        # Mock API response
        new_rule_mock = Mock()
        new_rule_mock.hostname = "app.example.com"
        new_rule_mock.service = "http://new-service:9090"
        
        updated_config = Mock()
        updated_config.config = Mock()
        updated_config.config.ingress = [new_rule_mock]
        mock_cloudflare_client.zero_trust.tunnels.cloudflared.configurations.update.return_value = updated_config
        
        # Mock DNS operations
        mock_cloudflare_client.dns.records.list.return_value = [Mock(id="dns-123")]
        
        # Add zone to cache
        zone = Mock()
        zone.id = "zone-123"
        zone.name = "example.com"
        cloudflare_client._manager.zones_cache["example.com"] = zone
        
        # Execute - update with new service URL
        new_rule = {"hostname": "app.example.com", "service": "http://new-service:9090"}
        cloudflare_client.add_or_update_ingress_rule("test-tunnel", new_rule)
        
        # Verify update was called
        assert mock_cloudflare_client.zero_trust.tunnels.cloudflared.configurations.update.called
    
    def test_remove_ingress_rule(self, reset_cloudflare_state, mock_cloudflare_client, mock_tunnel):
        """Test removing an ingress rule from a tunnel."""
        # Setup
        cloudflare_client._manager.cf_client = mock_cloudflare_client
        cloudflare_client._manager.account_id = "test-account"
        
        # Create mock tunnel with rule to remove
        rule_to_remove = Mock()
        rule_to_remove.hostname = "app.example.com"
        rule_to_remove.service = "http://app:8080"
        rule_to_remove.dict = lambda: {"hostname": "app.example.com", "service": "http://app:8080"}
        
        cloudflare_client._manager.tunnel_cache[mock_tunnel.id] = {
            "tunnel_object": mock_tunnel,
            "connections": [rule_to_remove]
        }
        
        # Mock API response (empty connections after removal)
        updated_config = Mock()
        updated_config.config = Mock()
        updated_config.config.ingress = []
        mock_cloudflare_client.zero_trust.tunnels.cloudflared.configurations.update.return_value = updated_config
        
        # Mock DNS operations
        dns_record = Mock()
        dns_record.id = "dns-123"
        mock_cloudflare_client.dns.records.list.return_value = [dns_record]
        mock_cloudflare_client.dns.records.delete.return_value = Mock()
        
        # Add zone to cache
        zone = Mock()
        zone.id = "zone-123"
        zone.name = "example.com"
        cloudflare_client._manager.zones_cache["example.com"] = zone
        
        # Execute
        cloudflare_client.remove_ingress_rule("test-tunnel", "app.example.com")
        
        # Verify tunnel update was called
        assert mock_cloudflare_client.zero_trust.tunnels.cloudflared.configurations.update.called
        
        # Verify DNS record was deleted
        assert mock_cloudflare_client.dns.records.delete.called
        
        # Verify cache was updated
        assert len(cloudflare_client._manager.tunnel_cache[mock_tunnel.id]["connections"]) == 0
    
    def test_ingress_rule_not_found(self, reset_cloudflare_state, mock_cloudflare_client, mock_tunnel):
        """Test removing a non-existent ingress rule."""
        # Setup
        cloudflare_client._manager.cf_client = mock_cloudflare_client
        cloudflare_client._manager.account_id = "test-account"
        
        cloudflare_client._manager.tunnel_cache[mock_tunnel.id] = {
            "tunnel_object": mock_tunnel,
            "connections": []
        }
        
        # Execute - should handle gracefully
        cloudflare_client.remove_ingress_rule("test-tunnel", "nonexistent.example.com")
        
        # Verify no API calls were made
        assert not mock_cloudflare_client.zero_trust.tunnels.cloudflared.configurations.update.called
    
    def test_tunnel_not_found(self, reset_cloudflare_state, mock_cloudflare_client):
        """Test adding rule to non-existent tunnel."""
        # Setup
        cloudflare_client._manager.cf_client = mock_cloudflare_client
        cloudflare_client._manager.account_id = "test-account"
        cloudflare_client._manager.tunnel_cache = {}  # Empty cache
        
        # Execute
        new_rule = {"hostname": "app.example.com", "service": "http://app:8080"}
        cloudflare_client.add_or_update_ingress_rule("nonexistent-tunnel", new_rule)
        
        # Verify no API calls were made
        assert not mock_cloudflare_client.zero_trust.tunnels.cloudflared.configurations.update.called
