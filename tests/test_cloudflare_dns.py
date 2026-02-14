"""Tests for Cloudflare DNS and zone management."""
import pytest
from unittest.mock import Mock
import cloudflare_client


class TestDNSZoneDetection:
    """Test DNS zone detection, especially for multi-part TLDs."""
    
    def test_simple_tld_zone_detection(self, reset_cloudflare_state, mock_cloudflare_client):
        """Test zone detection for simple TLD (.com, .net)."""
        # Setup
        cloudflare_client._manager.cf_client = mock_cloudflare_client
        
        zone = Mock()
        zone.id = "zone-123"
        zone.name = "example.com"
        cloudflare_client._manager.zones_cache = {"example.com": zone}
        
        # Mock tunnel
        tunnel = Mock()
        tunnel.id = "tunnel-123"
        tunnel.name = "test-tunnel"
        cloudflare_client._manager.tunnel_cache = {
            "tunnel-123": {
                "tunnel_object": tunnel,
                "connections": []
            }
        }
        
        # Mock DNS list (no existing records)
        mock_cloudflare_client.dns.records.list.return_value = []
        mock_cloudflare_client.dns.records.create.return_value = Mock()
        
        # Execute
        cloudflare_client.ensure_cname_record_exists("app.example.com", "test-tunnel")
        
        # Verify CNAME was created with correct zone
        assert mock_cloudflare_client.dns.records.create.called
        call_kwargs = mock_cloudflare_client.dns.records.create.call_args[1]
        assert call_kwargs['zone_id'] == "zone-123"
    
    def test_multi_part_tld_zone_detection(self, reset_cloudflare_state, mock_cloudflare_client):
        """Test zone detection for multi-part TLD (.co.uk, .com.au)."""
        # Setup
        cloudflare_client._manager.cf_client = mock_cloudflare_client
        
        zone = Mock()
        zone.id = "zone-456"
        zone.name = "example.co.uk"
        cloudflare_client._manager.zones_cache = {"example.co.uk": zone}
        
        # Mock tunnel
        tunnel = Mock()
        tunnel.id = "tunnel-456"
        tunnel.name = "uk-tunnel"
        cloudflare_client._manager.tunnel_cache = {
            "tunnel-456": {
                "tunnel_object": tunnel,
                "connections": []
            }
        }
        
        # Mock DNS operations
        mock_cloudflare_client.dns.records.list.return_value = []
        mock_cloudflare_client.dns.records.create.return_value = Mock()
        
        # Execute - should find example.co.uk, not just co.uk
        cloudflare_client.ensure_cname_record_exists("app.example.co.uk", "uk-tunnel")
        
        # Verify CNAME was attempted with correct zone
        assert mock_cloudflare_client.dns.records.create.called
        call_kwargs = mock_cloudflare_client.dns.records.create.call_args[1]
        assert call_kwargs['zone_id'] == "zone-456"
    
    def test_subdomain_with_multi_part_tld(self, reset_cloudflare_state, mock_cloudflare_client):
        """Test deeply nested subdomain with multi-part TLD."""
        # Setup
        cloudflare_client._manager.cf_client = mock_cloudflare_client
        
        zone = Mock()
        zone.id = "zone-789"
        zone.name = "mycompany.co.uk"
        cloudflare_client._manager.zones_cache = {"mycompany.co.uk": zone}
        
        # Mock tunnel
        tunnel = Mock()
        tunnel.id = "tunnel-789"
        tunnel.name = "company-tunnel"
        cloudflare_client._manager.tunnel_cache = {
            "tunnel-789": {
                "tunnel_object": tunnel,
                "connections": []
            }
        }
        
        # Mock DNS operations
        mock_cloudflare_client.dns.records.list.return_value = []
        mock_cloudflare_client.dns.records.create.return_value = Mock()
        
        # Execute with deep subdomain
        cloudflare_client.ensure_cname_record_exists("api.staging.mycompany.co.uk", "company-tunnel")
        
        # Verify correct zone was used
        assert mock_cloudflare_client.dns.records.create.called
        call_kwargs = mock_cloudflare_client.dns.records.create.call_args[1]
        assert call_kwargs['zone_id'] == "zone-789"
    
    def test_zone_not_found(self, reset_cloudflare_state, mock_cloudflare_client):
        """Test handling when zone is not in cache."""
        # Setup
        cloudflare_client._manager.cf_client = mock_cloudflare_client
        cloudflare_client._manager.zones_cache = {}  # Empty cache
        
        # Mock tunnel
        tunnel = Mock()
        tunnel.id = "tunnel-999"
        tunnel.name = "test-tunnel"
        cloudflare_client._manager.tunnel_cache = {
            "tunnel-999": {
                "tunnel_object": tunnel,
                "connections": []
            }
        }
        
        # Execute - should handle gracefully
        cloudflare_client.ensure_cname_record_exists("app.notinzone.com", "test-tunnel")
        
        # Verify no API calls were made
        assert not mock_cloudflare_client.dns.records.create.called


class TestDNSRecordManagement:
    """Test DNS record creation and deletion."""
    
    def test_cname_already_exists(self, reset_cloudflare_state, mock_cloudflare_client):
        """Test that existing CNAME records are not recreated."""
        # Setup
        cloudflare_client._manager.cf_client = mock_cloudflare_client
        
        zone = Mock()
        zone.id = "zone-123"
        zone.name = "example.com"
        cloudflare_client._manager.zones_cache = {"example.com": zone}
        
        tunnel = Mock()
        tunnel.id = "tunnel-123"
        tunnel.name = "test-tunnel"
        cloudflare_client._manager.tunnel_cache = {
            "tunnel-123": {
                "tunnel_object": tunnel,
                "connections": []
            }
        }
        
        # Mock existing DNS record
        existing_record = Mock()
        existing_record.id = "dns-existing"
        mock_cloudflare_client.dns.records.list.return_value = [existing_record]
        
        # Execute
        cloudflare_client.ensure_cname_record_exists("app.example.com", "test-tunnel")
        
        # Verify create was NOT called
        assert not mock_cloudflare_client.dns.records.create.called
    
    def test_remove_multiple_dns_records(self, reset_cloudflare_state, mock_cloudflare_client):
        """Test removal of duplicate DNS records."""
        # Setup
        cloudflare_client._manager.cf_client = mock_cloudflare_client
        
        zone = Mock()
        zone.id = "zone-123"
        zone.name = "example.com"
        cloudflare_client._manager.zones_cache = {"example.com": zone}
        
        # Mock multiple DNS records (duplicates)
        record1 = Mock()
        record1.id = "dns-1"
        record2 = Mock()
        record2.id = "dns-2"
        mock_cloudflare_client.dns.records.list.return_value = [record1, record2]
        mock_cloudflare_client.dns.records.delete.return_value = Mock()
        
        # Execute
        cloudflare_client.remove_cname_record("app.example.com")
        
        # Verify both records were deleted
        assert mock_cloudflare_client.dns.records.delete.call_count == 2
    
    def test_remove_nonexistent_dns_record(self, reset_cloudflare_state, mock_cloudflare_client):
        """Test removal when no DNS records exist."""
        # Setup
        cloudflare_client._manager.cf_client = mock_cloudflare_client
        
        zone = Mock()
        zone.id = "zone-123"
        zone.name = "example.com"
        cloudflare_client._manager.zones_cache = {"example.com": zone}
        
        # Mock no existing records
        mock_cloudflare_client.dns.records.list.return_value = []
        
        # Execute - should handle gracefully
        cloudflare_client.remove_cname_record("app.example.com")
        
        # Verify delete was NOT called
        assert not mock_cloudflare_client.dns.records.delete.called
