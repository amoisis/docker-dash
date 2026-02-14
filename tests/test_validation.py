"""
Tests for input validation functions.
"""
import pytest
import sys
sys.path.insert(0, '/workspaces/docker-dash/src')
import cloudflare_client


class TestHostnameValidation:
    """Test hostname validation function."""
    
    def test_valid_hostnames(self):
        """Test that valid hostnames pass validation."""
        valid_hostnames = [
            "example.com",
            "sub.example.com",
            "deep.sub.example.com",
            "my-app.example.com",
            "app123.example.com",
            "*.example.com",
            "*.sub.example.com",
            "example.co.uk",
            "test-app.mycompany.co.uk",
            "a.b.c.d.e.f.example.com"
        ]
        
        for hostname in valid_hostnames:
            # Should not raise exception
            cloudflare_client.validate_hostname(hostname)
    
    def test_invalid_hostnames(self):
        """Test that invalid hostnames raise ValidationError."""
        invalid_hostnames = [
            "",  # Empty
            "   ",  # Whitespace only
            None,  # None
            "example..com",  # Double dots
            "-example.com",  # Starts with hyphen
            "example-.com",  # Ends with hyphen
            "exa mple.com",  # Contains space
            "example.com-",  # Ends with hyphen
            "a" * 254,  # Too long (> 253 chars)
            "example",  # No TLD
            "example.",  # Trailing dot
            ".example.com",  # Leading dot
            "exam@ple.com",  # Invalid character
            "example$.com",  # Invalid character
        ]
        
        for hostname in invalid_hostnames:
            with pytest.raises(cloudflare_client.ValidationError):
                cloudflare_client.validate_hostname(hostname)


class TestTunnelNameValidation:
    """Test tunnel name validation function."""
    
    def test_valid_tunnel_names(self):
        """Test that valid tunnel names pass validation."""
        valid_names = [
            "tunnel-123",
            "cloudflared-container",
            "my_tunnel",
            "TUNNEL",
            "tunnel_with-both",
            "a",
            "tunnel123",
        ]
        
        for name in valid_names:
            # Should not raise exception
            cloudflare_client.validate_tunnel_name(name)
    
    def test_invalid_tunnel_names(self):
        """Test that invalid tunnel names raise ValidationError."""
        invalid_names = [
            "",  # Empty
            "   ",  # Whitespace only
            None,  # None
            "tunnel.name",  # Contains dot
            "tunnel@name",  # Invalid character
            "a" * 101,  # Too long (> 100 chars)
            "tunnel/name",  # Invalid character
        ]
        
        for name in invalid_names:
            with pytest.raises(cloudflare_client.ValidationError):
                cloudflare_client.validate_tunnel_name(name)


class TestServiceUrlValidation:
    """Test service URL validation function."""
    
    def test_valid_service_urls(self):
        """Test that valid service URLs pass validation."""
        valid_urls = [
            "http://container:8080",
            "https://backend:443",
            "http://192.168.1.1:3000",
            "https://api.internal.local",
            "http://service",
            "http://my-service:8080/path",
            "http_status:404",
            "http_status:200",
            "http_status:500",
        ]
        
        for url in valid_urls:
            # Should not raise exception
            cloudflare_client.validate_service_url(url)
    
    def test_invalid_service_urls(self):
        """Test that invalid service URLs raise ValidationError."""
        invalid_urls = [
            "",  # Empty
            "   ",  # Whitespace only
            None,  # None
            "ftp://server",  # Wrong protocol
            "container:8080",  # Missing protocol
            "http://",  # No host
            "http_status:999",  # Invalid status code
            "http_status:",  # No status code
            "http_status:abc",  # Non-numeric status code
        ]
        
        for url in invalid_urls:
            with pytest.raises(cloudflare_client.ValidationError):
                cloudflare_client.validate_service_url(url)


class TestValidationInFunctions:
    """Test that validation is properly integrated in API functions."""
    
    def test_add_ingress_rule_validates_tunnel_name(self, mocker):
        """Test that add_or_update_ingress_rule validates tunnel name."""
        # Mock the manager
        mock_manager = cloudflare_client.CloudflareManager()
        mock_manager.cf_client = mocker.MagicMock()
        mock_manager.account_id = "test-account"
        
        # Try with invalid tunnel name (contains invalid character)
        cloudflare_client.add_or_update_ingress_rule(
            "invalid@tunnel",  # Contains invalid character
            {"hostname": "test.example.com", "service": "http://backend:8080"},
            manager=mock_manager
        )
        
        # Should log error and return early (not call API)
        mock_manager.cf_client.zero_trust.tunnels.cloudflared.configurations.update.assert_not_called()
    
    def test_ensure_cname_validates_hostname(self, mocker):
        """Test that ensure_cname_record_exists validates hostname."""
        mock_manager = cloudflare_client.CloudflareManager()
        mock_manager.cf_client = mocker.MagicMock()
        
        # Try with invalid hostname
        cloudflare_client.ensure_cname_record_exists(
            "invalid..hostname",  # Double dots
            "tunnel-name",
            manager=mock_manager
        )
        
        # Should not proceed to API calls
        mock_manager.cf_client.dns.records.list.assert_not_called()
    
    def test_remove_access_application_validates_hostname(self, mocker):
        """Test that remove_access_application validates hostname."""
        mock_manager = cloudflare_client.CloudflareManager()
        mock_manager.cf_client = mocker.MagicMock()
        mock_manager.account_id = "test-account"
        
        # Try with invalid hostname
        cloudflare_client.remove_access_application(
            "invalid hostname with spaces",
            manager=mock_manager
        )
        
        # Should not proceed to API calls
        mock_manager.cf_client.zero_trust.access.applications.delete.assert_not_called()
