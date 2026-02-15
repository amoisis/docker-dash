"""Tests for Cloudflare Access Application management."""
import pytest
from unittest.mock import Mock
import cloudflare_client


class TestAccessApplicationManagement:
    """Test Access Application creation and management."""
    
    def test_create_access_application_with_policies(self, reset_cloudflare_state, mock_cloudflare_client):
        """Test creating an Access Application with multiple policies."""
        # Setup
        cloudflare_client._manager.cf_client = mock_cloudflare_client
        cloudflare_client._manager.account_id = "test-account"
        
        # Mock policies in cache
        policy1 = Mock()
        policy1.id = "policy-1"
        policy1.name = "Allow-Admins"
        
        policy2 = Mock()
        policy2.id = "policy-2"
        policy2.name = "Require-MFA"
        
        cloudflare_client._manager.access_policies_cache = {
            "Allow-Admins": policy1,
            "Require-MFA": policy2
        }
        
        # Mock IdP
        idp = Mock()
        idp.id = "idp-123"
        idp.name = "AzureAD"
        cloudflare_client._manager.idps_cache = {"AzureAD": idp}
        
        # Mock no existing app
        cloudflare_client._manager.access_apps_cache = {}
        
        # Mock API response
        created_app = Mock()
        created_app.id = "app-new"
        created_app.domain = "app.example.com"
        mock_cloudflare_client.zero_trust.access.applications.create.return_value = created_app
        
        # Execute
        access_config = {
            "policy": "Allow-Admins,Require-MFA",
            "loginmethods": "AzureAD"
        }
        cloudflare_client.add_or_update_access_application("app.example.com", access_config)
        
        # Verify create was called
        assert mock_cloudflare_client.zero_trust.access.applications.create.called
        
        # Verify cache was updated (explicit dictionary key check to avoid CodeQL warnings)
        cache_keys = list(cloudflare_client._manager.access_apps_cache.keys())
        assert "app.example.com" in cache_keys
    
    def test_update_existing_access_application(self, reset_cloudflare_state, mock_cloudflare_client):
        """Test updating an existing Access Application."""
        # Setup
        cloudflare_client._manager.cf_client = mock_cloudflare_client
        cloudflare_client._manager.account_id = "test-account"
        
        # Mock policy
        policy = Mock()
        policy.id = "policy-1"
        policy.name = "Allow-All"
        cloudflare_client._manager.access_policies_cache = {"Allow-All": policy}
        
        # Mock existing app
        existing_app = Mock()
        existing_app.id = "app-existing"
        existing_app.domain = "app.example.com"
        cloudflare_client._manager.access_apps_cache = {"app.example.com": existing_app}
        
        # Mock API response
        updated_app = Mock()
        updated_app.id = "app-existing"
        updated_app.domain = "app.example.com"
        mock_cloudflare_client.zero_trust.access.applications.update.return_value = updated_app
        
        # Execute
        access_config = {"policy": "Allow-All"}
        cloudflare_client.add_or_update_access_application("app.example.com", access_config)
        
        # Verify update was called (not create)
        assert mock_cloudflare_client.zero_trust.access.applications.update.called
        assert not mock_cloudflare_client.zero_trust.access.applications.create.called
    
    def test_access_application_with_instant_auth(self, reset_cloudflare_state, mock_cloudflare_client):
        """Test instant auth is enabled with single IdP."""
        # Setup
        cloudflare_client._manager.cf_client = mock_cloudflare_client
        cloudflare_client._manager.account_id = "test-account"
        
        policy = Mock()
        policy.id = "policy-1"
        policy.name = "Allow-Users"
        cloudflare_client._manager.access_policies_cache = {"Allow-Users": policy}
        
        idp = Mock()
        idp.id = "idp-single"
        idp.name = "Google"
        cloudflare_client._manager.idps_cache = {"Google": idp}
        
        cloudflare_client._manager.access_apps_cache = {}
        
        mock_cloudflare_client.zero_trust.access.applications.create.return_value = Mock()
        
        # Execute with instant auth requested
        access_config = {
            "policy": "Allow-Users",
            "loginmethods": "Google",
            "instantauth": "true"
        }
        cloudflare_client.add_or_update_access_application("app.example.com", access_config)
        
        # Verify instant auth was enabled in payload
        call_kwargs = mock_cloudflare_client.zero_trust.access.applications.create.call_args[1]
        assert call_kwargs.get('auto_redirect_to_identity') is True
    
    def test_access_application_instant_auth_disabled_with_multiple_idps(self, reset_cloudflare_state, mock_cloudflare_client):
        """Test instant auth is NOT enabled with multiple IdPs."""
        # Setup
        cloudflare_client._manager.cf_client = mock_cloudflare_client
        cloudflare_client._manager.account_id = "test-account"
        
        policy = Mock()
        policy.id = "policy-1"
        policy.name = "Allow-Users"
        cloudflare_client._manager.access_policies_cache = {"Allow-Users": policy}
        
        idp1 = Mock()
        idp1.id = "idp-1"
        idp1.name = "Google"
        
        idp2 = Mock()
        idp2.id = "idp-2"
        idp2.name = "AzureAD"
        
        cloudflare_client._manager.idps_cache = {"Google": idp1, "AzureAD": idp2}
        cloudflare_client._manager.access_apps_cache = {}
        
        mock_cloudflare_client.zero_trust.access.applications.create.return_value = Mock()
        
        # Execute with instant auth requested but multiple IdPs
        access_config = {
            "policy": "Allow-Users",
            "loginmethods": "Google,AzureAD",
            "instantauth": "true"
        }
        cloudflare_client.add_or_update_access_application("app.example.com", access_config)
        
        # Verify instant auth was NOT enabled (multiple IdPs)
        call_kwargs = mock_cloudflare_client.zero_trust.access.applications.create.call_args[1]
        assert call_kwargs.get('auto_redirect_to_identity') is False
    
    def test_access_application_missing_policy(self, reset_cloudflare_state, mock_cloudflare_client):
        """Test handling when requested policy doesn't exist."""
        # Setup
        cloudflare_client._manager.cf_client = mock_cloudflare_client
        cloudflare_client._manager.account_id = "test-account"
        cloudflare_client._manager.access_policies_cache = {}  # Empty cache
        cloudflare_client._manager.access_apps_cache = {}
        
        # Execute with non-existent policy
        access_config = {"policy": "NonExistent-Policy"}
        cloudflare_client.add_or_update_access_application("app.example.com", access_config)
        
        # Verify no API calls were made
        assert not mock_cloudflare_client.zero_trust.access.applications.create.called
    
    def test_remove_access_application(self, reset_cloudflare_state, mock_cloudflare_client):
        """Test removing an Access Application."""
        # Setup
        cloudflare_client._manager.cf_client = mock_cloudflare_client
        cloudflare_client._manager.account_id = "test-account"
        
        # Mock existing app
        existing_app = Mock()
        existing_app.id = "app-to-delete"
        existing_app.domain = "app.example.com"
        cloudflare_client._manager.access_apps_cache = {"app.example.com": existing_app}
        
        mock_cloudflare_client.zero_trust.access.applications.delete.return_value = Mock()
        
        # Execute
        cloudflare_client.remove_access_application("app.example.com")
        
        # Verify delete was called
        assert mock_cloudflare_client.zero_trust.access.applications.delete.called
        
        # Verify cache was cleared
        assert "app.example.com" not in cloudflare_client._manager.access_apps_cache
    
    def test_remove_nonexistent_access_application(self, reset_cloudflare_state, mock_cloudflare_client):
        """Test removing application that doesn't exist."""
        # Setup
        cloudflare_client._manager.cf_client = mock_cloudflare_client
        cloudflare_client._manager.account_id = "test-account"
        cloudflare_client._manager.access_apps_cache = {}
        
        # Execute - should handle gracefully
        cloudflare_client.remove_access_application("nonexistent.example.com")
        
        # Verify no API calls were made
        assert not mock_cloudflare_client.zero_trust.access.applications.delete.called
