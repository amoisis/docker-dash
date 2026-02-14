"""Tests for cache refresh functionality."""
import pytest
from unittest.mock import Mock, patch
import threading
import time
import cloudflare_client


class TestCacheRefresh:
    """Test periodic cache refresh logic."""
    
    def test_cache_refresh_updates_tunnels(self, reset_cloudflare_state, mock_cloudflare_client, mock_tunnel):
        """Test that cache refresh updates tunnel information."""
        # Setup
        cloudflare_client._manager.cf_client = mock_cloudflare_client
        cloudflare_client._manager.account_id = "test-account"
        
        # Initial empty cache
        cloudflare_client._manager.tunnel_cache = {}
        
        # Mock API response
        mock_cloudflare_client.zero_trust.tunnels.list.return_value = [mock_tunnel]
        
        config = Mock()
        config.config = Mock()
        config.config.ingress = []
        mock_cloudflare_client.zero_trust.tunnels.cloudflared.configurations.get.return_value = config
        
        mock_cloudflare_client.zero_trust.access.applications.list.return_value = []
        mock_cloudflare_client.zero_trust.access.policies.list.return_value = []
        mock_cloudflare_client.zero_trust.identity_providers.list.return_value = []
        mock_cloudflare_client.zones.list.return_value = []
        
        # Execute
        cloudflare_client.refresh_all_caches()
        
        # Verify cache was populated
        assert mock_tunnel.id in cloudflare_client._manager.tunnel_cache
    
    def test_periodic_refresh_runs_in_background(self, reset_cloudflare_state, mock_cloudflare_client, monkeypatch):
        """Test that periodic refresh thread runs in background."""
        # Setup
        cloudflare_client._manager.cf_client = mock_cloudflare_client
        cloudflare_client._manager.account_id = "test-account"
        cloudflare_client._manager.cache_refresh_interval = 1  # 1 second for testing
        cloudflare_client._manager.stop_refresh = False
        
        # Mock refresh function
        refresh_count = [0]
        original_refresh = cloudflare_client.refresh_all_caches
        
        def mock_refresh(manager=None):
            refresh_count[0] += 1
        
        monkeypatch.setattr(cloudflare_client, 'refresh_all_caches', mock_refresh)
        
        # Start thread
        cloudflare_client.start_cache_refresh_thread()
        
        # Wait for at least one refresh
        time.sleep(2.5)
        
        # Stop thread
        cloudflare_client.stop_cache_refresh_thread()
        
        # Verify refresh happened at least once
        assert refresh_count[0] >= 1
    
    def test_cache_refresh_disabled_when_interval_zero(self, reset_cloudflare_state, monkeypatch):
        """Test that cache refresh is disabled when interval is 0."""
        # Setup - directly set manager attributes
        cloudflare_client._manager.cache_refresh_interval = 0
        cloudflare_client._manager.cache_refresh_thread = None
        
        # Execute
        cloudflare_client.start_cache_refresh_thread()
        
        # Verify no thread was started
        assert cloudflare_client._manager.cache_refresh_thread is None
    
    def test_stop_refresh_thread(self, reset_cloudflare_state, mock_cloudflare_client, monkeypatch):
        """Test that refresh thread stops gracefully."""
        # Setup
        cloudflare_client._manager.cf_client = mock_cloudflare_client
        cloudflare_client._manager.account_id = "test-account"
        cloudflare_client._manager.cache_refresh_interval = 10
        cloudflare_client._manager.stop_refresh = False
        
        # Mock refresh to do nothing
        monkeypatch.setattr(cloudflare_client, 'refresh_all_caches', lambda manager=None: None)
        
        # Start thread
        cloudflare_client.start_cache_refresh_thread()
        
        # Verify thread is running
        assert cloudflare_client._manager.cache_refresh_thread is not None
        assert cloudflare_client._manager.cache_refresh_thread.is_alive()
        
        # Stop thread
        cloudflare_client.stop_cache_refresh_thread()
        
        # Give it a moment to stop
        time.sleep(0.5)
        
        # Verify stop flag was set
        assert cloudflare_client._manager.stop_refresh is True
