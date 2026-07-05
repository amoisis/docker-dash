"""Tests for cache refresh thread using event-based sleep."""
import pytest
import threading
import time
from unittest.mock import Mock
import cloudflare_client


class TestCacheRefreshEventSleep:
    """Test that cache refresh uses event-based sleep for fast shutdown."""

    def test_stop_refresh_interrupts_sleep(self, reset_cloudflare_state, mock_cloudflare_client, monkeypatch):
        """Test that stop_cache_refresh_thread interrupts the sleep immediately."""
        cloudflare_client._manager.cf_client = mock_cloudflare_client
        cloudflare_client._manager.account_id = "test-account"
        cloudflare_client._manager.cache_refresh_interval = 3600  # 1 hour
        cloudflare_client._manager.stop_refresh = False
        cloudflare_client._manager._stop_refresh_event.clear()

        monkeypatch.setattr(cloudflare_client, 'refresh_all_caches', lambda manager=None: None)

        cloudflare_client.start_cache_refresh_thread()
        assert cloudflare_client._manager.cache_refresh_thread is not None

        start = time.time()
        cloudflare_client.stop_cache_refresh_thread()
        elapsed = time.time() - start

        assert elapsed < 2.0, f"Stop took too long: {elapsed}s"
        assert not cloudflare_client._manager.cache_refresh_thread.is_alive()
