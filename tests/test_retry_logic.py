"""Tests for Cloudflare retry logic."""
import pytest
from unittest.mock import Mock
import cloudflare
import cloudflare_client


def _make_api_error(status_code: int, message: str = "error"):
    """Create a cloudflare.APIError with a status code."""
    error = cloudflare.APIError(message=message, request=None, body=None)
    error.status_code = status_code
    return error


class TestRetryLogic:
    """Test retry decorator behavior."""

    def test_retryable_5xx_error_is_retried(self):
        """Test that 5xx errors are retried."""
        error = _make_api_error(500, "Internal Server Error")
        mock_func = Mock(side_effect=error)

        wrapped = cloudflare_client.retry_on_api_error(max_retries=2, initial_delay=0.01)(lambda: mock_func())

        with pytest.raises(cloudflare.APIError):
            wrapped()

        assert mock_func.call_count == 2

    def test_4xx_error_not_retried(self):
        """Test that 4xx client errors are not retried."""
        error = _make_api_error(400, "Bad Request")
        mock_func = Mock(side_effect=error)

        wrapped = cloudflare_client.retry_on_api_error(max_retries=3, initial_delay=0.01)(lambda: mock_func())

        with pytest.raises(cloudflare.APIError):
            wrapped()

        assert mock_func.call_count == 1

    def test_429_rate_limit_is_retried(self):
        """Test that 429 rate limit errors are retried."""
        error = _make_api_error(429, "Rate Limited")
        mock_func = Mock(side_effect=error)

        wrapped = cloudflare_client.retry_on_api_error(max_retries=2, initial_delay=0.01)(lambda: mock_func())

        with pytest.raises(cloudflare.APIError):
            wrapped()

        assert mock_func.call_count == 2

    def test_success_after_retry(self):
        """Test that function succeeds after a retryable error."""
        error = _make_api_error(503, "Temporary")
        mock_func = Mock(side_effect=[error, "success"])

        wrapped = cloudflare_client.retry_on_api_error(max_retries=3, initial_delay=0.01)(lambda: mock_func())

        result = wrapped()
        assert result == "success"
        assert mock_func.call_count == 2
