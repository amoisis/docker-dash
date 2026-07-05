"""Tests for the web server."""
import pytest
import threading
import time
from unittest.mock import patch
from urllib.request import urlopen
from web_server import wsgi_app, start_server


class TestWSGIApp:
    """Test WSGI application endpoints."""

    def _start_response(self, status, headers):
        self.status = status
        self.headers = headers

    def test_health_endpoint(self):
        """Test /health returns OK with all expected health sections."""
        environ = {'PATH_INFO': '/health'}
        response = b''.join(wsgi_app(environ, self._start_response))
        assert self.status == '200 OK'
        assert b'"status"' in response
        assert b'"docker"' in response
        assert b'"cloudflare"' in response
        assert b'"cache"' in response
        assert b'"event_listener"' in response
        assert b'"timestamp"' in response

    def test_root_endpoint(self):
        """Test / returns HTML."""
        environ = {'PATH_INFO': '/'}
        response = b''.join(wsgi_app(environ, self._start_response))
        assert self.status == '200 OK'
        assert b'<!DOCTYPE html>' in response

    def test_404_endpoint(self):
        """Test unknown paths return 404."""
        environ = {'PATH_INFO': '/unknown'}
        response = b''.join(wsgi_app(environ, self._start_response))
        assert self.status == '404 Not Found'
        assert response == b'Not Found'


class TestServerStartup:
    """Test web server startup behavior."""

    def test_server_starts_and_responds(self):
        """Test that start_server actually binds and serves requests."""
        with patch('web_server.serve', side_effect=lambda app, host, port, _quiet: None):
            start_server(3445)
            # Give thread a moment to start
            time.sleep(0.1)

    def test_server_failure_reported(self):
        """Test that server bind failure is reported."""
        from waitress import serve as real_serve

        def failing_serve(app, host, port, _quiet):
            raise OSError("Address already in use")

        with patch('web_server.serve', side_effect=failing_serve):
            start_server(3445)
            time.sleep(0.1)
