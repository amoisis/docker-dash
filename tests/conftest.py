"""Pytest configuration and shared fixtures."""
import sys
from pathlib import Path

# Add src to path so we can import modules
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import pytest
from unittest.mock import MagicMock, Mock
from datetime import datetime


@pytest.fixture
def mock_cloudflare_client():
    """Mock Cloudflare API client."""
    client = MagicMock()
    client.zero_trust.tunnels.list.return_value = []
    client.zero_trust.access.applications.list.return_value = []
    client.zero_trust.access.policies.list.return_value = []
    client.zero_trust.identity_providers.list.return_value = []
    client.zones.list.return_value = []
    return client


@pytest.fixture
def mock_tunnel():
    """Create a mock tunnel object."""
    tunnel = Mock()
    tunnel.id = "tunnel-123"
    tunnel.name = "test-tunnel"
    tunnel.status = "healthy"
    tunnel.tun_type = "cloudflared"
    return tunnel


@pytest.fixture
def mock_ingress_rule():
    """Create a mock ingress rule."""
    rule = Mock()
    rule.hostname = "app.example.com"
    rule.service = "http://localhost:8080"
    
    def dict_method():
        return {
            "hostname": rule.hostname,
            "service": rule.service
        }
    
    rule.dict = dict_method
    return rule


@pytest.fixture
def mock_zone():
    """Create a mock DNS zone."""
    zone = Mock()
    zone.id = "zone-123"
    zone.name = "example.com"
    return zone


@pytest.fixture
def mock_zone_co_uk():
    """Create a mock DNS zone for multi-part TLD."""
    zone = Mock()
    zone.id = "zone-456"
    zone.name = "example.co.uk"
    return zone


@pytest.fixture
def mock_access_policy():
    """Create a mock Access Policy."""
    policy = Mock()
    policy.id = "policy-123"
    policy.name = "Allow-Admins"
    policy.decision = "allow"
    policy.app_count = 1
    return policy


@pytest.fixture
def mock_access_app():
    """Create a mock Access Application."""
    app = Mock()
    app.id = "app-123"
    app.domain = "app.example.com"
    app.type = "self_hosted"
    app.policies = []
    app.auto_redirect_to_identity = False
    return app


@pytest.fixture
def mock_idp():
    """Create a mock Identity Provider."""
    idp = Mock()
    idp.id = "idp-123"
    idp.name = "AzureAD"
    idp.type = "azureAD"
    return idp


@pytest.fixture
def mock_docker_client():
    """Mock Docker client."""
    client = MagicMock()
    client.ping.return_value = True
    client.containers.list.return_value = []
    client.events.return_value = iter([])
    return client


@pytest.fixture
def mock_container():
    """Create a mock Docker container."""
    container = Mock()
    container.id = "container-abc123"
    container.name = "test-container"
    container.labels = {
        "docker.dash.enable": "true",
        "docker.dash.tunnel": "test-tunnel",
        "docker.dash.hostname": "app.example.com",
        "docker.dash.service": "http://test-container:8080"
    }
    return container


@pytest.fixture
def reset_cloudflare_state():
    """Reset global state in cloudflare_client module."""
    import cloudflare_client
    
    # Store original state from the global manager
    original_tunnel_cache = cloudflare_client._manager.tunnel_cache.copy()
    original_access_apps = cloudflare_client._manager.access_apps_cache.copy()
    original_policies = cloudflare_client._manager.access_policies_cache.copy()
    original_idps = cloudflare_client._manager.idps_cache.copy()
    original_zones = cloudflare_client._manager.zones_cache.copy()
    original_client = cloudflare_client._manager.cf_client
    original_account = cloudflare_client._manager.account_id
    
    # Clear state before test
    cloudflare_client._manager.tunnel_cache.clear()
    cloudflare_client._manager.access_apps_cache.clear()
    cloudflare_client._manager.access_policies_cache.clear()
    cloudflare_client._manager.idps_cache.clear()
    cloudflare_client._manager.zones_cache.clear()
    cloudflare_client._manager.cf_client = None
    cloudflare_client._manager.account_id = None
    
    yield
    
    # Restore original state after test
    cloudflare_client._manager.tunnel_cache = original_tunnel_cache
    cloudflare_client._manager.access_apps_cache = original_access_apps
    cloudflare_client._manager.access_policies_cache = original_policies
    cloudflare_client._manager.idps_cache = original_idps
    cloudflare_client._manager.zones_cache = original_zones
    cloudflare_client._manager.cf_client = original_client
    cloudflare_client._manager.account_id = original_account
