# docker-dash Tests

## Running Tests

### Install test dependencies:
```bash
pip install -r tests/requirements-test.txt
```

### Run all tests:
```bash
cd /workspaces/docker-dash
pytest tests/ -v
```

### Run specific test file:
```bash
pytest tests/test_cloudflare_ingress.py -v
```

### Run with coverage:
```bash
pytest tests/ --cov=src --cov-report=html
```

### Run specific test:
```bash
pytest tests/test_cloudflare_dns.py::TestDNSZoneDetection::test_multi_part_tld_zone_detection -v
```

## Test Organization

- `test_cloudflare_ingress.py` - Ingress rule management (add/update/remove)
- `test_cloudflare_dns.py` - DNS zone detection and CNAME management
- `test_cloudflare_access.py` - Access Application creation and policies
- `test_docker_debounce.py` - Docker event debouncing logic
- `test_cache_refresh.py` - Periodic cache refresh functionality

## Test Fixtures

See `conftest.py` for shared fixtures including:
- Mock Cloudflare client
- Mock Docker containers
- Mock tunnels, zones, and Access resources
- State reset helpers

## Adding New Tests

1. Create test file in `tests/` directory
2. Import relevant fixtures from `conftest.py`
3. Use `reset_cloudflare_state` fixture to ensure clean state
4. Mock external API calls
5. Assert expected behavior

## Notes

- Tests use mocks to avoid real API calls
- State is reset between tests using fixtures
- Background threads are tested with short intervals
- Tests are designed to survive refactoring to class-based architecture
