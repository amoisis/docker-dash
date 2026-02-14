#!/bin/bash
# Test runner script for docker-dash

set -e

echo "================================"
echo "docker-dash Test Suite"
echo "================================"
echo ""

# Check if pytest is installed
if ! python -c "import pytest" 2>/dev/null; then
    echo "Installing test dependencies..."
    pip install -r tests/requirements-test.txt
    echo ""
fi

# Run tests with coverage
echo "Running tests with coverage..."
pytest tests/ -v --cov=src --cov-report=term-missing --cov-report=html

echo ""
echo "================================"
echo "Test run complete!"
echo "HTML coverage report: htmlcov/index.html"
echo "================================"
