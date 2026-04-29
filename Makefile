.PHONY: test test-unit test-integration test-e2e test-cov test-all install-dev install install-deps

# Install development dependencies
install-dev:
	cd control-plane && pip install -e . && pip install -r requirements-dev.txt

install:
	cd control-plane && pip install -r requirements.txt

install-deps:
	cd control-plane && pip install -r requirements-dev.txt

# Run all tests
test: test-unit

# Run unit tests only (no external services required)
test-unit:
	pytest tests/unit/ -v -m unit --tb=short

# Run integration tests (requires Docker for OPA/PostgreSQL)
test-integration:
	pytest tests/integration/ -v -m integration --tb=short

# Run E2E tests (requires full system running)
test-e2e:
	pytest tests/e2e/ -v -m e2e --tb=short

# Run all tests with coverage
test-cov:
	pytest tests/unit/ -v --cov=control-plane --cov-report=html --cov-report=term-missing

# Run all tests
test-all:
	pytest tests/ -v --tb=short

# Run tests with detailed output
test-verbose:
	pytest tests/ -vv --tb=long

# Run specific test
test-specific:
	pytest $(TEST) -v

# Clean test artifacts
clean-test:
	rm -rf .pytest_cache __pycache__ htmlcov .coverage .coveragerc

# Format code with ruff
format:
	cd control-plane && ruff format .

# Lint code with ruff
lint:
	cd control-plane && ruff check . --fix

# Type check with mypy
typecheck:
	cd control-plane && mypy . --ignore-missing-imports
