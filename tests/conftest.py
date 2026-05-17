"""Shared pytest fixtures and configuration for all tests."""

import json
import os
from typing import AsyncGenerator, Dict, Any
from unittest.mock import MagicMock, patch

import pytest
import asyncpg
from httpx import AsyncClient

# Unit and ASGI tests should not require local Redis, even if a developer's
# shell or .env points REDIS_URL at a production-like rate-limit backend.
os.environ["REDIS_URL"] = ""

# Optional imports for integration tests
try:
    from testcontainers.postgres import PostgresContainer
    HAS_TESTCONTAINERS = True
except ImportError:
    HAS_TESTCONTAINERS = False

# Test database
TEST_DATABASE_URL = "postgresql://testuser:testpass@localhost:5432/gavel_test"


@pytest.fixture(scope="session")
def postgres_container():
    """Start PostgreSQL container for integration tests."""
    if not HAS_TESTCONTAINERS:
        pytest.skip("testcontainers not installed")

    container = PostgresContainer("postgres:16-alpine")
    container = container.with_env("POSTGRES_USER", "testuser")
    container = container.with_env("POSTGRES_PASSWORD", "testpass")
    container = container.with_env("POSTGRES_DB", "gavel_test")

    container.start()
    yield container
    container.stop()


@pytest.fixture
async def db_connection(postgres_container):
    """Get database connection for a test."""
    connection_string = postgres_container.get_connection_string()
    connection_string = connection_string.replace("psycopg2://", "postgresql://")

    conn = await asyncpg.connect(connection_string)
    yield conn
    await conn.close()


@pytest.fixture
async def db_pool(postgres_container):
    """Create database pool for integration tests."""
    connection_string = postgres_container.get_connection_string()
    connection_string = connection_string.replace("psycopg2://", "postgresql://")

    pool = await asyncpg.create_pool(connection_string, min_size=2, max_size=10)
    yield pool
    await pool.close()


@pytest.fixture
def mock_opa_engine(mocker):
    """Mock OPA engine for unit tests."""
    mock = mocker.MagicMock()
    mock.is_available.return_value = True
    mock.check_routing_allowance.return_value = (True, "Authorized by OPA")
    mock.evaluate_runtime_policy.return_value = (True, "Authorized by Runtime Policy (ALLOW)")
    return mock


@pytest.fixture
def opa_responses():
    """Sample OPA response templates for tests."""
    return {
        "allow": {"result": True},
        "deny": {"result": False},
        "error": {"error": "OPA evaluation failed"},
        "runtime_allow": {"result": True, "verdict": "ALLOW"},
        "runtime_deny": {"result": False, "verdict": "DENY"},
        "runtime_escalate": {"result": None, "verdict": "ESCALATE"},
    }


@pytest.fixture
def sample_tool_proposal():
    """Sample tool proposal request for tests."""
    return {
        "agent_id": "claude-code-1",
        "tool_call_id": "tc_abc123",
        "api_ref": "payments.api",
        "operation": "transfer",
        "environment": "prod",
        "parameters": {"amount": 50000},
        "tenant_id": "tenant-001",
        "user_id": "user-001",
        "replay_nonce": "nonce_1234567890123456",
    }


def make_proposal(**overrides):
    """Build a default SRP proposal for policy and verdict-engine tests."""
    from srp.models import CallerContext, Proposal, ToolCall

    caller = overrides.pop(
        "caller",
        CallerContext(
            tenant_id="test-tenant",
            caller_id="agent-1",
            role="customer",
        ),
    )
    tool_call = overrides.pop(
        "tool_call",
        ToolCall(
            api_ref="payments.api",
            operation="read",
            parameters={"amount": 100.0},
        ),
    )
    defaults = {
        "caller": caller,
        "tool_call": tool_call,
        "environment": "dev",
        "origin": "other",
        "replay_nonce": "nonce-1234567890",
    }
    defaults.update(overrides)
    return Proposal(**defaults)


@pytest.fixture
def sample_network_policy_request():
    """Sample network policy request for tests."""
    return {
        "action": "93.184.216.34",
        "method": "CONNECT",
        "host_id": "host-abc123",
        "runtime_os": "linux",
        "agent_id": "claude-code-1",
    }


@pytest.fixture
def audit_ledger_entry():
    """Sample audit ledger entry for tests."""
    return {
        "id": "aud_001",
        "created_at": "2026-04-29T10:00:00Z",
        "event_json": {
            "action": "tool_proposal_verdict",
            "outcome": "SUCCESS",
            "agent_id": "claude-code-1",
            "verdict": "ALLOW",
            "reason": "Policy permits operation",
        },
        "previous_hash": "abc123",
        "entry_hash": "def456",
    }


@pytest.fixture
def mock_verify_chain(mocker):
    """Mock audit chain verification."""
    mock = mocker.MagicMock()
    mock.return_value = (True, "Chain verified")
    return mock


class MockWebSocket:
    """Mock WebSocket for testing telemetry broadcasts."""

    def __init__(self):
        self.messages = []

    async def send_text(self, data: str):
        """Record sent message."""
        self.messages.append(json.loads(data))

    async def accept(self):
        """Accept connection."""
        pass

    async def close(self):
        """Close connection."""
        pass

    def get_messages(self):
        """Get all sent messages."""
        return self.messages


@pytest.fixture
def mock_websocket():
    """Create mock WebSocket for telemetry tests."""
    return MockWebSocket()


@pytest.fixture
def mock_request_context():
    """Mock FastAPI request context."""
    mock = MagicMock()
    mock.state = MagicMock()
    mock.state.tenant_id = "tenant-001"
    mock.state.user_id = "user-001"
    mock.state.request_id = "req_001"
    return mock


def pytest_configure(config):
    """Configure pytest markers."""
    config.addinivalue_line("markers", "unit: mark test as a unit test")
    config.addinivalue_line("markers", "integration: mark test as an integration test")
    config.addinivalue_line("markers", "e2e: mark test as an end-to-end test")
