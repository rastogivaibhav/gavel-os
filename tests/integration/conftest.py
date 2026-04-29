"""Fixtures for integration tests."""

import pytest
import asyncpg
from testcontainers.postgres import PostgresContainer
from httpx import AsyncClient
import sys
sys.path.insert(0, 'control-plane')


@pytest.fixture(scope="function")
async def integration_db(postgres_container):
    """Get isolated database connection for integration test."""
    connection_string = postgres_container.get_connection_string()
    connection_string = connection_string.replace("psycopg2://", "postgresql://")
    
    conn = await asyncpg.connect(connection_string)
    yield conn
    await conn.close()


@pytest.fixture(scope="function")
async def integration_db_pool(postgres_container):
    """Get database pool for integration test."""
    connection_string = postgres_container.get_connection_string()
    connection_string = connection_string.replace("psycopg2://", "postgresql://")
    
    pool = await asyncpg.create_pool(
        connection_string,
        min_size=1,
        max_size=5,
        command_timeout=60,
    )
    
    yield pool
    await pool.close()


@pytest.fixture
async def http_client():
    """Create HTTP client for endpoint testing."""
    async with AsyncClient() as client:
        yield client
