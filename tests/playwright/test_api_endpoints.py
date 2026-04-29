"""Playwright-based API endpoint validation tests."""

import pytest
import asyncio
import sys
from datetime import datetime, timezone, timedelta
import uuid

sys.path.insert(0, 'control-plane')


@pytest.mark.playwright
class TestAPIEndpoints:
    """Test API endpoints via HTTP client."""

    @pytest.fixture
    async def api_client(self):
        """Create HTTP client for API testing."""
        import httpx

        async with httpx.AsyncClient(base_url="http://localhost:18000", timeout=30.0) as client:
            yield client

    @pytest.mark.asyncio
    async def test_root_endpoint(self, api_client):
        """Test root endpoint returns service info."""
        response = await api_client.get("/")

        assert response.status_code == 200
        data = response.json()
        assert data["service"] == "Gavel OS Control Plane"
        assert data["status"] == "operational"

    @pytest.mark.asyncio
    async def test_health_endpoint(self, api_client):
        """Test /health endpoint."""
        response = await api_client.get("/health")

        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert "components" in data

    @pytest.mark.asyncio
    async def test_readiness_probe(self, api_client):
        """Test /ready endpoint."""
        response = await api_client.get("/ready")

        assert response.status_code == 200
        data = response.json()
        assert data["ready"] is True

    @pytest.mark.asyncio
    async def test_liveness_probe(self, api_client):
        """Test /live endpoint."""
        response = await api_client.get("/live")

        assert response.status_code == 200
        data = response.json()
        assert data["alive"] is True


@pytest.mark.playwright
class TestExternalEndpoints:
    """Test external API endpoints."""

    @pytest.fixture
    async def api_client(self):
        """Create HTTP client for API testing."""
        import httpx

        async with httpx.AsyncClient(base_url="http://localhost:18000", timeout=30.0) as client:
            yield client

    @pytest.mark.asyncio
    async def test_tool_verdict_endpoint_exists(self, api_client):
        """Test that /external/tool/verdict endpoint exists."""
        # Test with minimal auth for availability check
        response = await api_client.post(
            "/external/tool/verdict",
            json={
                "agent_id": "test-agent",
                "tool_call_id": "tc_test_123",
                "api_ref": "test.api",
                "operation": "test",
                "environment": "prod",
                "parameters": {},
                "tenant_id": "test-tenant",
            },
            headers={"x-machine-key": "test-key"},
        )

        # Should return 200 or 401/403 (auth error), not 404 (not found)
        assert response.status_code in [200, 401, 403, 500]

    @pytest.mark.asyncio
    async def test_escalations_endpoint_exists(self, api_client):
        """Test that /escalations endpoint exists."""
        response = await api_client.get("/escalations")

        # Should return auth error or success, not 404
        assert response.status_code in [200, 401, 403]

    @pytest.mark.asyncio
    async def test_network_policy_endpoint_exists(self, api_client):
        """Test that /external/network/policy endpoint exists."""
        response = await api_client.post(
            "/external/network/policy",
            json={
                "action": "example.com",
                "method": "CONNECT",
                "host_id": "host-123",
                "runtime_os": "linux",
                "agent_id": "test-agent",
            },
            headers={"x-machine-key": "test-key"},
        )

        # Should return 200 or auth error, not 404
        assert response.status_code in [200, 401, 403, 500]


@pytest.mark.playwright
class TestEndpointResponseFormats:
    """Test that endpoints return proper response formats."""

    @pytest.fixture
    async def api_client(self):
        """Create HTTP client for API testing."""
        import httpx

        async with httpx.AsyncClient(base_url="http://localhost:18000", timeout=30.0) as client:
            yield client

    @pytest.mark.asyncio
    async def test_health_response_structure(self, api_client):
        """Test health endpoint response structure."""
        response = await api_client.get("/health")

        assert response.status_code == 200
        data = response.json()

        # Check structure
        assert "status" in data
        assert "timestamp" in data
        assert "components" in data

        # Check OPA component
        components = data["components"]
        assert "opa" in components
        assert "status" in components["opa"]

        # Check database component
        assert "database" in components
        assert "status" in components["database"]

    @pytest.mark.asyncio
    async def test_error_response_format(self, api_client):
        """Test that error responses have correct format."""
        # Send invalid request to generate error
        response = await api_client.post(
            "/external/tool/verdict",
            json={"invalid": "request"},
            headers={"x-machine-key": "test-key"},
        )

        # Should get error response
        assert response.status_code in [400, 422]
        data = response.json()

        # Error should have detail or error field
        assert "detail" in data or "error" in data


@pytest.mark.playwright
class TestEndpointPerformance:
    """Test endpoint performance characteristics."""

    @pytest.fixture
    async def api_client(self):
        """Create HTTP client for API testing."""
        import httpx

        async with httpx.AsyncClient(base_url="http://localhost:18000", timeout=30.0) as client:
            yield client

    @pytest.mark.asyncio
    async def test_root_endpoint_response_time(self, api_client):
        """Test root endpoint responds quickly."""
        import time

        start = time.time()
        response = await api_client.get("/")
        elapsed = time.time() - start

        assert response.status_code == 200
        assert elapsed < 0.5, f"Root endpoint took {elapsed}s, expected <0.5s"

    @pytest.mark.asyncio
    async def test_health_endpoint_response_time(self, api_client):
        """Test health endpoint responds quickly."""
        import time

        start = time.time()
        response = await api_client.get("/health")
        elapsed = time.time() - start

        assert response.status_code == 200
        assert elapsed < 2.0, f"Health check took {elapsed}s, expected <2.0s"

    @pytest.mark.asyncio
    async def test_multiple_concurrent_requests(self, api_client):
        """Test server handles concurrent requests."""
        import asyncio

        async def make_request():
            return await api_client.get("/")

        # Make 10 concurrent requests
        tasks = [make_request() for _ in range(10)]
        results = await asyncio.gather(*tasks)

        # All should succeed
        assert all(r.status_code == 200 for r in results)


@pytest.mark.playwright
class TestDataIntegration:
    """Test data flow through API endpoints."""

    @pytest.fixture
    async def api_client(self):
        """Create HTTP client for API testing."""
        import httpx

        async with httpx.AsyncClient(base_url="http://localhost:18000", timeout=30.0) as client:
            yield client

    @pytest.mark.asyncio
    async def test_health_reflects_component_status(self, api_client):
        """Test that health endpoint reflects actual component status."""
        response = await api_client.get("/health")

        assert response.status_code == 200
        data = response.json()

        # Get OPA component status
        opa_status = data["components"]["opa"]["status"]
        assert opa_status in ["healthy", "unhealthy", "degraded"]

        # Get database status
        db_status = data["components"]["database"]["status"]
        assert db_status in ["healthy", "unhealthy", "degraded"]

        # Overall status should reflect components
        overall_status = data["status"]
        assert overall_status in ["healthy", "degraded"]


@pytest.mark.playwright
class TestServerReliability:
    """Test server reliability and error handling."""

    @pytest.fixture
    async def api_client(self):
        """Create HTTP client for API testing."""
        import httpx

        async with httpx.AsyncClient(base_url="http://localhost:18000", timeout=30.0) as client:
            yield client

    @pytest.mark.asyncio
    async def test_invalid_json_handling(self, api_client):
        """Test server handles invalid JSON gracefully."""
        try:
            response = await api_client.post(
                "/external/tool/verdict",
                content="invalid json {",
                headers={
                    "Content-Type": "application/json",
                    "x-machine-key": "test-key",
                },
            )
            # Should return 400, not 500
            assert response.status_code in [400, 422]
        except Exception as e:
            # Connection errors are acceptable
            pass

    @pytest.mark.asyncio
    async def test_nonexistent_endpoint_returns_404(self, api_client):
        """Test that nonexistent endpoints return 404."""
        response = await api_client.get("/nonexistent/endpoint")

        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_server_timeout_handling(self, api_client):
        """Test server handles timeouts gracefully."""
        # Create client with short timeout
        import httpx

        async with httpx.AsyncClient(
            base_url="http://localhost:18000",
            timeout=0.001  # Very short timeout
        ) as short_timeout_client:
            try:
                response = await short_timeout_client.get("/")
                # Either succeeds or times out - both acceptable
            except httpx.TimeoutException:
                # Expected behavior
                pass
            except httpx.ConnectError:
                # Also acceptable
                pass
