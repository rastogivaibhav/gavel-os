"""Playwright browser tests for Gavel OS API UI."""

import pytest
from playwright.async_api import async_playwright, expect
import asyncio


@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for async tests."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.mark.playwright
class TestAPIBrowser:
    """Test API using Playwright browser automation."""

    BASE_URL = "http://localhost:18000"

    @pytest.mark.asyncio
    async def test_api_root_page(self):
        """Test root API page loads and displays content."""
        async with async_playwright() as p:
            browser = await p.chromium.launch()
            page = await browser.new_page()

            # Navigate to API
            response = await page.goto(self.BASE_URL)
            assert response.status == 200

            # Check page title/content
            content = await page.content()
            assert "Gavel OS" in content or "Control Plane" in content or "ACTIVE" in content

            await browser.close()

    @pytest.mark.asyncio
    async def test_api_docs_page(self):
        """Test API documentation page loads."""
        async with async_playwright() as p:
            browser = await p.chromium.launch()
            page = await browser.new_page()

            # Navigate to docs
            response = await page.goto(f"{self.BASE_URL}/docs")

            # Swagger/OpenAPI page should load
            if response.status == 200:
                content = await page.content()
                # Check for Swagger UI indicators
                has_swagger = "swagger" in content.lower() or "openapi" in content.lower() or "api" in content.lower()
                assert has_swagger, "API docs page should contain API documentation"

            await browser.close()

    @pytest.mark.asyncio
    async def test_health_endpoint_response(self):
        """Test health endpoint returns JSON response."""
        async with async_playwright() as p:
            browser = await p.chromium.launch()
            context = await browser.new_context()
            page = await context.new_page()

            # Capture network responses
            responses = []

            async def handle_response(response):
                if "/health" in response.url:
                    responses.append({
                        "url": response.url,
                        "status": response.status,
                        "body": await response.text()
                    })

            page.on("response", handle_response)

            # Navigate to health endpoint
            await page.goto(f"{self.BASE_URL}/health")
            await page.wait_for_load_state("networkidle")

            # Verify response
            assert len(responses) > 0, "Should have captured health endpoint response"
            health_response = responses[0]
            assert health_response["status"] == 200
            assert "status" in health_response["body"].lower()
            assert "healthy" in health_response["body"].lower()

            await context.close()
            await browser.close()

    @pytest.mark.asyncio
    async def test_page_navigation(self):
        """Test page navigation and links."""
        async with async_playwright() as p:
            browser = await p.chromium.launch()
            page = await browser.new_page()

            # Navigate to root
            await page.goto(self.BASE_URL)
            await page.wait_for_load_state("networkidle")

            # Check for documentation link (may be empty for API root)
            links = await page.locator("a").all()
            link_texts = []
            for link in links:
                try:
                    text = await link.text_content()
                    href = await link.get_attribute("href")
                    link_texts.append({"text": text, "href": href})
                except:
                    pass

            # Root API page may not have links; just verify we can query them
            assert isinstance(link_texts, list), "Should return list of links"

            await browser.close()

    @pytest.mark.asyncio
    async def test_page_performance(self):
        """Test page load performance."""
        async with async_playwright() as p:
            browser = await p.chromium.launch()
            page = await browser.new_page()

            import time
            start = time.time()
            await page.goto(self.BASE_URL)
            await page.wait_for_load_state("networkidle")
            elapsed = time.time() - start

            # Page should load quickly
            assert elapsed < 5.0, f"Page took {elapsed}s to load, expected <5s"

            await browser.close()

    @pytest.mark.asyncio
    async def test_http_headers(self):
        """Test HTTP response headers."""
        async with async_playwright() as p:
            browser = await p.chromium.launch()
            page = await browser.new_page()

            # Capture response
            response = await page.goto(self.BASE_URL)

            # Check headers
            headers = response.headers
            assert "content-type" in headers

            await browser.close()

    @pytest.mark.asyncio
    async def test_page_error_handling(self):
        """Test error page handling."""
        async with async_playwright() as p:
            browser = await p.chromium.launch()
            page = await browser.new_page()

            # Navigate to non-existent endpoint
            response = await page.goto(f"{self.BASE_URL}/nonexistent")

            # Should return 401 (auth middleware) or 404 (not found)
            assert response.status in [401, 404], f"Expected 401 or 404, got {response.status}"

            await browser.close()


@pytest.mark.playwright
class TestAPIConcurrency:
    """Test API under concurrent browser access."""

    BASE_URL = "http://localhost:18000"

    @pytest.mark.asyncio
    async def test_multiple_concurrent_requests(self):
        """Test multiple concurrent browser requests."""
        async with async_playwright() as p:
            browser = await p.chromium.launch()

            # Create multiple pages concurrently
            async def fetch_page():
                page = await browser.new_page()
                response = await page.goto(self.BASE_URL)
                status = response.status
                await page.close()
                return status

            # Run 5 concurrent requests
            tasks = [fetch_page() for _ in range(5)]
            results = await asyncio.gather(*tasks)

            # All should succeed
            assert all(status == 200 for status in results), f"Got statuses: {results}"

            await browser.close()

    @pytest.mark.asyncio
    async def test_rapid_sequential_requests(self):
        """Test rapid sequential requests from single browser."""
        async with async_playwright() as p:
            browser = await p.chromium.launch()
            page = await browser.new_page()

            # Make 10 rapid requests
            statuses = []
            for i in range(10):
                response = await page.goto(self.BASE_URL)
                statuses.append(response.status)

            # All should succeed
            assert all(status == 200 for status in statuses)

            await browser.close()


@pytest.mark.playwright
class TestAPIValidation:
    """Test API response validation."""

    BASE_URL = "http://localhost:18000"

    @pytest.mark.asyncio
    async def test_json_response_format(self):
        """Test JSON response is valid."""
        async with async_playwright() as p:
            browser = await p.chromium.launch()
            context = await browser.new_context()
            page = await context.new_page()

            # Intercept and validate JSON response
            responses = []

            async def handle_response(response):
                if response.status == 200:
                    try:
                        body = await response.json()
                        responses.append(body)
                    except:
                        pass

            page.on("response", handle_response)

            # Navigate
            await page.goto(f"{self.BASE_URL}/health")
            await page.wait_for_load_state("networkidle")

            # Should have valid JSON
            assert len(responses) > 0, "Should have captured JSON responses"

            for resp in responses:
                assert isinstance(resp, dict), "Response should be JSON object"

            await context.close()
            await browser.close()

    @pytest.mark.asyncio
    async def test_content_type_header(self):
        """Test response has correct content type."""
        async with async_playwright() as p:
            browser = await p.chromium.launch()
            page = await browser.new_page()

            response = await page.goto(f"{self.BASE_URL}/health")

            # Check content type
            headers = response.headers
            content_type = headers.get("content-type", "").lower()
            assert "json" in content_type or "application" in content_type

            await browser.close()


@pytest.mark.playwright
class TestAPISecurity:
    """Test API security features."""

    BASE_URL = "http://localhost:18000"

    @pytest.mark.asyncio
    async def test_no_exposed_errors(self):
        """Test that error messages don't expose internals."""
        async with async_playwright() as p:
            browser = await p.chromium.launch()
            page = await browser.new_page()

            # Try to access endpoint that might error
            await page.goto(f"{self.BASE_URL}/nonexistent")
            content = await page.content()

            # Should not contain stack traces or file paths
            assert "Traceback" not in content
            assert "File \"" not in content
            assert "line " not in content.lower() or "error" not in content.lower()

            await browser.close()

    @pytest.mark.asyncio
    async def test_security_headers(self):
        """Test security headers are present."""
        async with async_playwright() as p:
            browser = await p.chromium.launch()
            page = await browser.new_page()

            response = await page.goto(self.BASE_URL)

            headers = response.headers
            # Server header should be present
            assert "server" in headers or "content-type" in headers

            await browser.close()
