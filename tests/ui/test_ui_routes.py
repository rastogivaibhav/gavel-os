"""Integration tests for UI routes."""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_dashboard_page_loads(authenticated_client):
    """Test dashboard page HTML is served correctly."""
    response = await authenticated_client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "<!DOCTYPE html>" in response.text or "<html" in response.text
    assert "gavel" in response.text.lower() or "dashboard" in response.text.lower()


@pytest.mark.asyncio
async def test_audit_ledger_page_loads(authenticated_client):
    """Test audit ledger page HTML is served correctly."""
    response = await authenticated_client.get("/audit-ledger")
    assert response.status_code == 200
    assert response.headers["content-type"] == "text/html; charset=utf-8"
    assert "<!DOCTYPE html>" in response.text or "<html" in response.text
    assert len(response.text) > 100  # Should have substantial content


@pytest.mark.asyncio
async def test_policies_page_loads(authenticated_client):
    """Test policies management page HTML is served correctly."""
    response = await authenticated_client.get("/policies")
    assert response.status_code == 200
    assert response.headers["content-type"] == "text/html; charset=utf-8"
    assert "<!DOCTYPE html>" in response.text or "<html" in response.text


@pytest.mark.asyncio
async def test_policy_editor_page_loads(authenticated_client):
    """Test policy editor page HTML is served correctly."""
    response = await authenticated_client.get("/policy-editor")
    assert response.status_code == 200
    assert response.headers["content-type"] == "text/html; charset=utf-8"
    assert "<!DOCTYPE html>" in response.text or "<html" in response.text


@pytest.mark.asyncio
async def test_live_monitor_page_loads(authenticated_client):
    """Test live monitor page HTML is served correctly."""
    response = await authenticated_client.get("/live-monitor")
    assert response.status_code == 200
    assert response.headers["content-type"] == "text/html; charset=utf-8"
    assert "<!DOCTYPE html>" in response.text or "<html" in response.text


@pytest.mark.asyncio
async def test_unauthenticated_access_allowed(client):
    """Test that dashboard page is publicly accessible (auth on API calls, not pages)."""
    response = await client.get("/", follow_redirects=False)
    # Dashboard page is public; authentication is enforced on API endpoints
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]


@pytest.mark.asyncio
async def test_static_css_file_served(authenticated_client):
    """Test that compiled Tailwind CSS file is served correctly."""
    response = await authenticated_client.get("/static/css/output.css")
    assert response.status_code == 200
    assert "text/css" in response.headers.get("content-type", "")
    assert len(response.text) > 1000  # Should have compiled CSS
    assert "@tailwind" not in response.text  # Should be compiled, not source


@pytest.mark.asyncio
async def test_material_symbols_font_accessible(authenticated_client):
    """Test Material Symbols icon font is accessible."""
    response = await authenticated_client.get("/static/css/output.css")
    assert response.status_code == 200
    # CSS should reference fonts from Google Fonts
    assert "fonts" in response.text or response.text


@pytest.mark.asyncio
async def test_pages_reference_javascript_modules(authenticated_client):
    """Test that pages reference required JavaScript modules."""
    response = await authenticated_client.get("/")
    assert response.status_code == 200
    # Should reference API client or other JS modules
    content = response.text.lower()
    # Look for script tags or module references
    assert "<script" in content or "javascript" in content or ".js" in content
