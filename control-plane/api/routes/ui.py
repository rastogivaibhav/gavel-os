"""UI page serving routes — dashboard, audit ledger, policies, etc."""

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from pathlib import Path
from typing import Optional

router = APIRouter(tags=["UI"])

# Resolve static directory relative to this file
STATIC_DIR = Path(__file__).parent.parent.parent / "static"
PAGES_DIR = STATIC_DIR / "pages"

@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Serve dashboard page."""
    page_path = PAGES_DIR / "dashboard.html"
    if not page_path.exists():
        return "<h1>Dashboard page not found</h1>"
    return page_path.read_text()

@router.get("/audit-ledger", response_class=HTMLResponse)
async def audit_ledger(request: Request):
    """Serve audit ledger page."""
    page_path = PAGES_DIR / "audit-ledger.html"
    if not page_path.exists():
        return "<h1>Audit ledger page not found</h1>"
    return page_path.read_text()

@router.get("/policies", response_class=HTMLResponse)
async def policies(request: Request):
    """Serve policies management page."""
    page_path = PAGES_DIR / "policies.html"
    if not page_path.exists():
        return "<h1>Policies page not found</h1>"
    return page_path.read_text()

@router.get("/policy-editor", response_class=HTMLResponse)
async def policy_editor(request: Request):
    """Serve policy editor page."""
    page_path = PAGES_DIR / "policy-editor.html"
    if not page_path.exists():
        return "<h1>Policy editor page not found</h1>"
    return page_path.read_text()

@router.get("/live-monitor", response_class=HTMLResponse)
async def live_monitor(request: Request):
    """Serve live monitor page."""
    page_path = PAGES_DIR / "live-monitor.html"
    if not page_path.exists():
        return "<h1>Live monitor page not found</h1>"
    return page_path.read_text()
