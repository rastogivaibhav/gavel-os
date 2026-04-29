# Gavel OS Control Plane — UI Setup & Deployment

## Overview

The Gavel OS Control Plane includes a comprehensive web-based UI for monitoring, policy management, and real-time event tracking. The UI is built with:

- **FastAPI** — Backend API server
- **HTML/CSS/JavaScript** — Frontend (no framework)
- **Tailwind CSS** — Pre-compiled styling (production-ready, no CDN)
- **WebSocket** — Real-time event streaming
- **Material Design** — Icons and typography

## Quick Start

### Prerequisites

- Python 3.11+
- Node.js 18+ (for Tailwind CSS build)
- npm or yarn

### Setup

1. **Install backend dependencies:**

```bash
cd control-plane
pip install -e .
```

2. **Build Tailwind CSS:**

```bash
# One-time build
npm install
npm run build:css

# Or watch mode for development
npm run watch:css
```

3. **Start the API server:**

```bash
# Development
python -m uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload

# Production
gunicorn api.main:app --workers 4 --worker-class uvicorn.workers.UvicornWorker --bind 0.0.0.0:8000
```

4. **Access the UI:**

Open your browser to `http://localhost:8000` (or your configured port)

## Project Structure

```
control-plane/
├── api/
│   ├── main.py              # FastAPI app entry point
│   ├── routes/
│   │   ├── ui.py            # UI page serving routes
│   │   ├── websocket.py     # WebSocket endpoint (/ws/events)
│   │   ├── external.py      # API endpoints
│   │   └── ...
│   └── middleware/
│       ├── auth.py          # JWT authentication
│       └── ...
│
├── static/
│   ├── css/
│   │   ├── tailwind.css     # Tailwind source (imports @tailwind directives)
│   │   └── output.css       # Compiled CSS (production-ready)
│   ├── js/
│   │   ├── api-client.js    # API wrapper for all endpoints
│   │   ├── auth.js          # Authentication & token management
│   │   ├── common.js        # Utility functions
│   │   └── websocket-handler.js # Real-time event handling
│   └── pages/
│       ├── dashboard.html   # System overview
│       ├── audit-ledger.html # Forensic analysis
│       ├── policies.html    # Policy management
│       ├── policy-editor.html # REGO editor & validator
│       └── live-monitor.html  # Real-time events
│
├── package.json             # NPM configuration
├── tailwind.config.js       # Tailwind configuration
└── pytest.ini               # Test configuration

tests/ui/
├── conftest.py              # Test fixtures
└── test_ui_routes.py        # Integration tests (9 tests, all passing)
```

## UI Pages

### Dashboard (`/`)

System overview with:
- Health status of all components (OPA, PostgreSQL, Redis, gRPC, etc.)
- Quick stats (total decisions, recent events, policy versions)
- Recent audit entries
- Component status indicators

### Audit Ledger (`/audit-ledger`)

Forensic analysis interface:
- Search and filter audit entries by decision, tenant, agent, timestamp
- SHA-256 chain verification display
- Export audit logs as JSON
- Detailed decision context and reasoning

### Policies (`/policies`)

Policy management interface:
- List all deployed policies with metadata
- View policy history and versions
- Deployment timestamps and approvers
- Policy effect distribution (ALLOW vs DENY)

### Policy Editor (`/policy-editor`)

Interactive REGO policy development:
- Syntax-highlighted editor for OPA REGO code
- Real-time validation panel
- Test cases and dry-run execution
- One-click deploy to control plane

### Live Monitor (`/live-monitor`)

Real-time event streaming via WebSocket:
- Live decision feed (ALLOW, DENY, ESCALATE)
- Throughput metrics and decision distribution
- Agent activity tracking
- Real-time policy impact analysis

## Build System

### Tailwind CSS Compilation

The UI uses **compiled Tailwind CSS** (not CDN) for production-safe deployment:

```bash
# Development: watch for changes
npm run watch:css

# Production: one-time build
npm run build:css
```

**Key points:**
- Source file: `control-plane/static/css/tailwind.css`
- Output file: `control-plane/static/css/output.css` (17 KB)
- No external CDN dependency
- Safe for offline/air-gapped environments
- Includes all custom colors, spacing, typography

### Custom Tailwind Configuration

File: `control-plane/tailwind.config.js`

Defines:
- **Color palette** (30+ custom colors: primary, secondary, tertiary, surface variants, etc.)
- **Typography** (Space Grotesk for headlines, Inter for body text)
- **Spacing** (unit: 8px, stack variants, component padding)
- **Border radius** (fine-grained rounded corners)
- **Plugins** (@tailwindcss/forms for form styling)

## Testing

### Run Tests

```bash
# All UI integration tests
pytest tests/ui/test_ui_routes.py -v

# Specific test
pytest tests/ui/test_ui_routes.py::test_dashboard_page_loads -v

# With coverage
pytest tests/ui/ --cov=control-plane.api.routes.ui
```

### Test Coverage

9 comprehensive integration tests:
1. Dashboard page loads and contains HTML
2. Audit ledger page loads
3. Policies page loads
4. Policy editor page loads
5. Live monitor page loads
6. Unauthenticated access allowed (pages are public; API requires auth)
7. Static CSS file served correctly
8. Material Symbols font accessible
9. Pages reference JavaScript modules

All tests **PASS** ✓

## Authentication

### JWT Tokens

The UI uses JWT tokens stored in `sessionStorage` for API requests:

```javascript
// Fetch token
const token = sessionStorage.getItem('gavel_token');

// Or get new token
const response = await fetch('/auth/token', {
  method: 'POST',
  body: JSON.stringify({
    role: 'customer',
    clearance_level: 1,
    tenant_id: 'default'
  })
});
```

### Token Lifecycle

- **Obtained** at page load via `/auth/token` endpoint
- **Stored** in `sessionStorage` with expiry timestamp (1 hour default)
- **Refreshed** automatically on page reload if expired
- **Sent** as `Authorization: Bearer <token>` header in all API calls
- **Cleared** on logout

### Machine Authentication

For service-to-service calls, use the `X-Machine-Key` header:

```bash
curl -H "X-Machine-Key: <GAVEL_MACHINE_KEY>" \
  http://localhost:8000/external/validate
```

## API Endpoints

All endpoints are documented in the interactive API docs:
- **Swagger UI:** `http://localhost:8000/docs`
- **ReDoc:** `http://localhost:8000/redoc`
- **OpenAPI schema:** `http://localhost:8000/openapi.json`

### Key UI Endpoints

| Method | Endpoint | Purpose | Auth |
|--------|----------|---------|------|
| GET | `/` | Dashboard | Optional |
| GET | `/audit-ledger` | Audit interface | Optional |
| GET | `/policies` | Policy list | Optional |
| GET | `/policy-editor` | REGO editor | Optional |
| GET | `/live-monitor` | Event stream | Optional |
| POST | `/auth/token` | Get JWT | Machine key |
| GET | `/health` | System health | None |
| WS | `/ws/events` | Real-time events | JWT |

### Data APIs (used by UI)

| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/audit/ledger` | Fetch audit entries |
| POST | `/audit/verify` | Verify chain integrity |
| GET | `/policies` | List policies |
| POST | `/policies/validate` | Validate REGO code |
| POST | `/external/tool/verdict` | Test tool proposals |
| GET | `/external/network/policy` | Query runtime policy |

## Deployment

### Local Development

```bash
# Start server with auto-reload
python -m uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload

# UI automatically available at http://localhost:8000
```

### Docker

```dockerfile
FROM python:3.13-slim

WORKDIR /app
COPY control-plane /app
RUN pip install -e .

# Ensure CSS is built
RUN npm install && npm run build:css

EXPOSE 8000
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0"]
```

### Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: gavel-control-plane
spec:
  replicas: 1
  selector:
    matchLabels:
      app: gavel-cp
  template:
    metadata:
      labels:
        app: gavel-cp
    spec:
      containers:
      - name: control-plane
        image: gavel-control-plane:latest
        ports:
        - containerPort: 8000
        env:
        - name: ENV
          value: "production"
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: gavel-secrets
              key: database-url
        - name: GAVEL_MACHINE_KEY
          valueFrom:
            secretKeyRef:
              name: gavel-secrets
              key: machine-key
```

### Environment Variables

Key variables for UI:

```bash
# Server
GAVEL_API_PORT=8000              # HTTP port
ENV=development|production        # Environment

# Authentication
GAVEL_MACHINE_KEY=<hex>          # Machine-to-CP auth
ADMIN_SECRET_KEY=<hex>           # Admin token minting
JWT_EXPIRY_SECONDS=3600          # Token lifetime

# Database (for audit ledger)
DATABASE_URL=postgres://...      # PostgreSQL connection

# OPA (for policy evaluation)
OPA_URL=http://localhost:8181    # OPA endpoint
OPA_PACKAGE_PATH=sentinel/api/authz

# CORS (for browser access)
ALLOWED_ORIGINS=http://localhost:3000,... # Comma-separated

# Development (unsafe, dev-only)
ALLOW_INSECURE_DEV_AUTH=false    # Bypass auth
GRPC_INSECURE=true               # Development gRPC (dev only)
```

## Troubleshooting

### CSS Not Loading

**Problem:** Page loads but styling is missing

**Solution:**
```bash
# Rebuild CSS
npm run build:css

# Verify output.css exists
ls -la control-plane/static/css/output.css
```

### WebSocket Connection Failed

**Problem:** Live Monitor shows connection error

**Solution:**
- Verify `/ws/events` endpoint is accessible: `curl http://localhost:8000/ws/events`
- Check authentication token is valid
- Ensure firewall allows WebSocket upgrades
- Check browser console for detailed error

### Auth Token Expired

**Problem:** API calls return 401 Unauthorized

**Solution:**
- Page auto-refreshes token on load
- Or clear `sessionStorage` and reload: `sessionStorage.clear(); location.reload()`
- Check JWT_EXPIRY_SECONDS in environment

### Database Unavailable

**Problem:** Audit ledger shows "unavailable"

**Solution:**
```bash
# Check PostgreSQL connection
echo "SELECT 1" | psql $DATABASE_URL

# Restart control plane if connection string changed
```

### OPA Unavailable

**Problem:** Policy validation fails

**Solution:**
```bash
# Verify OPA is running
curl http://localhost:8181/health

# Check OPA_URL and OPA_PACKAGE_PATH in environment
```

## Performance

### Page Load Time

Typical metrics (development):
- Dashboard: < 500ms
- Audit ledger (empty): < 300ms
- Policy editor: < 400ms
- Live monitor: < 200ms (WebSocket connects in background)

### Optimization Tips

1. **CSS:** Tailwind CSS is pre-compiled (17 KB gzipped) — cached by browser
2. **JS:** Minimal dependencies — api-client, auth, common, websocket-handler
3. **API:** All endpoints return JSON < 100 KB for typical queries
4. **Database:** Index audit_ledger.created_at and decision for fast queries
5. **WebSocket:** Connection pooling built-in, automatic reconnection with exponential backoff

## Contributing

### Adding New Pages

1. Create HTML in `control-plane/static/pages/new-page.html`
2. Add route in `control-plane/api/routes/ui.py`:
   ```python
   @router.get("/new-page", response_class=HTMLResponse)
   async def new_page(request: Request):
       page_path = PAGES_DIR / "new-page.html"
       if not page_path.exists():
           return "<h1>Page not found</h1>"
       return page_path.read_text()
   ```
3. Add test in `tests/ui/test_ui_routes.py`
4. Update navigation in dashboard and other pages

### Styling Changes

1. Edit `control-plane/static/css/tailwind.css` (source)
2. Run `npm run build:css` to generate `output.css`
3. Verify in browser — Tailwind classes are applied automatically
4. Commit both source and output files

### JavaScript Changes

1. Edit files in `control-plane/static/js/`
2. No build step required (plain JavaScript)
3. Test in browser DevTools console
4. Add test coverage if adding new functionality

## References

- **FastAPI Docs:** https://fastapi.tiangolo.com
- **Tailwind CSS:** https://tailwindcss.com
- **Material Design:** https://fonts.google.com/metadata/icons
- **OPA Policy Language:** https://www.openpolicyagent.org/docs/latest/
- **WebSocket API:** https://developer.mozilla.org/en-US/docs/Web/API/WebSocket

---

**Last Updated:** 2026-04-29
**Status:** Production-ready
