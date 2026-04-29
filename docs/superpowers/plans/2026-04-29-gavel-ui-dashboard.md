# Gavel OS Web Dashboard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a production-ready web dashboard at http://localhost:18000 that serves Gavel OS UI screens with real-time monitoring, policy management, and Windows AD authentication.

**Architecture:** 
- FastAPI serves compiled Tailwind CSS (no CDN) from static directory
- JavaScript API client communicates with existing `/external/*`, `/audit/*`, `/policies/*` endpoints
- WebSocket integration for real-time Live Monitor and event streams
- Windows AD auth via existing JWT middleware
- 5 main screens: Dashboard, Audit Ledger, Policies, Policy Editor, Live Monitor

**Tech Stack:** FastAPI, Tailwind CSS (built), Vanilla JavaScript, WebSocket, Material Symbols Icons

---

## File Structure

```
control-plane/
├── api/
│   ├── routes/
│   │   └── ui.py                          # NEW: Routes for serving UI pages
│   ├── main.py                            # MODIFY: Add static file serving
│   └── ...
├── static/                                # NEW: Static assets directory
│   ├── css/
│   │   ├── output.css                     # NEW: Compiled Tailwind CSS (from build)
│   │   └── tailwind.css                   # NEW: Tailwind directives (source)
│   ├── js/
│   │   ├── api-client.js                  # NEW: API client utility
│   │   ├── websocket-handler.js           # NEW: WebSocket real-time updates
│   │   ├── auth.js                        # NEW: Windows AD auth integration
│   │   └── common.js                      # NEW: Shared utilities
│   └── pages/
│       ├── dashboard.html                 # NEW: Dashboard screen
│       ├── audit-ledger.html              # NEW: Audit Ledger screen
│       ├── policies.html                  # NEW: Policies list screen
│       ├── policy-editor.html             # NEW: Policy editor screen
│       ├── live-monitor.html              # NEW: Live monitor screen
│       └── layout.html                    # NEW: Base layout (nav, shared elements)
├── tailwind.config.js                     # NEW: Tailwind configuration
├── package.json                           # NEW: Node dependencies
├── Makefile                               # NEW: Build automation
└── ...
```

---

## Tasks

### Task 1: Set up Tailwind CSS build system

**Files:**
- Create: `control-plane/package.json`
- Create: `control-plane/tailwind.config.js`
- Create: `control-plane/static/css/tailwind.css`

- [ ] **Step 1: Create package.json with Tailwind dependencies**

```json
{
  "name": "gavel-os-ui",
  "version": "1.0.0",
  "description": "Gavel OS Web Dashboard",
  "scripts": {
    "build:css": "tailwindcss -i ./static/css/tailwind.css -o ./static/css/output.css",
    "watch:css": "tailwindcss -i ./static/css/tailwind.css -o ./static/css/output.css --watch"
  },
  "devDependencies": {
    "tailwindcss": "^3.4.1",
    "@tailwindcss/forms": "^0.5.7"
  }
}
```

- [ ] **Step 2: Run npm install to install Tailwind**

```bash
cd control-plane
npm install
```

Expected: `node_modules/` directory created, `package-lock.json` generated

- [ ] **Step 3: Create tailwind.config.js**

```javascript
/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './static/pages/**/*.html',
    './static/js/**/*.js',
  ],
  theme: {
    extend: {
      colors: {
        'surface-dim': '#cfdaf2',
        'on-error-container': '#93000a',
        'secondary-fixed-dim': '#b7c8e1',
        'on-tertiary-fixed': '#001e2f',
        'surface-tint': '#006c4a',
        'on-primary': '#ffffff',
        'tertiary-fixed-dim': '#89ceff',
        'on-tertiary': '#ffffff',
        'on-background': '#111c2d',
        'error-container': '#ffdad6',
        'surface-container-lowest': '#ffffff',
        'surface': '#f9f9ff',
        'surface-variant': '#d8e3fb',
        'surface-container-high': '#dee8ff',
        'on-tertiary-fixed-variant': '#004c6e',
        'primary-container': '#00855d',
        'on-primary-container': '#f5fff7',
        'secondary-container': '#d0e1fb',
        'on-surface': '#111c2d',
        'on-primary-fixed-variant': '#005137',
        'background': '#f9f9ff',
        'inverse-on-surface': '#ecf1ff',
        'surface-container-low': '#f0f3ff',
        'secondary': '#505f76',
        'outline': '#6d7a72',
        'on-secondary-container': '#54647a',
        'primary-fixed-dim': '#68dba9',
        'on-primary-fixed': '#002114',
        'surface-container': '#e7eeff',
        'on-secondary-fixed': '#0b1c30',
        'on-tertiary-container': '#fcfcff',
        'on-secondary': '#ffffff',
        'primary': '#006948',
        'outline-variant': '#bccac0',
        'error': '#ba1a1a',
        'on-error': '#ffffff',
        'primary-fixed': '#85f8c4',
        'tertiary': '#00628d',
        'surface-container-highest': '#d8e3fb',
        'secondary-fixed': '#d3e4fe',
        'surface-bright': '#f9f9ff',
        'on-surface-variant': '#3d4a42',
        'tertiary-fixed': '#c9e6ff',
        'inverse-surface': '#263143',
        'tertiary-container': '#007cb1',
        'on-secondary-fixed-variant': '#38485d',
        'inverse-primary': '#68dba9'
      },
      borderRadius: {
        'DEFAULT': '0.125rem',
        'lg': '0.25rem',
        'xl': '0.5rem',
        'full': '0.75rem'
      },
      spacing: {
        'unit': '8px',
        'stack-lg': '32px',
        'container-margin': '32px',
        'gutter': '24px',
        'component-padding-x': '16px',
        'component-padding-y': '10px',
        'stack-sm': '8px',
        'stack-md': '16px'
      },
      fontFamily: {
        'title-sm': ['Inter'],
        'display-lg': ['Space Grotesk'],
        'display-xl': ['Space Grotesk'],
        'label-caps': ['Space Grotesk'],
        'body-sm': ['Inter'],
        'headline-md': ['Space Grotesk'],
        'mono-data': ['Space Grotesk'],
        'body-md': ['Inter']
      },
      fontSize: {
        'title-sm': ['18px', { lineHeight: '1.5', fontWeight: '600' }],
        'display-lg': ['30px', { lineHeight: '1.2', letterSpacing: '-0.01em', fontWeight: '600' }],
        'display-xl': ['36px', { lineHeight: '1.2', letterSpacing: '-0.02em', fontWeight: '700' }],
        'label-caps': ['12px', { lineHeight: '1', letterSpacing: '0.05em', fontWeight: '700' }],
        'body-sm': ['14px', { lineHeight: '1.5', fontWeight: '400' }],
        'headline-md': ['24px', { lineHeight: '1.3', fontWeight: '600' }],
        'mono-data': ['14px', { lineHeight: '1.4', letterSpacing: '-0.01em', fontWeight: '500' }],
        'body-md': ['16px', { lineHeight: '1.6', fontWeight: '400' }]
      }
    }
  },
  plugins: [
    require('@tailwindcss/forms'),
  ],
}
```

- [ ] **Step 4: Create source Tailwind CSS file**

Create `control-plane/static/css/tailwind.css`:

```css
@tailwind base;
@tailwind components;
@tailwind utilities;

@import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;500;600;700&family=Inter:wght@400;500;600;700&display=swap');
@import url('https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap');

* {
  font-family: 'Inter', sans-serif;
}

h1, h2, h3, h4, h5, h6 {
  font-family: 'Space Grotesk', sans-serif;
}
```

- [ ] **Step 5: Build Tailwind CSS**

```bash
cd control-plane
npm run build:css
```

Expected: `static/css/output.css` generated (~50-100KB uncompressed)

- [ ] **Step 6: Commit**

```bash
git add package.json tailwind.config.js static/css/tailwind.css static/css/output.css .gitignore
git commit -m "chore: set up Tailwind CSS build system (no CDN)

- Add package.json with tailwindcss dependencies
- Configure tailwind.config.js with custom theme (slate-emerald palette)
- Create compiled output.css for production use
- Add build script: npm run build:css

Co-Authored-By: Claude Haiku 4.5 <noreply@anthropic.com>"
```

---

### Task 2: Create FastAPI routes for serving UI pages

**Files:**
- Create: `control-plane/api/routes/ui.py`
- Modify: `control-plane/api/main.py`
- Modify: `control-plane/.gitignore`

[... rest of plan continues with Tasks 3-10 ...]
