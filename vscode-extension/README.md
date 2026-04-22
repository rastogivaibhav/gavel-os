# Gavel for VS Code

Catch policy mistakes before they reach production. The Gavel icon appears in your Activity Bar as soon as the extension is installed.

---

## Install

1. Press `Ctrl+Shift+X` → search **Gavel** → Install

The shield icon appears in the left Activity Bar immediately.

---

## First use

**Policy validation works with zero setup.** Open any `.yaml` file inside a `policies/` folder. Errors appear in the Problems panel (`Ctrl+Shift+M`) automatically.

**To enable the live monitor and audit ledger**, click the Gavel icon in the Activity Bar. You'll see a welcome screen with one button:

- **Start with Docker Compose** — opens a terminal and runs `docker compose up -d` for you, then connects automatically when the control plane is ready.
- **Connect to Control Plane** — if it's already running, connects immediately.

That's the entire setup.

---

## What's in the sidebar

Click the Gavel icon (Activity Bar, left side) to open the Gavel panel.

**Before connecting** — you see the welcome screen with setup buttons.

**After connecting** — you see two sections:

### Enforcer Status
Shows whether the control plane is healthy and which components are running (OPA, audit ledger, gRPC, database, Redis).

### Audit Ledger
The last 24 hours of enforcement decisions. Click any entry to see the full event JSON including the SHA-256 hash chain. Use the refresh button (↻) at the top of the section to reload.

---

## Policy validation — no server needed

Open a file in `policies/`. Errors appear as you work.

**What gets caught automatically:**

| Problem | Example |
|---|---|
| Missing required field | Rule with no `effect:` |
| Wrong effect value | `effect: DENY` instead of `BLOCK` |
| Wrong environment name | `environments: [production]` |
| Empty list | `operations: []` |
| Duplicate rule IDs | Two rules with the same `id:` |
| Rule that can never fire | Shadowed by a broader rule above it |
| BLOCK killed by ALLOW | ALLOW fires first, BLOCK never runs |
| Empty condition | Matches every agent — almost always a mistake |

Hover over any red underline to see what's wrong. Click the lightbulb (💡) for a quick fix.

---

## Commands

Press `Ctrl+Shift+P` and type **Gavel** to see all commands:

| Command | What it does |
|---|---|
| **Gavel: Connect to Control Plane** | Connect manually |
| **Gavel: Start with Docker Compose** | Start the full stack and connect |
| **Gavel: Open Live Monitor** | Real-time enforcement event stream |
| **Gavel: Test Policy Proposal** | Type an action, see if it's allowed or blocked |
| **Gavel: Validate Policy File** | Run validation on the open file now |
| **Gavel: Verify Audit Chain** | Check SHA-256 chain integrity |
| **Gavel: Mint JWT Token** | Generate a token and copy to clipboard |
| **Gavel: Run Enforcer Preflight** | Check what this host can enforce |

---

## Settings

Open `Ctrl+,` and search **Gavel**. The only setting you normally need to change:

| Setting | Default | When to change it |
|---|---|---|
| `gavel.controlPlaneUrl` | `http://localhost:8000` | If your control plane runs on a different host or port |
| `gavel.apiKey` | *(empty)* | Paste your `API_SECRET_KEY` from `.env` for full access |

Everything else works with the defaults.

---

## What works without a running control plane

| Feature | Needs control plane? |
|---|---|
| Policy YAML validation | ❌ No |
| Quick Fix suggestions | ❌ No |
| Live monitor | ✅ Yes |
| Audit ledger | ✅ Yes |
| Proposal tester | ✅ Yes |
| Status bar | ✅ Yes (shows offline if unreachable) |

---

## Troubleshooting

**Gavel icon not visible in Activity Bar**

Right-click the Activity Bar → make sure **Gavel** is checked.

**"Connect" button shows an error**

The control plane isn't running. Use **Start with Docker Compose** or run `docker compose up -d` from the repo root manually.

**No errors showing in Problems panel**

The file must be inside a `policies/` directory. Check the path.

**Live monitor shows nothing after connecting**

Set `gavel.apiKey` in settings to match `API_SECRET_KEY` in your `.env` file.
