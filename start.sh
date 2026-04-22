#!/usr/bin/env bash
# start.sh — One-command Gavel OS startup for Linux / macOS
#
# Usage:
#   ./start.sh              start everything
#   ./start.sh --stop       stop everything
#   ./start.sh --status     show what's running
#   ./start.sh --logs       tail all logs
#   ./start.sh --enforcer   also start the OS enforcer

set -euo pipefail

GAVEL_API_PORT="${GAVEL_API_PORT:-18000}"
GAVEL_MACHINE_KEY="${GAVEL_MACHINE_KEY:-dev-machine-key-change-in-production}"

GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'
RED='\033[0;31m'; GRAY='\033[0;90m'; RESET='\033[0m'

ok()   { echo -e "  ${GREEN}✓${RESET} $1"; }
warn() { echo -e "  ${YELLOW}⚠${RESET} $1"; }
fail() { echo -e "  ${RED}✗${RESET} $1"; }
info() { echo -e "  ${GRAY}·${RESET} $1"; }
header() { echo -e "\n  ${CYAN}$1${RESET}\n  $(printf '─%.0s' $(seq 1 ${#1}))"; }

# ── Flags ─────────────────────────────────────────────────────────────────────

STOP=false; STATUS=false; LOGS=false; ENFORCER=false

for arg in "$@"; do
    case $arg in
        --stop)     STOP=true ;;
        --status)   STATUS=true ;;
        --logs)     LOGS=true ;;
        --enforcer) ENFORCER=true ;;
        --help)
            echo ""
            echo "  Gavel OS — Start Script"
            echo ""
            echo "  Usage:"
            echo "    ./start.sh              Start all services"
            echo "    ./start.sh --enforcer   Also start the OS enforcer"
            echo "    ./start.sh --stop       Stop all services"
            echo "    ./start.sh --status     Show running services and health"
            echo "    ./start.sh --logs       Tail logs from all containers"
            echo ""
            exit 0 ;;
    esac
done

# ── Stop ──────────────────────────────────────────────────────────────────────

if $STOP; then
    header "Stopping Gavel OS"
    docker compose down --remove-orphans
    pkill -f gavel-enforcer 2>/dev/null && ok "Enforcer stopped" || true
    ok "All services stopped"
    exit 0
fi

# ── Status ────────────────────────────────────────────────────────────────────

if $STATUS; then
    header "Gavel OS Status"
    docker compose ps
    echo ""
    if curl -sf "http://localhost:$GAVEL_API_PORT/health" > /tmp/gavel_health.json 2>/dev/null; then
        STATUS_VAL=$(python3 -c "import json,sys; d=json.load(open('/tmp/gavel_health.json')); print(d['status'])")
        ok "Control plane: $STATUS_VAL"
        python3 -c "
import json
d = json.load(open('/tmp/gavel_health.json'))
for k, v in d['components'].items():
    icon = '✓' if v in ('connected','ready','loaded','configured') else '✗'
    print(f'    {icon} {k}: {v}')
"
    else
        fail "Control plane not reachable at http://localhost:$GAVEL_API_PORT"
    fi
    echo ""
    if pgrep -f gavel-enforcer > /dev/null 2>&1; then
        ok "Enforcer: running (PID $(pgrep -f gavel-enforcer))"
    else
        info "Enforcer: not running  (run ./start.sh --enforcer to start)"
    fi
    exit 0
fi

# ── Logs ──────────────────────────────────────────────────────────────────────

if $LOGS; then
    docker compose logs -f --tail=50
    exit 0
fi

# ── Start ─────────────────────────────────────────────────────────────────────

echo ""
echo -e "  ${CYAN}██████╗  █████╗ ██╗   ██╗███████╗██╗${RESET}"
echo -e "  ${CYAN}██╔════╝ ██╔══██╗██║   ██║██╔════╝██║${RESET}"
echo -e "  ${CYAN}██║  ███╗███████║██║   ██║█████╗  ██║${RESET}"
echo -e "  ${CYAN}██║   ██║██╔══██║╚██╗ ██╔╝██╔══╝  ██║${RESET}"
echo -e "  ${CYAN}╚██████╔╝██║  ██║ ╚████╔╝ ███████╗███████╗${RESET}"
echo -e "  ${CYAN} ╚═════╝ ╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚══════╝${RESET}"
echo -e "  ${GRAY}OS-level enforcement runtime for AI agents${RESET}"
echo ""

# ── Check prerequisites ───────────────────────────────────────────────────────

header "Checking prerequisites"

if ! docker info > /dev/null 2>&1; then
    fail "Docker is not running. Start Docker and try again."
    exit 1
fi
ok "Docker is running"

# ── Generate secrets if .env doesn't exist ────────────────────────────────────

if [ ! -f ".env" ]; then
    header "First run — generating secrets"

    MACHINE_KEY=$(openssl rand -hex 32)
    API_KEY=$(openssl rand -hex 32)
    ADMIN_KEY=$(openssl rand -hex 32)
    METRICS_KEY=$(openssl rand -hex 16)

    cat > .env << EOF
# Gavel OS — Auto-generated secrets
# Generated: $(date)

GAVEL_API_PORT=18000
GAVEL_GRPC_PORT=18051
OPA_PORT=18181

GAVEL_MACHINE_KEY=$MACHINE_KEY
API_SECRET_KEY=$API_KEY
ADMIN_SECRET_KEY=$ADMIN_KEY
METRICS_SECRET_KEY=$METRICS_KEY

ENV=development
EOF
    ok ".env created with generated secrets"
    MACHINE_KEY_FOR_ENFORCER="$MACHINE_KEY"
else
    ok ".env already exists"
    MACHINE_KEY_FOR_ENFORCER=$(grep "^GAVEL_MACHINE_KEY=" .env | cut -d= -f2 || echo "$GAVEL_MACHINE_KEY")
fi

# ── Start Docker services ─────────────────────────────────────────────────────

header "Starting services"
info "PostgreSQL, Redis, OPA, Control Plane"

docker compose up -d --build

# ── Wait for control plane ────────────────────────────────────────────────────

header "Waiting for control plane"

MAX_WAIT=60; WAITED=0; HEALTHY=false

while [ $WAITED -lt $MAX_WAIT ]; do
    if curl -sf "http://localhost:$GAVEL_API_PORT/health" > /dev/null 2>&1; then
        HEALTHY=true
        break
    fi
    printf "  ${GRAY}· Waiting... (%d/%ds)${RESET}\r" $WAITED $MAX_WAIT
    sleep 3
    WAITED=$((WAITED + 3))
done

echo ""

if ! $HEALTHY; then
    fail "Control plane did not start within ${MAX_WAIT}s"
    info "Run './start.sh --logs' to diagnose"
    exit 1
fi

STATUS_VAL=$(curl -sf "http://localhost:$GAVEL_API_PORT/health" | python3 -c "import json,sys; print(json.load(sys.stdin)['status'])")
ok "Control plane is $STATUS_VAL"

# ── Start enforcer (optional) ─────────────────────────────────────────────────

if $ENFORCER; then
    header "Starting enforcer"
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')

    if [ ! -f "enforcer/gavel-enforcer" ]; then
        info "Building enforcer binary..."
        (cd enforcer && GOOS=$OS GOARCH=$ARCH go build -o gavel-enforcer .)
    fi

    if [ -f "enforcer/gavel-enforcer" ]; then
        export GAVEL_ENGINE_URL="http://localhost:$GAVEL_API_PORT"
        export GAVEL_MACHINE_KEY="$MACHINE_KEY_FOR_ENFORCER"

        info "Running preflight check..."
        ./enforcer/gavel-enforcer -preflight 2>/dev/null | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    print(f'    ✓ Enforcer mode: {d[\"runtime_mode\"]}')
    print(f'    ✓ Enforcement capable: {d[\"enforcement_capable\"]}')
except: pass
" || true

        nohup ./enforcer/gavel-enforcer > /tmp/gavel-enforcer.log 2>&1 &
        ok "Enforcer started (PID $!, logs: /tmp/gavel-enforcer.log)"
    else
        warn "Enforcer build failed — is Go installed?"
    fi
fi

# ── Quick validation ──────────────────────────────────────────────────────────

header "Validating system"

TOKEN=$(curl -sf -X POST "http://localhost:$GAVEL_API_PORT/auth/token" \
    -H "Content-Type: application/json" \
    -d '{"role":"customer","clearance_level":2}' | python3 -c "import json,sys; print(json.load(sys.stdin)['access_token'])")

DENY=$(curl -sf -X POST "http://localhost:$GAVEL_API_PORT/external/validate" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"action":"data.delete","method":"EXECUTE","required_clearance":1}' | python3 -c "import json,sys; print(json.load(sys.stdin)['is_allowed'])")

[ "$DENY" = "False" ] && ok "Policy enforcement: DENY works (data.delete correctly blocked)" || warn "Unexpected ALLOW for data.delete"

ALLOW=$(curl -sf -X POST "http://localhost:$GAVEL_API_PORT/external/validate" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"action":"read.data","method":"GET","required_clearance":1}' | python3 -c "import json,sys; print(json.load(sys.stdin)['is_allowed'])")

[ "$ALLOW" = "True" ] && ok "Policy enforcement: ALLOW works (read.data correctly permitted)" || warn "Unexpected DENY for read.data"

COUNT=$(curl -sf -X POST "http://localhost:$GAVEL_API_PORT/audit/ledger" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"start_date":"2020-01-01T00:00:00Z","end_date":"2030-12-31T00:00:00Z"}' | python3 -c "import json,sys; print(json.load(sys.stdin)['count'])")

ok "Audit ledger: $COUNT entries recorded"

# ── Done ──────────────────────────────────────────────────────────────────────

echo ""
echo -e "  ${GREEN}┌─────────────────────────────────────────────────┐${RESET}"
echo -e "  ${GREEN}│  Gavel OS is running                            │${RESET}"
echo -e "  ${GREEN}│                                                 │${RESET}"
echo -e "  ${GREEN}│  Control plane:  http://localhost:$GAVEL_API_PORT        │${RESET}"
echo -e "  ${GREEN}│  Health check:   http://localhost:$GAVEL_API_PORT/health │${RESET}"
echo -e "  ${GREEN}│  API docs:       http://localhost:$GAVEL_API_PORT/docs   │${RESET}"
echo -e "  ${GREEN}│                                                 │${RESET}"
echo -e "  ${GREEN}│  VS Code: click the Gavel shield icon           │${RESET}"
echo -e "  ${GREEN}│  Stop:    ./start.sh --stop                     │${RESET}"
echo -e "  ${GREEN}└─────────────────────────────────────────────────┘${RESET}"
echo ""
