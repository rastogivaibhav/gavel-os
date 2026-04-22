#!/usr/bin/env pwsh
# start.ps1 — One-command Gavel OS startup for Windows
#
# Usage:
#   .\start.ps1              # start everything
#   .\start.ps1 -Stop        # stop everything
#   .\start.ps1 -Status      # show what's running
#   .\start.ps1 -Logs        # tail all logs
#   .\start.ps1 -Enforcer    # also start the Windows enforcer

param(
    [switch]$Stop,
    [switch]$Status,
    [switch]$Logs,
    [switch]$Enforcer,
    [switch]$Help
)

$ErrorActionPreference = "Stop"
$GAVEL_API_PORT = $env:GAVEL_API_PORT ?? "18000"
$GAVEL_MACHINE_KEY = $env:GAVEL_MACHINE_KEY ?? "dev-machine-key-change-in-production"

function Write-Header($text) {
    Write-Host ""
    Write-Host "  $text" -ForegroundColor Cyan
    Write-Host "  $("─" * $text.Length)" -ForegroundColor DarkGray
}

function Write-Ok($text)   { Write-Host "  ✓ $text" -ForegroundColor Green }
function Write-Warn($text) { Write-Host "  ⚠ $text" -ForegroundColor Yellow }
function Write-Fail($text) { Write-Host "  ✗ $text" -ForegroundColor Red }
function Write-Info($text) { Write-Host "  · $text" -ForegroundColor Gray }

# ── Help ──────────────────────────────────────────────────────────────────────

if ($Help) {
    Write-Host @"

  Gavel OS — Start Script

  Usage:
    .\start.ps1              Start all services (control plane + dependencies)
    .\start.ps1 -Enforcer    Also start the Windows enforcer (requires Go)
    .\start.ps1 -Stop        Stop all services
    .\start.ps1 -Status      Show running services and health
    .\start.ps1 -Logs        Tail logs from all containers
    .\start.ps1 -Help        Show this help

  After starting, open:
    http://localhost:$GAVEL_API_PORT/health   — health check
    http://localhost:$GAVEL_API_PORT/docs     — API documentation

"@
    exit 0
}

# ── Stop ──────────────────────────────────────────────────────────────────────

if ($Stop) {
    Write-Header "Stopping Gavel OS"
    docker compose down --remove-orphans 2>&1 | Out-Null
    Write-Ok "All services stopped"

    # Stop enforcer if running
    $enforcer = Get-Process -Name "gavel-enforcer" -ErrorAction SilentlyContinue
    if ($enforcer) {
        Stop-Process -Name "gavel-enforcer" -Force
        Write-Ok "Enforcer stopped"
    }
    exit 0
}

# ── Status ────────────────────────────────────────────────────────────────────

if ($Status) {
    Write-Header "Gavel OS Status"

    # Docker services
    $containers = docker compose ps --format json 2>&1
    if ($LASTEXITCODE -eq 0) {
        docker compose ps
    }

    # Health check
    try {
        $health = Invoke-RestMethod -Uri "http://localhost:$GAVEL_API_PORT/health" -TimeoutSec 3
        Write-Host ""
        Write-Ok "Control plane: $($health.status) (v$($health.version))"
        foreach ($component in $health.components.PSObject.Properties) {
            $icon = if ($component.Value -in @("connected","ready","loaded","configured")) { "✓" } else { "✗" }
            $color = if ($component.Value -in @("connected","ready","loaded","configured")) { "Green" } else { "Red" }
            Write-Host "    $icon $($component.Name): $($component.Value)" -ForegroundColor $color
        }
    } catch {
        Write-Fail "Control plane not reachable at http://localhost:$GAVEL_API_PORT"
    }

    # Enforcer
    $enforcer = Get-Process -Name "gavel-enforcer" -ErrorAction SilentlyContinue
    Write-Host ""
    if ($enforcer) {
        Write-Ok "Enforcer: running (PID $($enforcer.Id))"
    } else {
        Write-Info "Enforcer: not running  (run .\start.ps1 -Enforcer to start)"
    }
    exit 0
}

# ── Logs ──────────────────────────────────────────────────────────────────────

if ($Logs) {
    docker compose logs -f --tail=50
    exit 0
}

# ── Start ─────────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "  ██████╗  █████╗ ██╗   ██╗███████╗██╗" -ForegroundColor Cyan
Write-Host "  ██╔════╝ ██╔══██╗██║   ██║██╔════╝██║" -ForegroundColor Cyan
Write-Host "  ██║  ███╗███████║██║   ██║█████╗  ██║" -ForegroundColor Cyan
Write-Host "  ██║   ██║██╔══██║╚██╗ ██╔╝██╔══╝  ██║" -ForegroundColor Cyan
Write-Host "  ╚██████╔╝██║  ██║ ╚████╔╝ ███████╗███████╗" -ForegroundColor Cyan
Write-Host "   ╚═════╝ ╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚══════╝" -ForegroundColor Cyan
Write-Host "  OS-level enforcement runtime for AI agents" -ForegroundColor DarkGray
Write-Host ""

# ── Check prerequisites ───────────────────────────────────────────────────────

Write-Header "Checking prerequisites"

$dockerOk = $false
try {
    docker info 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Ok "Docker is running"
        $dockerOk = $true
    }
} catch {}

if (-not $dockerOk) {
    Write-Fail "Docker is not running. Start Docker Desktop and try again."
    exit 1
}

# ── Generate secrets if .env doesn't exist ────────────────────────────────────

if (-not (Test-Path ".env")) {
    Write-Header "First run — generating secrets"

    $machineKey  = -join ((1..32) | ForEach-Object { '{0:x2}' -f (Get-Random -Max 256) })
    $apiKey      = -join ((1..32) | ForEach-Object { '{0:x2}' -f (Get-Random -Max 256) })
    $adminKey    = -join ((1..32) | ForEach-Object { '{0:x2}' -f (Get-Random -Max 256) })
    $metricsKey  = -join ((1..16) | ForEach-Object { '{0:x2}' -f (Get-Random -Max 256) })

    $envContent = @"
# Gavel OS — Auto-generated secrets
# Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")

GAVEL_API_PORT=18000
GAVEL_GRPC_PORT=18051
OPA_PORT=18181

GAVEL_MACHINE_KEY=$machineKey
API_SECRET_KEY=$apiKey
ADMIN_SECRET_KEY=$adminKey
METRICS_SECRET_KEY=$metricsKey

ENV=development
"@
    $envContent | Set-Content ".env"
    Write-Ok ".env created with generated secrets"

    # Reload for this session
    $machineKeyForEnforcer = $machineKey
} else {
    Write-Ok ".env already exists"
    # Read machine key for enforcer
    $envVars = Get-Content ".env" | Where-Object { $_ -match "^GAVEL_MACHINE_KEY=" }
    $machineKeyForEnforcer = if ($envVars) { ($envVars -split "=", 2)[1] } else { $GAVEL_MACHINE_KEY }
}

# ── Start Docker services ─────────────────────────────────────────────────────

Write-Header "Starting services"
Write-Info "PostgreSQL, Redis, OPA, Control Plane"

docker compose up -d --build 2>&1 | ForEach-Object {
    if ($_ -match "✔|Created|Started|Healthy|Running") {
        Write-Ok $_
    } elseif ($_ -match "✘|Error|error|failed") {
        Write-Fail $_
    } elseif ($_ -match "WARNING|warning") {
        # suppress version warnings
    } else {
        Write-Info $_
    }
}

if ($LASTEXITCODE -ne 0) {
    Write-Fail "Docker Compose failed. Run '.\start.ps1 -Logs' to see what went wrong."
    exit 1
}

# ── Wait for control plane to be healthy ──────────────────────────────────────

Write-Header "Waiting for control plane"

$maxWait = 60
$waited = 0
$healthy = $false

while ($waited -lt $maxWait) {
    try {
        $health = Invoke-RestMethod -Uri "http://localhost:$GAVEL_API_PORT/health" -TimeoutSec 2
        if ($health.status -in @("healthy", "degraded")) {
            $healthy = $true
            break
        }
    } catch {}

    Write-Host "  · Waiting... ($waited/$maxWait s)" -ForegroundColor DarkGray -NoNewline
    Write-Host "`r" -NoNewline
    Start-Sleep -Seconds 3
    $waited += 3
}

if (-not $healthy) {
    Write-Fail "Control plane did not start within $maxWait seconds"
    Write-Info "Run '.\start.ps1 -Logs' to diagnose"
    exit 1
}

Write-Ok "Control plane is $($health.status)"

# ── Start Windows enforcer (optional) ────────────────────────────────────────

if ($Enforcer) {
    Write-Header "Starting Windows enforcer"

    # Build if binary doesn't exist
    if (-not (Test-Path "enforcer\gavel-enforcer.exe")) {
        Write-Info "Building enforcer binary..."
        Push-Location enforcer
        $env:GOOS = "windows"; $env:GOARCH = "amd64"
        go build -o gavel-enforcer.exe . 2>&1 | Out-Null
        Pop-Location
        if (-not (Test-Path "enforcer\gavel-enforcer.exe")) {
            Write-Fail "Enforcer build failed. Is Go installed?"
        }
    }

    if (Test-Path "enforcer\gavel-enforcer.exe") {
        $env:GAVEL_ENGINE_URL = "http://localhost:$GAVEL_API_PORT"
        $env:GAVEL_MACHINE_KEY = $machineKeyForEnforcer

        # Run preflight first
        Write-Info "Running preflight check..."
        $preflight = & ".\enforcer\gavel-enforcer.exe" -preflight 2>&1 | ConvertFrom-Json -ErrorAction SilentlyContinue
        if ($preflight) {
            Write-Ok "Enforcer mode: $($preflight.runtime_mode)"
            Write-Ok "Enforcement capable: $($preflight.enforcement_capable)"
        }

        # Start enforcer in background
        Start-Process -FilePath ".\enforcer\gavel-enforcer.exe" `
            -WindowStyle Hidden `
            -PassThru | Out-Null
        Write-Ok "Enforcer started in background"
    }
}

# ── Quick validation ──────────────────────────────────────────────────────────

Write-Header "Validating system"

try {
    # Get token
    $token = (Invoke-RestMethod -Uri "http://localhost:$GAVEL_API_PORT/auth/token" `
        -Method POST -ContentType "application/json" `
        -Body '{"role":"customer","clearance_level":2}').access_token

    # Test deny
    $deny = Invoke-RestMethod -Uri "http://localhost:$GAVEL_API_PORT/external/validate" `
        -Method POST -ContentType "application/json" `
        -Headers @{Authorization="Bearer $token"} `
        -Body '{"action":"data.delete","method":"EXECUTE","required_clearance":1}'

    if ($deny.is_allowed -eq $false) {
        Write-Ok "Policy enforcement: DENY works (data.delete correctly blocked)"
    } else {
        Write-Warn "Policy enforcement: unexpected ALLOW for data.delete"
    }

    # Test allow
    $allow = Invoke-RestMethod -Uri "http://localhost:$GAVEL_API_PORT/external/validate" `
        -Method POST -ContentType "application/json" `
        -Headers @{Authorization="Bearer $token"} `
        -Body '{"action":"read.data","method":"GET","required_clearance":1}'

    if ($allow.is_allowed -eq $true) {
        Write-Ok "Policy enforcement: ALLOW works (read.data correctly permitted)"
    } else {
        Write-Warn "Policy enforcement: unexpected DENY for read.data"
    }

    # Check audit ledger
    $ledger = Invoke-RestMethod -Uri "http://localhost:$GAVEL_API_PORT/audit/ledger" `
        -Method POST -ContentType "application/json" `
        -Headers @{Authorization="Bearer $token"} `
        -Body '{"start_date":"2020-01-01T00:00:00Z","end_date":"2030-12-31T00:00:00Z"}'

    Write-Ok "Audit ledger: $($ledger.count) entries recorded"

} catch {
    Write-Warn "Validation skipped: $($_.Exception.Message)"
}

# ── Done ──────────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "  ┌─────────────────────────────────────────────────┐" -ForegroundColor Green
Write-Host "  │  Gavel OS is running                            │" -ForegroundColor Green
Write-Host "  │                                                 │" -ForegroundColor Green
Write-Host "  │  Control plane:  http://localhost:$GAVEL_API_PORT        │" -ForegroundColor Green
Write-Host "  │  Health check:   http://localhost:$GAVEL_API_PORT/health │" -ForegroundColor Green
Write-Host "  │  API docs:       http://localhost:$GAVEL_API_PORT/docs   │" -ForegroundColor Green
Write-Host "  │                                                 │" -ForegroundColor Green
Write-Host "  │  VS Code: click the Gavel shield icon           │" -ForegroundColor Green
Write-Host "  │  Stop:    .\start.ps1 -Stop                     │" -ForegroundColor Green
Write-Host "  └─────────────────────────────────────────────────┘" -ForegroundColor Green
Write-Host ""
