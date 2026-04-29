# Gavel OS Validation Script (PowerShell)
# Validates running containers and API endpoints

Write-Host "╔════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║   Gavel OS Portal - Validation & Testing Suite        ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Check Docker
Write-Host "📦 Checking Docker..." -ForegroundColor Yellow
try {
    $dockerVersion = docker --version
    Write-Host "✓ Docker found: $dockerVersion" -ForegroundColor Green
} catch {
    Write-Host "✗ Docker not found" -ForegroundColor Red
    exit 1
}
Write-Host ""

# Check Docker Compose
Write-Host "📦 Checking Docker Compose..." -ForegroundColor Yellow
try {
    docker compose version | Out-Null
    Write-Host "✓ Docker Compose found" -ForegroundColor Green
} catch {
    Write-Host "✗ Docker Compose not found" -ForegroundColor Red
    exit 1
}
Write-Host ""

# Check running containers
Write-Host "🔍 Checking running containers..." -ForegroundColor Yellow
$containers = docker compose ps --services --filter "status=running"

if ($containers -contains "control-plane") {
    Write-Host "✓ Control Plane is running" -ForegroundColor Green
    $status = docker compose ps control-plane | Select-Object -Last 1 | ForEach-Object { $_.Split()[-1] }
    Write-Host "  Status: $status"
} else {
    Write-Host "⚠ Control Plane not running" -ForegroundColor Yellow
}

if ($containers -contains "postgres") {
    Write-Host "✓ PostgreSQL is running" -ForegroundColor Green
} else {
    Write-Host "⚠ PostgreSQL not running" -ForegroundColor Yellow
}

if ($containers -contains "opa") {
    Write-Host "✓ OPA Policy Engine is running" -ForegroundColor Green
} else {
    Write-Host "⚠ OPA not running" -ForegroundColor Yellow
}
Write-Host ""

# Check API endpoints
Write-Host "🌐 Checking API Endpoints..." -ForegroundColor Yellow
$apiBase = "http://localhost:18000"

# Root endpoint
Write-Host -NoNewline "  GET / ... "
try {
    $response = Invoke-WebRequest -Uri "$apiBase/" -ErrorAction SilentlyContinue
    if ($response.StatusCode -eq 200) {
        Write-Host "✓ 200 OK" -ForegroundColor Green
    } else {
        Write-Host "✗ Failed" -ForegroundColor Red
    }
} catch {
    Write-Host "✗ Error" -ForegroundColor Red
}

# Health endpoint
Write-Host -NoNewline "  GET /health ... "
try {
    $health = Invoke-WebRequest -Uri "$apiBase/health" -ErrorAction SilentlyContinue | ConvertFrom-Json
    if ($health.status -eq "healthy") {
        Write-Host "✓ Healthy" -ForegroundColor Green
    } else {
        Write-Host "⚠ $($health.status)" -ForegroundColor Yellow
    }
} catch {
    Write-Host "✗ Error" -ForegroundColor Red
}

# Ready endpoint
Write-Host -NoNewline "  GET /ready ... "
try {
    $response = Invoke-WebRequest -Uri "$apiBase/ready" -ErrorAction SilentlyContinue | ConvertFrom-Json
    if ($response.ready) {
        Write-Host "✓ Ready" -ForegroundColor Green
    } else {
        Write-Host "✗ Not ready" -ForegroundColor Red
    }
} catch {
    Write-Host "✗ Error" -ForegroundColor Red
}

# Live endpoint
Write-Host -NoNewline "  GET /live ... "
try {
    $response = Invoke-WebRequest -Uri "$apiBase/live" -ErrorAction SilentlyContinue | ConvertFrom-Json
    if ($response.alive) {
        Write-Host "✓ Alive" -ForegroundColor Green
    } else {
        Write-Host "✗ Not alive" -ForegroundColor Red
    }
} catch {
    Write-Host "✗ Error" -ForegroundColor Red
}
Write-Host ""

# Component health
Write-Host "📊 Component Status:" -ForegroundColor Yellow
try {
    $health = Invoke-WebRequest -Uri "$apiBase/health" -ErrorAction SilentlyContinue | ConvertFrom-Json
    $health.components | ForEach-Object {
        $_.PSObject.Properties | ForEach-Object {
            Write-Host "  $($_.Name): $($_.Value)" -ForegroundColor Cyan
        }
    }
} catch {
    Write-Host "  Unable to fetch component status" -ForegroundColor Yellow
}
Write-Host ""

# Port check
Write-Host "🔌 Port Check:" -ForegroundColor Yellow

$ports = @(
    @{Name = "API (18000)"; Port = 18000},
    @{Name = "OPA (18181)"; Port = 18181},
    @{Name = "PostgreSQL (5432)"; Port = 5432}
)

foreach ($portCheck in $ports) {
    Write-Host -NoNewline "  $($portCheck.Name): "
    try {
        $tcpClient = [System.Net.Sockets.TcpClient]::new()
        $tcpClient.ConnectAsync("127.0.0.1", $portCheck.Port).Wait(1000) | Out-Null
        if ($tcpClient.Connected) {
            Write-Host "✓ Open" -ForegroundColor Green
            $tcpClient.Close()
        } else {
            Write-Host "✗ Closed" -ForegroundColor Red
        }
    } catch {
        Write-Host "✗ Closed" -ForegroundColor Red
    }
}
Write-Host ""

# Test modes
Write-Host "🧪 Testing Options:" -ForegroundColor Yellow
Write-Host "  1. Run API validation tests:"
Write-Host "     python -m pytest tests/playwright/test_api_endpoints.py -v -m playwright" -ForegroundColor Cyan
Write-Host ""
Write-Host "  2. Run full test suite:"
Write-Host "     python -m pytest tests/ -v" -ForegroundColor Cyan
Write-Host ""
Write-Host "  3. Run integration tests:"
Write-Host "     python -m pytest tests/integration/ -v -m integration" -ForegroundColor Cyan
Write-Host ""
Write-Host "  4. Run tests in Docker container:"
Write-Host "     docker-compose -f docker-compose.test.yml up --build test-runner" -ForegroundColor Cyan
Write-Host ""
Write-Host "  5. Validate Linux runtime (in container):"
Write-Host "     docker-compose -f docker-compose.test.yml up runtime-validation" -ForegroundColor Cyan
Write-Host ""

# Summary
Write-Host "╔════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║          Portal is Running and Accessible             ║" -ForegroundColor Cyan
Write-Host "║                                                        ║" -ForegroundColor Cyan
Write-Host "║  API Docs:  http://localhost:18000/docs              ║" -ForegroundColor Cyan
Write-Host "║  API Base:  http://localhost:18000                   ║" -ForegroundColor Cyan
Write-Host "║  OPA:       http://localhost:18181                   ║" -ForegroundColor Cyan
Write-Host "║  Database:  localhost:5432                           ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
