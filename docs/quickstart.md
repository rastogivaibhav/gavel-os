# Quickstart

Get Gavel running end-to-end in under 10 minutes.

## Prerequisites

- Docker and Docker Compose
- Go 1.21+ (for the enforcer)
- `openssl` (for generating secrets)

## 1. Clone and configure

```bash
git clone https://github.com/gavel-os/gavel
cd gavel
cp .env.example .env
```

Edit `.env` and fill in the required secrets:

```bash
# Generate secrets
GAVEL_MACHINE_KEY=$(openssl rand -hex 32)
API_SECRET_KEY=$(openssl rand -hex 32)
ADMIN_SECRET_KEY=$(openssl rand -hex 32)
METRICS_SECRET_KEY=$(openssl rand -hex 16)

# Write them to .env
sed -i "s/^GAVEL_MACHINE_KEY=$/GAVEL_MACHINE_KEY=$GAVEL_MACHINE_KEY/" .env
sed -i "s/^API_SECRET_KEY=$/API_SECRET_KEY=$API_SECRET_KEY/" .env
sed -i "s/^ADMIN_SECRET_KEY=$/ADMIN_SECRET_KEY=$ADMIN_SECRET_KEY/" .env
sed -i "s/^METRICS_SECRET_KEY=$/METRICS_SECRET_KEY=$METRICS_SECRET_KEY/" .env
```

## 2. Start the control plane

```bash
docker compose up -d
```

This starts PostgreSQL, Redis, OPA, and the Gavel control plane. Wait ~15 seconds for all health checks to pass, then verify:

```bash
curl http://localhost:18000/health
```

A healthy response looks like:

```json
{
  "status": "healthy",
  "service": "gavel-control-plane",
  "version": "1.0.0",
  "components": {
    "audit_ledger": "connected",
    "policy_loader": "loaded",
    "verdict_engine": "ready",
    "machine_auth": "configured",
    "grpc_authz": "ready",
    "opa_policy_engine": "ready",
    "database": "connected",
    "redis": "connected"
  }
}
```

## 3. Get a JWT token

```bash
TOKEN=$(curl -s -X POST http://localhost:18000/auth/token \
  -H "Content-Type: application/json" \
  -d '{"role": "customer", "tenant_id": "default", "clearance_level": 2}' \
  | jq -r .access_token)
```

## 4. Test a policy decision

```bash
# Should be allowed (read operation, clearance 2)
curl -s -X POST http://localhost:18000/external/validate \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"action": "read.data", "method": "GET", "required_clearance": 1}' | jq .

# Should be denied (blocked action)
curl -s -X POST http://localhost:18000/external/validate \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"action": "data.delete", "method": "EXECUTE", "required_clearance": 1}' | jq .
```

## 5. Run the Linux enforcer (requires Linux with cgroup v2)

```bash
cd enforcer

# Build
GOOS=linux GOARCH=amd64 go build -o gavel-enforcer .

# Preflight check — shows what the enforcer can do on this host
sudo ./gavel-enforcer -preflight

# Start with control plane connection
export GAVEL_ENGINE_URL=http://localhost:18000
export GAVEL_MACHINE_KEY=<your-machine-key-from-.env>
sudo ./gavel-enforcer
```

## 6. Run the Windows enforcer

```powershell
cd enforcer
$env:GOOS = 'windows'; $env:GOARCH = 'amd64'
go build -o gavel-enforcer.exe .

$env:GAVEL_ENGINE_URL = "http://localhost:18000"
$env:GAVEL_MACHINE_KEY = "<your-machine-key-from-.env>"
.\gavel-enforcer.exe
```

## 7. View the audit ledger

```bash
curl -s -X POST http://localhost:18000/audit/ledger \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "start_date": "2020-01-01T00:00:00Z",
    "end_date": "2030-12-31T00:00:00Z",
    "tenant_id": "default"
  }' | jq .
```

## 8. Verify chain integrity

```bash
curl -s -X POST http://localhost:18000/audit/verify \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}' | jq .
```

## Next steps

- [Architecture](architecture.md) — understand the trust model and data flow
- [Policy Authoring](policy-authoring.md) — write OPA/Rego and YAML policies
- [Deployment: Kubernetes](deployment/kubernetes.md) — production cluster deployment
- [API Reference](api-reference.md) — full endpoint documentation
