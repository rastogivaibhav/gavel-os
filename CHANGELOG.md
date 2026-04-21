# Changelog

All notable changes to Gavel OS are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added — Phase 4: GA Polish

**Version bump**
- Control plane version bumped from `0.1.0-alpha` to `1.0.0` in `main.py` (FastAPI app + health endpoint)

**CI/CD** (`.github/workflows/`)
- `ci.yml` — runs on every PR and push to main: Go vet + golangci-lint + `go test`, Python ruff lint + format check + pytest with 75% coverage gate, Docker build smoke test, gitleaks secret scan
- `release.yml` — triggered on `v*` tags: builds enforcer binaries for all 6 platform/arch combinations, builds and pushes multi-arch Docker image to `ghcr.io`, creates GitHub Release with binary attachments and release notes

**Documentation** (`docs/`)
- `quickstart.md` — end-to-end setup in under 10 minutes: clone, configure, `docker compose up`, get token, test policy decision, run enforcer, view audit ledger
- `architecture.md` — trust boundary diagram, component descriptions, enforcement decision flow, fail-closed behaviour, audit chain structure
- `policy-authoring.md` — OPA/Rego authz and runtime policies with input shapes, data.json format, testing with curl; YAML policy format with all condition fields, priority ordering, hot reload, Python test examples, common patterns
- `security-model.md` — trust boundaries, authentication (machine key, JWT, JWKS), fail-closed default, audit ledger integrity, gRPC TLS modes, rate limiting, known limitations
- `api-reference.md` — all endpoints: auth, health, external (REST + machine), audit, telemetry, metrics
- `deployment/kubernetes.md` — raw manifests and Helm deployment, database migration job, health checks, enforcer privileges, scaling
- `deployment/systemd.md` — Linux bare-metal: build enforcer, configure, install systemd units, run migrations, verify

**Python test suite** (`tests/`)
- `conftest.py` — shared fixtures: `make_proposal()`, `mock_app_state`, `mock_opa_allow/deny/unavailable`, sys.path bootstrap
- `test_verdict_engine.py` — 18 tests covering all 4 VerdictEngine rules, reason truncation, OK reason, policy set integration (BLOCK/ESCALATE/no-match), proposal ID preservation
- `test_policy.py` — 18 tests covering `evaluate_policies` and `_matches`: tenant/role/environment/api_ref/operation matching, numeric parameter constraints, priority ordering, AND semantics
- `test_jwt_handler.py` — 12 tests covering token creation, `kid` header, claim round-trip, expiry rejection, tamper rejection, wrong algorithm rejection, JWKS export, JWKS round-trip verification
- `test_auth_middleware.py` — 10 tests covering public paths, Bearer/API-key/machine-key auth, expired token, wrong key, and the `sys.exit(1)` production guard
- `test_opa_engine.py` — 9 tests covering `is_available`, allow/deny/unavailable/exception paths, env var configuration
- `test_control_plane.py` — 9 tests covering `identity_context_from_headers`, degraded control plane deny, machine auth role assignment, `build_runtime_policy` (no policy, blocked IPs, Windows IP folding, degraded)
- `test_runtime_contract.py` — 14 tests covering `RuntimeEventEnvelope` metadata validation: all allowed keys accepted, all blocked keys rejected, unknown keys rejected, timezone normalisation, Windows/macOS enforcer metadata
- `test_external_routes.py` — 14 integration tests covering all 5 `/external/*` endpoints: auth enforcement, allow/deny verdicts, policy response shape, agent detection

**Kubernetes manifests** (`deploy/kubernetes/`)
- `namespace.yaml`, `rbac.yaml`, `secret-template.yaml`, `configmap.yaml`
- `control-plane-deployment.yaml` — 2-replica, TLS mounts, probes, non-root, topology spread
- `control-plane-service.yaml` — ClusterIP on 8000 + 50051
- `opa-deployment.yaml` — 2-replica OPA + service
- `enforcer-daemonset.yaml` — `CAP_BPF`/`CAP_SYS_ADMIN`/`CAP_NET_ADMIN`, cgroup + bpf mounts, Linux node selector
- `networkpolicy.yaml` — enforcer→control-plane ingress only; enforcer egress restricted to control-plane + DNS

**Helm chart** (`deploy/helm/gavel/`)
- `Chart.yaml`, `values.yaml`, `templates/_helpers.tpl`
- `templates/deployment.yaml`, `service.yaml`, `daemonset.yaml`, `configmap.yaml`, `rbac.yaml`

### Added — Phase 2: Security Hardening
- **gRPC TLS**: `grpc_server.py` now builds server credentials from `GRPC_TLS_CERT_PATH` / `GRPC_TLS_KEY_PATH`. mTLS enabled when `GRPC_CA_CERT_PATH` is also set. In development, a self-signed cert is auto-generated. `GRPC_INSECURE=true` is rejected outside `ENV=development` with a hard `sys.exit`.
- **Per-host rate limiting**: `api/middleware/rate_limit.py` — slowapi limiter keyed on `X-Gavel-Host-Id` (falls back to IP). Redis-backed when `REDIS_URL` is set; in-memory fallback for single-instance dev. Applied to `/external/runtime/validate` (200/min), `/external/heartbeat` (4/min), `/internal/telemetry/push` (300/min), `/external/runtime/policy` (30/min). All limits configurable via env vars.
- **JWKS endpoint**: `GET /auth/jwks` and `GET /.well-known/jwks.json` expose the local RSA public key as a JWKS document. `Cache-Control` header set to `JWKS_CACHE_TTL_SECONDS`.
- **JWT key rotation**: `jwt_handler.py` accepts `JWKS_URL` env var. Tokens signed by any key in the remote JWKS are accepted alongside the local key. Remote keys are cached with configurable TTL. `kid` header is now embedded in all issued JWTs.
- **Metadata contract fix**: `ALLOWED_METADATA_KEYS` in `runtime_contract.py` expanded to cover all keys actually sent by Linux, Windows, and macOS enforcers (`process_id`, `remote_port`, `network_source`, `kernel_version`, `cgroup_v2`, `ebpf_program_status`, provider identity fields, macOS audit fields, etc.).
- New env vars: `GRPC_TLS_CERT_PATH`, `GRPC_TLS_KEY_PATH`, `GRPC_CA_CERT_PATH`, `GRPC_INSECURE`, `GRPC_PORT`, `GRPC_DEV_CERT_DIR`, `RATE_LIMIT_VALIDATE`, `RATE_LIMIT_HEARTBEAT`, `RATE_LIMIT_TELEMETRY`, `RATE_LIMIT_POLICY`, `JWKS_URL`, `JWKS_CACHE_TTL_SECONDS`, `JWT_KEY_ID`.

### Changed
- `grpc_server.py`: removed `add_insecure_port` as the default binding. Insecure mode now requires explicit opt-in.
- `api/main.py`: rate limiter now sourced from `api.middleware.rate_limit` (centralised) instead of being constructed inline.
- `/auth/jwks` and `/.well-known/jwks.json` added to `_PUBLIC_PATHS` — no auth required to fetch the key set.

## [0.1.0-alpha] — 2026-03-17

### Added
- Initial alpha release
- Linux eBPF cgroup socket enforcer (`enforcer/main.go`, `gavel.bpf.c`)
- Windows ETW/WFP enforcer (`enforcer/windows_enforcer.go`, `windows_runtime_components.go`)
- macOS audit-only runtime (`enforcer/darwin_runtime.go`)
- FastAPI control plane with OPA integration, JWT auth, machine-key auth
- Cryptographic SHA-256 chained audit ledger
- gRPC ext_authz server for Envoy sidecar integration
- Real-time telemetry via WebSocket
- SRP VerdictEngine with deterministic policy evaluation
- Prometheus metrics endpoint
- Kubernetes readiness/liveness probes (`/readyz`, `/health`)
