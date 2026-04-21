# Contributing to Gavel OS

## Development Setup

### Prerequisites

- Go 1.21+
- Python 3.11+
- Docker + Docker Compose
- `psql` (for running migrations manually)

### Control Plane

```bash
cd control-plane
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt

cp ../.env.example ../.env         # fill in values
docker compose up postgres redis opa -d

uvicorn api.main:app --reload
```

### Enforcer (Linux)

```bash
cd enforcer
go build -o gavel-enforcer .
sudo ./gavel-enforcer -preflight
```

### Enforcer (Windows)

```powershell
cd enforcer
go build -o gavel-enforcer.exe .
.\gavel-enforcer.exe
```

## Running Tests

### Python (control plane)

```bash
cd control-plane
pytest tests/ -v --cov=. --cov-report=term-missing
```

### Go (enforcer)

```bash
cd enforcer
go test ./...
```

## Code Style

**Python:** `ruff check .` and `ruff format .`. Configuration in `pyproject.toml`.

**Go:** `gofmt` and `golangci-lint run`. No custom configuration — standard Go style.

## Pull Request Process

1. Fork the repository and create a branch from `main`.
2. Write tests for any new behavior. PRs without tests for new code will not be merged.
3. Ensure `go test ./...` and `pytest` pass locally before opening a PR.
4. Keep PRs focused. One logical change per PR.
5. Update `CHANGELOG.md` with a brief description of your change under `[Unreleased]`.
6. A maintainer will review within 5 business days.

## Highest-Value Contribution Areas

1. **macOS System Extension enforcement** — the biggest platform gap
2. **AGT adapter** — first-class Microsoft Agent Governance Toolkit integration
3. **Framework adapters** — LangChain, CrewAI, AutoGen, OpenAI Agents SDK
4. **Benchmark suite** — reproducible enforcement latency numbers
5. **OPA policy templates** — SQL injection, privilege escalation, data exfiltration patterns

## Security Vulnerabilities

Do not open public issues for security vulnerabilities. See [SECURITY.md](SECURITY.md).
