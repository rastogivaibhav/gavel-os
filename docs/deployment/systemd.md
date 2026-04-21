# Linux Bare-Metal Deployment (systemd)

## Prerequisites

- Linux with cgroup v2 (`/sys/fs/cgroup/cgroup.controllers` must exist)
- Kernel 5.8+ for `CAP_BPF`; kernel 4.15+ with `CAP_SYS_ADMIN` as fallback
- Go 1.21+ to build the enforcer
- Python 3.11+ and pip for the control plane

---

## 1. Build the enforcer

```bash
cd enforcer
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o gavel-enforcer .
sudo cp gavel-enforcer /usr/local/bin/gavel-enforcer
sudo chmod 755 /usr/local/bin/gavel-enforcer
```

Run preflight to verify the host is capable:

```bash
sudo /usr/local/bin/gavel-enforcer -preflight
```

---

## 2. Configure the enforcer

```bash
sudo mkdir -p /etc/gavel
sudo tee /etc/gavel/enforcer.env > /dev/null <<EOF
GAVEL_ENGINE_URL=http://control-plane.internal:8000
GAVEL_MACHINE_KEY=$(openssl rand -hex 32)
EOF
sudo chmod 600 /etc/gavel/enforcer.env
```

---

## 3. Install the systemd unit

```bash
sudo cp deploy/systemd/gavel-enforcer.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now gavel-enforcer
```

Check status:

```bash
sudo systemctl status gavel-enforcer
sudo journalctl -u gavel-enforcer -f
```

---

## 4. Deploy the control plane

```bash
# Create a dedicated user
sudo useradd -r -s /bin/false -d /opt/gavel gavel

# Install Python dependencies
sudo mkdir -p /opt/gavel/control-plane
sudo cp -r control-plane/* /opt/gavel/control-plane/
cd /opt/gavel/control-plane
sudo python3 -m venv /opt/gavel/venv
sudo /opt/gavel/venv/bin/pip install -r requirements.txt

# Configure
sudo mkdir -p /etc/gavel
sudo tee /etc/gavel/control-plane.env > /dev/null <<EOF
ENV=production
DATABASE_URL=postgres://gavel:<password>@localhost:5432/gavel
REDIS_URL=redis://:<password>@localhost:6379/0
OPA_URL=http://localhost:8181
GAVEL_MACHINE_KEY=<same key as enforcer>
API_SECRET_KEY=$(openssl rand -hex 32)
ADMIN_SECRET_KEY=$(openssl rand -hex 32)
METRICS_SECRET_KEY=$(openssl rand -hex 16)
GRPC_TLS_CERT_PATH=/etc/gavel/tls/server.crt
GRPC_TLS_KEY_PATH=/etc/gavel/tls/server.key
EOF
sudo chmod 600 /etc/gavel/control-plane.env
sudo chown gavel:gavel /etc/gavel/control-plane.env
```

---

## 5. Install the control plane systemd unit

```bash
sudo cp deploy/systemd/gavel-control-plane.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now gavel-control-plane
```

---

## 6. Run database migrations

```bash
DATABASE_URL="postgres://gavel:<password>@localhost:5432/gavel" \
  bash database/migrate.sh
```

---

## 7. Verify

```bash
curl http://localhost:8000/health
sudo journalctl -u gavel-enforcer -u gavel-control-plane -f
```
