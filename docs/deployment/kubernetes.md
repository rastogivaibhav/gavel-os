# Kubernetes Deployment

## Prerequisites

- Kubernetes 1.27+
- `kubectl` configured for your cluster
- `helm` 3.12+ (for Helm deployment)
- A PostgreSQL instance (managed or in-cluster)
- A Redis instance (managed or in-cluster)

---

## Option A: Raw Manifests

Apply manifests in order:

```bash
# 1. Namespace
kubectl apply -f deploy/kubernetes/namespace.yaml

# 2. RBAC
kubectl apply -f deploy/kubernetes/rbac.yaml

# 3. Secrets (fill in real values first — see secret-template.yaml)
kubectl create secret generic gavel-secrets \
  --namespace gavel-system \
  --from-literal=GAVEL_MACHINE_KEY=$(openssl rand -hex 32) \
  --from-literal=API_SECRET_KEY=$(openssl rand -hex 32) \
  --from-literal=ADMIN_SECRET_KEY=$(openssl rand -hex 32) \
  --from-literal=METRICS_SECRET_KEY=$(openssl rand -hex 16) \
  --from-literal=DATABASE_URL="postgres://gavel:<password>@<host>:5432/gavel" \
  --from-literal=REDIS_URL="redis://:<password>@<host>:6379/0"

# 4. gRPC TLS secret (generate or use your PKI)
kubectl create secret generic gavel-grpc-tls \
  --namespace gavel-system \
  --from-file=server.crt=/path/to/server.crt \
  --from-file=server.key=/path/to/server.key

# 5. ConfigMap
kubectl apply -f deploy/kubernetes/configmap.yaml

# 6. OPA
kubectl apply -f deploy/kubernetes/opa-deployment.yaml

# 7. Control plane
kubectl apply -f deploy/kubernetes/control-plane-deployment.yaml
kubectl apply -f deploy/kubernetes/control-plane-service.yaml

# 8. Enforcer DaemonSet (Linux nodes only)
kubectl apply -f deploy/kubernetes/enforcer-daemonset.yaml

# 9. Network policies
kubectl apply -f deploy/kubernetes/networkpolicy.yaml
```

Verify:

```bash
kubectl -n gavel-system get pods
kubectl -n gavel-system logs -l app=gavel-control-plane --tail=50
kubectl -n gavel-system port-forward svc/gavel-control-plane 8000:8000
curl http://localhost:8000/health
```

---

## Option B: Helm

```bash
# Install
helm install gavel ./deploy/helm/gavel \
  --namespace gavel-system \
  --create-namespace \
  --set controlPlane.existingSecret=gavel-secrets \
  --set controlPlane.grpcTls.existingSecret=gavel-grpc-tls

# Upgrade
helm upgrade gavel ./deploy/helm/gavel \
  --namespace gavel-system \
  --reuse-values

# Uninstall
helm uninstall gavel --namespace gavel-system
```

### Custom values

```yaml
# my-values.yaml
controlPlane:
  replicas: 3
  resources:
    requests:
      cpu: "500m"
      memory: "512Mi"
    limits:
      cpu: "2000m"
      memory: "1Gi"
  env:
    RATE_LIMIT_VALIDATE: "500/minute"
    ENABLE_OTLP: "true"
    OTEL_EXPORTER_OTLP_ENDPOINT: "http://otel-collector:4317"

enforcer:
  resources:
    limits:
      cpu: "500m"
      memory: "256Mi"
```

```bash
helm install gavel ./deploy/helm/gavel \
  --namespace gavel-system \
  --create-namespace \
  -f my-values.yaml \
  --set controlPlane.existingSecret=gavel-secrets
```

---

## Database Migrations

Run migrations before deploying the control plane:

```bash
# From a pod with psql access, or a migration job
DATABASE_URL="postgres://gavel:<password>@<host>:5432/gavel" \
  bash database/migrate.sh
```

Or as a Kubernetes Job:

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: gavel-migrate
  namespace: gavel-system
spec:
  template:
    spec:
      restartPolicy: OnFailure
      containers:
        - name: migrate
          image: postgres:16-alpine
          command: ["/bin/sh", "-c"]
          args:
            - |
              for f in /migrations/*.sql; do
                psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f "$f"
              done
          env:
            - name: DATABASE_URL
              valueFrom:
                secretKeyRef:
                  name: gavel-secrets
                  key: DATABASE_URL
          volumeMounts:
            - name: migrations
              mountPath: /migrations
      volumes:
        - name: migrations
          configMap:
            name: gavel-migrations
```

---

## Health Checks

The control plane exposes two probe endpoints:

| Endpoint | Purpose | Returns 503 when |
|---|---|---|
| `GET /health` | Liveness + component status | Any critical component is unavailable |
| `GET /readyz` | Kubernetes readiness | audit_ledger, policy_loader, or verdict_engine not initialized |

---

## Enforcer Privileges

The enforcer DaemonSet requires elevated privileges for eBPF:

```yaml
securityContext:
  capabilities:
    add: ["BPF", "SYS_ADMIN", "NET_ADMIN"]
```

On kernels < 5.8 that lack `CAP_BPF`, `CAP_SYS_ADMIN` alone is sufficient. The enforcer's preflight check (`-preflight`) reports exactly which capabilities are present and whether enforcement mode is available.

---

## Scaling

The control plane is stateless (state is in PostgreSQL and Redis). Scale horizontally:

```bash
kubectl -n gavel-system scale deployment gavel-control-plane --replicas=5
```

Rate limiting uses Redis as a shared counter store when `REDIS_URL` is configured, so limits are correctly enforced across all replicas.
