"""
grpc_server.py — Gavel gRPC ext_authz server

Serves the Envoy ext_authz CheckRequest interface on port 50051.

TLS modes (controlled by env vars):
  - Production (default): server-side TLS.
      GRPC_TLS_CERT_PATH  — path to server certificate PEM
      GRPC_TLS_KEY_PATH   — path to server private key PEM
  - mTLS: additionally set
      GRPC_CA_CERT_PATH   — path to CA certificate PEM (enables client verification)
  - Insecure (dev only): set GRPC_INSECURE=true
      The control plane will log a loud warning and refuse insecure mode
      when ENV != development.
"""

from __future__ import annotations

import logging
import os
import sys
import threading
from concurrent import futures
from pathlib import Path

from google.rpc import status_pb2

from api.control_plane import evaluate_runtime_decision
from api.envoy_ext_auth_pb2 import (
    CheckResponse,
    DeniedHttpResponse,
    HttpStatus,
    OkHttpResponse,
)
from api.envoy_ext_auth_pb2_grpc import (
    AuthorizationServicer,
    add_AuthorizationServicer_to_server,
)

try:
    import grpc
    GRPC_AVAILABLE = True
except ImportError:
    GRPC_AVAILABLE = False

logger = logging.getLogger("gavel.grpc")

_GRPC_STATUS = "stopped"
_STATUS_LOCK = threading.Lock()
_SERVER_THREAD: threading.Thread | None = None

_GRPC_PORT = int(os.getenv("GRPC_PORT", "50051"))


def _set_grpc_authz_status(value: str) -> None:
    global _GRPC_STATUS
    with _STATUS_LOCK:
        _GRPC_STATUS = value


def get_grpc_authz_status() -> str:
    with _STATUS_LOCK:
        return _GRPC_STATUS


# ── TLS credential builder ────────────────────────────────────────────────────

def _build_grpc_credentials() -> "grpc.ServerCredentials | None":
    """
    Build gRPC server credentials from environment configuration.

    Returns None only when GRPC_INSECURE=true AND ENV=development.
    Raises SystemExit if insecure mode is requested outside development.
    """
    insecure = os.getenv("GRPC_INSECURE", "false").lower() == "true"
    env = os.getenv("ENV", "production")

    if insecure:
        if env != "development":
            logger.critical(
                "FATAL: GRPC_INSECURE=true is set but ENV=%s. "
                "Insecure gRPC is not permitted outside local development. "
                "Provide TLS certificates via GRPC_TLS_CERT_PATH and GRPC_TLS_KEY_PATH.",
                env,
            )
            sys.exit(1)
        logger.warning(
            "gRPC running in INSECURE mode (GRPC_INSECURE=true). "
            "This is only acceptable for local development."
        )
        return None

    cert_path = os.getenv("GRPC_TLS_CERT_PATH", "")
    key_path = os.getenv("GRPC_TLS_KEY_PATH", "")
    ca_path = os.getenv("GRPC_CA_CERT_PATH", "")

    if not cert_path or not key_path:
        if env == "development":
            # Dev fallback: auto-generate a self-signed cert so the server
            # still starts with TLS without manual cert setup.
            logger.warning(
                "GRPC_TLS_CERT_PATH / GRPC_TLS_KEY_PATH not set. "
                "Generating a self-signed certificate for development use."
            )
            return _generate_dev_tls_credentials()
        logger.critical(
            "FATAL: GRPC_TLS_CERT_PATH and GRPC_TLS_KEY_PATH must be set in production. "
            "Set GRPC_INSECURE=true only for local development."
        )
        sys.exit(1)

    cert_pem = Path(cert_path).read_bytes()
    key_pem = Path(key_path).read_bytes()

    if ca_path:
        # mTLS: verify client certificates against the CA
        ca_pem = Path(ca_path).read_bytes()
        credentials = grpc.ssl_server_credentials(
            [(key_pem, cert_pem)],
            root_certificates=ca_pem,
            require_client_auth=True,
        )
        logger.info("gRPC mTLS enabled (cert=%s ca=%s)", cert_path, ca_path)
    else:
        # Server-side TLS only
        credentials = grpc.ssl_server_credentials([(key_pem, cert_pem)])
        logger.info("gRPC server-side TLS enabled (cert=%s)", cert_path)

    return credentials


def _generate_dev_tls_credentials() -> "grpc.ServerCredentials":
    """Generate a self-signed RSA certificate for development gRPC TLS."""
    import datetime
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "gavel-grpc-dev"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.DNSName("gavel-control-plane"),
            ]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)

    # Persist so the Envoy sidecar can trust the cert
    dev_cert_dir = Path(os.getenv("GRPC_DEV_CERT_DIR", "/tmp/gavel-grpc-dev"))
    dev_cert_dir.mkdir(parents=True, exist_ok=True)
    (dev_cert_dir / "server.crt").write_bytes(cert_pem)
    (dev_cert_dir / "server.key").write_bytes(key_pem)
    logger.info("Dev gRPC TLS cert written to %s", dev_cert_dir)

    return grpc.ssl_server_credentials([(key_pem, cert_pem)])


# ── Servicer ──────────────────────────────────────────────────────────────────

class GavelAuthorizationServicer(AuthorizationServicer):
    def __init__(self, app):
        self.app = app

    def Check(self, request, context):
        try:
            http_request = request.attributes.request
            headers = {key.lower(): value for key, value in http_request.headers.items()}
            host = http_request.host or headers.get(":authority") or headers.get("host") or "unknown"
            method = http_request.method or "CONNECT"
            path = http_request.path or "/"
            action = f"{host}{path}" if path and path != "/" else host
            target_tenant_id = headers.get("x-tenant-id", "default")
            required_clearance = int(headers.get("x-required-clearance", "1") or 1)

            decision = evaluate_runtime_decision(
                self.app,
                action=action,
                method=method,
                target_tenant_id=target_tenant_id,
                required_clearance=required_clearance,
                host_id=headers.get("x-gavel-host-id", host),
                agent_id=headers.get("user-agent", "envoy"),
                runtime_mode="enforce",
                enforcement_capable=True,
                runtime_os=headers.get("x-runtime-os", "linux"),
                runtime_arch=headers.get("x-runtime-arch", "amd64"),
                headers=headers,
                auth_status="authenticated" if headers.get("authorization") else "anonymous",
            )

            if decision["is_allowed"]:
                return CheckResponse(
                    status=status_pb2.Status(code=0, message=decision["reason"]),
                    ok_response=OkHttpResponse(),
                )

            denied_code = 503 if decision["reason_code"] == "CONTROL_PLANE_DEGRADED" else 403
            grpc_status = 14 if denied_code == 503 else 7
            return CheckResponse(
                status=status_pb2.Status(code=grpc_status, message=decision["reason"]),
                denied_response=DeniedHttpResponse(
                    status=HttpStatus(code=denied_code),
                    body=decision["reason"],
                ),
            )
        except Exception as exc:
            logger.exception("Envoy ext_authz check failed: %s", exc)
            return CheckResponse(
                status=status_pb2.Status(code=14, message="Authorization service failure"),
                denied_response=DeniedHttpResponse(
                    status=HttpStatus(code=503),
                    body="Authorization service failure",
                ),
            )


# ── Server lifecycle ──────────────────────────────────────────────────────────

def serve_grpc(app) -> None:
    if not GRPC_AVAILABLE:
        logger.warning("grpcio not installed — Envoy ext_authz will not function.")
        _set_grpc_authz_status("unavailable")
        return

    _set_grpc_authz_status("starting")

    credentials = _build_grpc_credentials()

    server = grpc.server(
        futures.ThreadPoolExecutor(max_workers=int(os.getenv("GRPC_MAX_WORKERS", "10"))),
        options=[
            ("grpc.max_receive_message_length", 1 * 1024 * 1024),   # 1 MB
            ("grpc.max_send_message_length", 1 * 1024 * 1024),
            ("grpc.keepalive_time_ms", 30_000),
            ("grpc.keepalive_timeout_ms", 10_000),
            ("grpc.keepalive_permit_without_calls", True),
        ],
    )
    add_AuthorizationServicer_to_server(GavelAuthorizationServicer(app), server)

    bind_address = f"[::]:{_GRPC_PORT}"
    if credentials is None:
        server.add_insecure_port(bind_address)
        logger.warning("gRPC ext_authz listening on %s (INSECURE — dev only)", bind_address)
    else:
        server.add_secure_port(bind_address, credentials)
        logger.info("gRPC ext_authz listening on %s (TLS)", bind_address)

    server.start()
    _set_grpc_authz_status("ready")
    server.wait_for_termination()
    _set_grpc_authz_status("stopped")


def start_grpc_background(app) -> None:
    global _SERVER_THREAD
    if _SERVER_THREAD and _SERVER_THREAD.is_alive():
        return
    _SERVER_THREAD = threading.Thread(target=serve_grpc, args=(app,), daemon=True)
    _SERVER_THREAD.start()
