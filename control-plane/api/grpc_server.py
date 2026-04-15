from __future__ import annotations

import logging
import threading
from concurrent import futures

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


def _set_grpc_authz_status(value: str) -> None:
    global _GRPC_STATUS
    with _STATUS_LOCK:
        _GRPC_STATUS = value


def get_grpc_authz_status() -> str:
    with _STATUS_LOCK:
        return _GRPC_STATUS


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
                runtime_os=headers.get("x-runtime-os", "windows"),
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


def serve_grpc(app):
    if not GRPC_AVAILABLE:
        logger.warning("gRPC not installed. Envoy ext_authz will not function.")
        _set_grpc_authz_status("unavailable")
        return

    _set_grpc_authz_status("starting")
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    add_AuthorizationServicer_to_server(GavelAuthorizationServicer(app), server)
    server.add_insecure_port("[::]:50051")
    server.start()
    _set_grpc_authz_status("ready")
    logger.info("Gavel gRPC ext_authz server active on port 50051")
    server.wait_for_termination()


def start_grpc_background(app):
    global _SERVER_THREAD
    if _SERVER_THREAD and _SERVER_THREAD.is_alive():
        return

    _SERVER_THREAD = threading.Thread(target=serve_grpc, args=(app,), daemon=True)
    _SERVER_THREAD.start()
