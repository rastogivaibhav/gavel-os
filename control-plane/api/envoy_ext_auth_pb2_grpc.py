"""
Minimal gRPC bindings for Envoy ext_authz v3 Authorization service.
"""

from __future__ import annotations

import grpc

from api import envoy_ext_auth_pb2 as external_auth_pb2


class AuthorizationStub:
    def __init__(self, channel):
        self.Check = channel.unary_unary(
            "/envoy.service.auth.v3.Authorization/Check",
            request_serializer=external_auth_pb2.CheckRequest.SerializeToString,
            response_deserializer=external_auth_pb2.CheckResponse.FromString,
        )


class AuthorizationServicer:
    def Check(self, request, context):
        raise NotImplementedError("AuthorizationServicer.Check must be implemented")


def add_AuthorizationServicer_to_server(servicer, server):
    rpc_method_handlers = {
        "Check": grpc.unary_unary_rpc_method_handler(
            servicer.Check,
            request_deserializer=external_auth_pb2.CheckRequest.FromString,
            response_serializer=external_auth_pb2.CheckResponse.SerializeToString,
        ),
    }
    generic_handler = grpc.method_handlers_generic_handler(
        "envoy.service.auth.v3.Authorization",
        rpc_method_handlers,
    )
    server.add_generic_rpc_handlers((generic_handler,))
