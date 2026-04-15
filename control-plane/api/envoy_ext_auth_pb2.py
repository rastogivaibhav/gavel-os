"""
Minimal protobuf definitions for Envoy ext_authz v3.

This intentionally defines only the subset of the protocol we use.
"""

from __future__ import annotations

from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pb2
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database

import google.rpc.context.attribute_context_pb2  # noqa: F401
import google.rpc.status_pb2  # noqa: F401

_sym_db = _symbol_database.Default()
_pool = _descriptor_pool.Default()


def _add_file_descriptor(file_proto: descriptor_pb2.FileDescriptorProto):
    try:
        return _pool.AddSerializedFile(file_proto.SerializeToString())
    except Exception:
        return _pool.FindFileByName(file_proto.name)


_http_status_proto = descriptor_pb2.FileDescriptorProto()
_http_status_proto.name = "envoy/type/v3/http_status.proto"
_http_status_proto.package = "envoy.type.v3"
_http_status_proto.syntax = "proto3"

_status_enum = _http_status_proto.enum_type.add()
_status_enum.name = "StatusCode"
for name, number in (
    ("STATUS_CODE_UNSPECIFIED", 0),
    ("OK", 200),
    ("UNAUTHORIZED", 401),
    ("FORBIDDEN", 403),
    ("SERVICE_UNAVAILABLE", 503),
):
    value = _status_enum.value.add()
    value.name = name
    value.number = number

_http_status_msg = _http_status_proto.message_type.add()
_http_status_msg.name = "HttpStatus"
field = _http_status_msg.field.add()
field.name = "code"
field.number = 1
field.label = _descriptor.FieldDescriptor.LABEL_OPTIONAL
field.type = _descriptor.FieldDescriptor.TYPE_ENUM
field.type_name = ".envoy.type.v3.StatusCode"

_add_file_descriptor(_http_status_proto)

_base_proto = descriptor_pb2.FileDescriptorProto()
_base_proto.name = "envoy/config/core/v3/base.proto"
_base_proto.package = "envoy.config.core.v3"
_base_proto.syntax = "proto3"

_header_value = _base_proto.message_type.add()
_header_value.name = "HeaderValue"
field = _header_value.field.add()
field.name = "key"
field.number = 1
field.label = _descriptor.FieldDescriptor.LABEL_OPTIONAL
field.type = _descriptor.FieldDescriptor.TYPE_STRING
field = _header_value.field.add()
field.name = "value"
field.number = 2
field.label = _descriptor.FieldDescriptor.LABEL_OPTIONAL
field.type = _descriptor.FieldDescriptor.TYPE_STRING

_header_value_option = _base_proto.message_type.add()
_header_value_option.name = "HeaderValueOption"
field = _header_value_option.field.add()
field.name = "header"
field.number = 1
field.label = _descriptor.FieldDescriptor.LABEL_OPTIONAL
field.type = _descriptor.FieldDescriptor.TYPE_MESSAGE
field.type_name = ".envoy.config.core.v3.HeaderValue"

_add_file_descriptor(_base_proto)

_ext_auth_proto = descriptor_pb2.FileDescriptorProto()
_ext_auth_proto.name = "envoy/service/auth/v3/external_auth.proto"
_ext_auth_proto.package = "envoy.service.auth.v3"
_ext_auth_proto.syntax = "proto3"
_ext_auth_proto.dependency.extend(
    [
        "google/rpc/status.proto",
        "google/rpc/context/attribute_context.proto",
        "envoy/type/v3/http_status.proto",
        "envoy/config/core/v3/base.proto",
    ]
)

_check_request = _ext_auth_proto.message_type.add()
_check_request.name = "CheckRequest"
field = _check_request.field.add()
field.name = "attributes"
field.number = 1
field.label = _descriptor.FieldDescriptor.LABEL_OPTIONAL
field.type = _descriptor.FieldDescriptor.TYPE_MESSAGE
field.type_name = ".google.rpc.context.AttributeContext"

_denied_http = _ext_auth_proto.message_type.add()
_denied_http.name = "DeniedHttpResponse"
field = _denied_http.field.add()
field.name = "status"
field.number = 1
field.label = _descriptor.FieldDescriptor.LABEL_OPTIONAL
field.type = _descriptor.FieldDescriptor.TYPE_MESSAGE
field.type_name = ".envoy.type.v3.HttpStatus"
field = _denied_http.field.add()
field.name = "headers"
field.number = 2
field.label = _descriptor.FieldDescriptor.LABEL_REPEATED
field.type = _descriptor.FieldDescriptor.TYPE_MESSAGE
field.type_name = ".envoy.config.core.v3.HeaderValueOption"
field = _denied_http.field.add()
field.name = "body"
field.number = 3
field.label = _descriptor.FieldDescriptor.LABEL_OPTIONAL
field.type = _descriptor.FieldDescriptor.TYPE_STRING

_ok_http = _ext_auth_proto.message_type.add()
_ok_http.name = "OkHttpResponse"
field = _ok_http.field.add()
field.name = "headers"
field.number = 2
field.label = _descriptor.FieldDescriptor.LABEL_REPEATED
field.type = _descriptor.FieldDescriptor.TYPE_MESSAGE
field.type_name = ".envoy.config.core.v3.HeaderValueOption"

_check_response = _ext_auth_proto.message_type.add()
_check_response.name = "CheckResponse"
oneof_decl = _check_response.oneof_decl.add()
oneof_decl.name = "http_response"
field = _check_response.field.add()
field.name = "status"
field.number = 1
field.label = _descriptor.FieldDescriptor.LABEL_OPTIONAL
field.type = _descriptor.FieldDescriptor.TYPE_MESSAGE
field.type_name = ".google.rpc.Status"
field = _check_response.field.add()
field.name = "denied_response"
field.number = 2
field.label = _descriptor.FieldDescriptor.LABEL_OPTIONAL
field.type = _descriptor.FieldDescriptor.TYPE_MESSAGE
field.type_name = ".envoy.service.auth.v3.DeniedHttpResponse"
field.oneof_index = 0
field = _check_response.field.add()
field.name = "ok_response"
field.number = 3
field.label = _descriptor.FieldDescriptor.LABEL_OPTIONAL
field.type = _descriptor.FieldDescriptor.TYPE_MESSAGE
field.type_name = ".envoy.service.auth.v3.OkHttpResponse"
field.oneof_index = 0

_service = _ext_auth_proto.service.add()
_service.name = "Authorization"
_method = _service.method.add()
_method.name = "Check"
_method.input_type = ".envoy.service.auth.v3.CheckRequest"
_method.output_type = ".envoy.service.auth.v3.CheckResponse"

DESCRIPTOR = _add_file_descriptor(_ext_auth_proto)

StatusCode = _pool.FindEnumTypeByName("envoy.type.v3.StatusCode")

CheckRequest = _reflection.GeneratedProtocolMessageType(
    "CheckRequest",
    (_message.Message,),
    {
        "DESCRIPTOR": DESCRIPTOR.message_types_by_name["CheckRequest"],
        "__module__": "api.envoy_ext_auth_pb2",
    },
)
_sym_db.RegisterMessage(CheckRequest)

DeniedHttpResponse = _reflection.GeneratedProtocolMessageType(
    "DeniedHttpResponse",
    (_message.Message,),
    {
        "DESCRIPTOR": DESCRIPTOR.message_types_by_name["DeniedHttpResponse"],
        "__module__": "api.envoy_ext_auth_pb2",
    },
)
_sym_db.RegisterMessage(DeniedHttpResponse)

OkHttpResponse = _reflection.GeneratedProtocolMessageType(
    "OkHttpResponse",
    (_message.Message,),
    {
        "DESCRIPTOR": DESCRIPTOR.message_types_by_name["OkHttpResponse"],
        "__module__": "api.envoy_ext_auth_pb2",
    },
)
_sym_db.RegisterMessage(OkHttpResponse)

CheckResponse = _reflection.GeneratedProtocolMessageType(
    "CheckResponse",
    (_message.Message,),
    {
        "DESCRIPTOR": DESCRIPTOR.message_types_by_name["CheckResponse"],
        "__module__": "api.envoy_ext_auth_pb2",
    },
)
_sym_db.RegisterMessage(CheckResponse)

_HTTP_STATUS_DESCRIPTOR = _pool.FindMessageTypeByName("envoy.type.v3.HttpStatus")
HttpStatus = _reflection.GeneratedProtocolMessageType(
    "HttpStatus",
    (_message.Message,),
    {
        "DESCRIPTOR": _HTTP_STATUS_DESCRIPTOR,
        "__module__": "api.envoy_ext_auth_pb2",
    },
)
_sym_db.RegisterMessage(HttpStatus)
