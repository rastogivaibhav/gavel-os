"""IPv6 host policy remains explicit, normalized, and machine-readable."""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from api.control_plane import build_runtime_policy
from api.runtime_contract import RuntimeMode, RuntimeOS


def test_linux_runtime_policy_publishes_native_ipv6_literals():
    with patch("api.control_plane.control_plane_status_from_app", return_value="online"):
        with patch.dict(
            os.environ,
            {
                "GAVEL_RUNTIME_BLOCKED_IPV6": "2001:db8::1, fd00::42",
                "GAVEL_RUNTIME_BLOCKED_IPS": "",
                "GAVEL_RUNTIME_BLOCKED_TARGETS": "example.org",
                "GAVEL_RUNTIME_MONITORED_PIDS": "42",
            },
        ):
            response = build_runtime_policy(
                app=None,
                host_id="ipv6-test-host",
                runtime_os=RuntimeOS.LINUX,
                runtime_arch="amd64",
                runtime_mode=RuntimeMode.ENFORCE,
                enforcement_capable=True,
            )
    assert response.blocked_ipv6 == ["2001:db8::1", "fd00::42"]
    assert response.blocked_ipv4 == []
    assert response.blocked_targets == []
    assert response.reason_code == "POLICY_SYNC_READY"
    assert response.model_dump()["blocked_ipv6"] == ["2001:db8::1", "fd00::42"]


@pytest.mark.parametrize("invalid", ["not-ip", "::ffff:127.0.0.2", "127.0.0.2"])
def test_bad_ipv6_rule_aborts_policy_delivery(invalid):
    with patch("api.control_plane.control_plane_status_from_app", return_value="online"):
        with patch.dict(os.environ, {"GAVEL_RUNTIME_BLOCKED_IPV6": invalid}):
            with pytest.raises(ValueError, match="IPv6|IPv4-mapped"):
                build_runtime_policy(
                    app=None,
                    host_id="ipv6-test-host",
                    runtime_os=RuntimeOS.LINUX,
                    runtime_arch="amd64",
                    runtime_mode=RuntimeMode.ENFORCE,
                    enforcement_capable=True,
                )
