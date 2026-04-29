"""Sample policy data for testing."""


class TestPolicies:
    """Sample OPA/Rego policies for testing."""

    # Sample authz policy (sentinel.api.authz.allow)
    AUTHZ_POLICY_ALLOW = """
    package sentinel.api.authz

    allow {
        input.identity.roles[_] == "admin"
    }

    allow {
        input.resource.public == true
    }
    """

    # Sample runtime policy (sentinel.runtime.policy.allow)
    RUNTIME_POLICY = """
    package sentinel.runtime.policy

    allow {
        input.runtime_os == "linux"
        input.method == "CONNECT"
        allowed_ips[input.action]
    }

    allowed_ips[ip] {
        ip := "93.184.216.34"
    }

    allow {
        input.agent_id == "trusted-agent"
    }
    """

    # Sample tool proposal policy (sentinel.tool.authz.allow)
    TOOL_POLICY = """
    package sentinel.tool.authz

    allow {
        input.operation == "read"
    }

    deny {
        input.operation == "delete"
        input.environment == "prod"
    }
    """


class TestData:
    """Sample test data."""

    SAMPLE_TENANTS = [
        {
            "id": "tenant-001",
            "name": "Test Tenant 1",
            "created_at": "2026-04-01T00:00:00Z",
        },
        {
            "id": "tenant-002",
            "name": "Test Tenant 2",
            "created_at": "2026-04-02T00:00:00Z",
        },
    ]

    SAMPLE_USERS = [
        {
            "id": "user-001",
            "tenant_id": "tenant-001",
            "email": "admin@test.local",
            "roles": ["admin"],
        },
        {
            "id": "user-002",
            "tenant_id": "tenant-001",
            "email": "viewer@test.local",
            "roles": ["viewer"],
        },
    ]

    SAMPLE_ESCALATION_APPROVERS = [
        {
            "tenant_id": "tenant-001",
            "user_id": "user-001",
            "approver_role": "security-lead",
        },
    ]
