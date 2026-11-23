"""Phase 1 Infrastructure Tests - Database and Server Startup."""

import asyncio
import os
import pytest
import sys

sys.path.insert(0, 'control-plane')

# Try importing testcontainers - gracefully skip if not available
try:
    import testcontainers.postgres
    HAS_TESTCONTAINERS = True
except ImportError:
    HAS_TESTCONTAINERS = False


@pytest.mark.integration
@pytest.mark.skipif(not HAS_TESTCONTAINERS, reason="testcontainers required")
class TestMigrationRunner:
    """Test database migration runner."""

    @pytest.fixture
    async def postgres_container(self):
        """Start a PostgreSQL container."""
        container = testcontainers.postgres.PostgresContainer("postgres:15")
        container.start()
        yield container
        container.stop()

    @pytest.mark.asyncio
    async def test_migration_runner_creates_tables(self, postgres_container):
        """Test that migration runner creates schema_migrations and audit_ledger tables."""
        from db.migration_runner import MigrationRunner

        db_url = str(postgres_container.get_connection_url()).replace(
            "postgresql+psycopg2://", "postgresql://"
        )

        runner = MigrationRunner(db_url)

        # Run migrations
        count = await runner.run()
        assert count >= 1, "Should apply at least migration 001"

        # Verify schema_migrations table exists
        # MigrationRunner disconnects on return; use an independent connection
        # to verify the actual persisted database state.
        import asyncpg
        conn = await asyncpg.connect(db_url)

        try:
            rows = await conn.fetch("SELECT version FROM schema_migrations")
            assert len(rows) >= 1, "Should have at least one applied migration"
            versions = [row["version"] for row in rows]
            assert 1 in versions, "Migration 1 should be applied"

            # Verify audit_ledger table exists
            result = await conn.fetchval(
                "SELECT EXISTS(SELECT 1 FROM information_schema.tables WHERE table_name='audit_ledger')"
            )
            assert result, "audit_ledger table should exist"

        finally:
            if conn:
                await conn.close()

    @pytest.mark.asyncio
    async def test_migration_status(self, postgres_container):
        """Test migration status command."""
        from db.migration_runner import MigrationRunner

        db_url = str(postgres_container.get_connection_url()).replace(
            "postgresql+psycopg2://", "postgresql://"
        )

        runner = MigrationRunner(db_url)

        status = await runner.status()
        assert "applied" in status
        assert "pending" in status
        assert "total" in status

    @pytest.mark.asyncio
    async def test_migration_idempotent(self, postgres_container):
        """Test that running migrations twice is idempotent."""
        from db.migration_runner import MigrationRunner

        db_url = str(postgres_container.get_connection_url()).replace(
            "postgresql+psycopg2://", "postgresql://"
        )

        runner = MigrationRunner(db_url)

        # Run migrations first time
        count1 = await runner.run()

        # Run migrations second time
        count2 = await runner.run()

        assert count2 == 0, "Second run should apply zero migrations"


@pytest.mark.integration
class TestNotificationService:
    """Test notification service backends."""

    def test_notification_service_initialization(self):
        """Test that notification service initializes with backends."""
        from service.notification_service import NotificationService

        service = NotificationService(
            enable_logging=True,
            enable_slack=False,
            enable_email=False,
        )

        assert len(service.backends) >= 1, "Should have at least logging backend"

    @pytest.mark.asyncio
    async def test_logging_backend_approval_required(self):
        """Test logging backend sends approval required notification."""
        from service.notification_service import (
            LoggingBackend,
            NotificationPayload,
            NotificationType,
        )
        from datetime import datetime, timezone

        backend = LoggingBackend()

        payload = NotificationPayload(
            notification_type=NotificationType.APPROVAL_REQUIRED,
            tenant_id="tenant-001",
            escalation_id="esc_abc123",
            ticket_number="ESC-tc_abc123",
            tool_call_id="tc_abc123",
            operation="transfer",
            agent_id="claude-code-1",
            deadline=datetime.now(timezone.utc),
            parameters={"amount": 50000},
        )

        result = await backend.send(payload)
        assert result is True, "Logging backend should always succeed"

    @pytest.mark.asyncio
    async def test_notification_service_send(self):
        """Test notification service sends to backends."""
        from service.notification_service import (
            NotificationService,
            NotificationPayload,
            NotificationType,
        )
        from datetime import datetime, timezone

        service = NotificationService(
            enable_logging=True,
            enable_slack=False,
            enable_email=False,
        )

        payload = NotificationPayload(
            notification_type=NotificationType.APPROVAL_REQUIRED,
            tenant_id="tenant-001",
            escalation_id="esc_abc123",
            ticket_number="ESC-tc_abc123",
            tool_call_id="tc_abc123",
            operation="transfer",
            agent_id="claude-code-1",
            deadline=datetime.now(timezone.utc),
            parameters={"amount": 50000},
        )

        result = await service.send(payload)
        assert result is True, "Service should send successfully"


@pytest.mark.integration
class TestMainApplicationStartup:
    """Test main FastAPI application can initialize."""

    def test_import_main_module(self):
        """Test that main module can be imported."""
        # This verifies all imports in main.py work
        import main

        assert main.app is not None, "FastAPI app should be created"
        assert main.app.title == "Gavel OS Control Plane"

    def test_main_has_routes(self):
        """Test that main application has expected routes."""
        import main

        # Get list of routes
        routes = [route.path for route in main.app.routes]

        expected_paths = ["/", "/ready", "/live", "/health", "/auth/token", "/auth/jwks"]
        for path in expected_paths:
            assert path in routes, f"Route {path} should exist"

    def test_main_has_middleware(self):
        """Test that main application has expected middleware."""
        import main

        # FastAPI middleware is accessed via app.user_middleware
        assert hasattr(main.app, 'user_middleware'), "Should have user_middleware"
        assert len(main.app.user_middleware) > 0, "Should have at least one middleware configured"

        # Check that middleware classes are in the stack
        middleware_types = [m.cls.__name__ for m in main.app.user_middleware]
        assert 'SecurityHeadersMiddleware' in middleware_types, "SecurityHeadersMiddleware should be configured"
        assert 'AuthMiddleware' in middleware_types, "AuthMiddleware should be configured"
