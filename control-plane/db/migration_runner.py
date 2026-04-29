"""Database migration runner for Gavel OS."""

import asyncio
import logging
import os
import re
from pathlib import Path
from typing import Optional

import asyncpg

logger = logging.getLogger("sentinel.migration")


class MigrationRunner:
    """Executes database migrations in order."""

    def __init__(self, db_url: str, migrations_dir: str = "control-plane/db/migrations"):
        """Initialize migration runner.

        Args:
            db_url: PostgreSQL connection URL
            migrations_dir: Directory containing migration files
        """
        self.db_url = db_url
        self.migrations_dir = Path(migrations_dir)
        self.conn: Optional[asyncpg.Connection] = None

    async def connect(self):
        """Connect to database."""
        self.conn = await asyncpg.connect(self.db_url)
        logger.info(f"Connected to database: {self.db_url}")

    async def disconnect(self):
        """Disconnect from database."""
        if self.conn:
            await self.conn.close()
            logger.info("Disconnected from database")

    async def _ensure_schema_version_table(self):
        """Ensure schema_version table exists."""
        await self.conn.execute("""
            CREATE TABLE IF NOT EXISTS schema_version (
                version INT PRIMARY KEY,
                applied_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
                description TEXT
            )
        """)
        logger.debug("Schema version table ensured")

    async def _get_applied_versions(self) -> set[int]:
        """Get set of applied migration versions."""
        rows = await self.conn.fetch("SELECT version FROM schema_version ORDER BY version")
        return {row["version"] for row in rows}

    async def _get_migration_files(self) -> list[tuple[int, Path]]:
        """Get migration files sorted by version number.

        Returns:
            List of (version, path) tuples sorted by version
        """
        if not self.migrations_dir.exists():
            logger.warning(f"Migrations directory not found: {self.migrations_dir}")
            return []

        migrations = []
        for file_path in sorted(self.migrations_dir.glob("*.sql")):
            # Extract version from filename (e.g., 001_core_schema.sql -> 1)
            match = re.match(r"(\d+)_", file_path.name)
            if match:
                version = int(match.group(1))
                migrations.append((version, file_path))

        return migrations

    async def run(self) -> int:
        """Run all pending migrations.

        Returns:
            Number of migrations applied
        """
        try:
            await self.connect()
            await self._ensure_schema_version_table()

            applied = await self._get_applied_versions()
            migrations = await self._get_migration_files()

            count = 0
            for version, path in migrations:
                if version in applied:
                    logger.info(f"Migration {version} already applied")
                    continue

                logger.info(f"Applying migration {version}: {path.name}")
                try:
                    sql = path.read_text()
                    await self.conn.execute(sql)

                    # Record migration
                    description = path.stem.replace(f"{version:03d}_", "")
                    await self.conn.execute(
                        "INSERT INTO schema_version (version, description) VALUES ($1, $2)",
                        version,
                        description,
                    )
                    logger.info(f"Migration {version} applied successfully")
                    count += 1
                except Exception as e:
                    logger.error(f"Failed to apply migration {version}: {e}")
                    raise

            logger.info(f"Applied {count} migrations")
            return count

        finally:
            await self.disconnect()

    async def status(self) -> dict:
        """Get migration status.

        Returns:
            Dict with applied versions and pending migrations
        """
        try:
            await self.connect()
            await self._ensure_schema_version_table()

            applied = await self._get_applied_versions()
            migrations = await self._get_migration_files()

            pending = [
                (version, path.name)
                for version, path in migrations
                if version not in applied
            ]

            return {
                "applied": sorted(applied),
                "pending": pending,
                "total": len(migrations),
            }

        finally:
            await self.disconnect()


async def main():
    """CLI entry point for migrations."""
    import argparse

    parser = argparse.ArgumentParser(description="Gavel OS Database Migrations")
    parser.add_argument(
        "--action",
        choices=["run", "status"],
        default="run",
        help="Migration action",
    )
    parser.add_argument(
        "--db-url",
        default=os.getenv("DATABASE_URL", "postgresql://user:password@localhost:5432/gavel"),
        help="Database URL",
    )
    parser.add_argument(
        "--migrations-dir",
        default="control-plane/db/migrations",
        help="Migrations directory",
    )

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    runner = MigrationRunner(args.db_url, args.migrations_dir)

    if args.action == "status":
        status = await runner.status()
        print("\nMigration Status:")
        print(f"  Applied: {status['applied']}")
        print(f"  Pending: {status['pending']}")
        print(f"  Total: {status['total']}\n")

    elif args.action == "run":
        count = await runner.run()
        print(f"\nApplied {count} migrations\n")


if __name__ == "__main__":
    asyncio.run(main())
