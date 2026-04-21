#!/usr/bin/env bash
# migrate.sh — Apply all pending Gavel database migrations in order.
#
# Usage:
#   DATABASE_URL=postgres://user:pass@host:5432/gavel ./database/migrate.sh
#
# Requires: psql on PATH.

set -euo pipefail

DB_URL="${DATABASE_URL:-${POSTGRES_URL:-}}"

if [[ -z "$DB_URL" ]]; then
  echo "ERROR: DATABASE_URL or POSTGRES_URL must be set." >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/migrations"

if [[ ! -d "$SCRIPT_DIR" ]]; then
  echo "ERROR: migrations directory not found at $SCRIPT_DIR" >&2
  exit 1
fi

echo "Applying migrations from $SCRIPT_DIR"

# Ensure schema_migrations table exists (idempotent bootstrap)
psql "$DB_URL" -v ON_ERROR_STOP=1 -c "
CREATE TABLE IF NOT EXISTS schema_migrations (
    version     INTEGER PRIMARY KEY,
    description TEXT        NOT NULL,
    applied_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);" > /dev/null

APPLIED=0
for migration in "$SCRIPT_DIR"/*.sql; do
  version=$(basename "$migration" | grep -oE '^[0-9]+')
  already_applied=$(psql "$DB_URL" -t -c "SELECT COUNT(*) FROM schema_migrations WHERE version = $version;" | tr -d '[:space:]')

  if [[ "$already_applied" == "1" ]]; then
    echo "  [skip] $(basename "$migration") — already applied"
    continue
  fi

  echo "  [apply] $(basename "$migration")"
  psql "$DB_URL" -v ON_ERROR_STOP=1 -f "$migration"
  APPLIED=$((APPLIED + 1))
done

echo "Done. Applied $APPLIED migration(s)."
