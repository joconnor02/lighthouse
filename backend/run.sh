#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
# Keep existing DBs in sync (create_all alone does not add new columns).
./.venv/bin/alembic upgrade head 2>/dev/null || alembic upgrade head
exec uvicorn app.main:app --host "${LIGHTHOUSE_BIND_HOST:-127.0.0.1}" --port "${LIGHTHOUSE_BIND_PORT:-8000}" --reload --reload-dir app
