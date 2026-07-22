#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
exec uvicorn app.main:app --host "${LIGHTHOUSE_BIND_HOST:-127.0.0.1}" --port "${LIGHTHOUSE_BIND_PORT:-8000}" --reload
