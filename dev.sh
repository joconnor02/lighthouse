#!/usr/bin/env bash
# Launch Lighthouse backend + frontend together, stream their output with
# prefixed lines, and tear both down when this script exits (Ctrl-C or kill).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND="$ROOT/backend"
FRONTEND="$ROOT/frontend"

BACKEND_PID=""
FRONTEND_PID=""

# --- helpers -----------------------------------------------------------------

log()  { printf '\033[90m[%s]\033[0m %s\n' "$(date +%H:%M:%S)" "$*"; }
err()  { printf '\033[91m[%s] ERROR:\033[0m %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
bold() { printf '\033[1m%s\033[0m' "$*"; }

cleanup() {
  echo
  log "shutting down..."
  local killed=0
  for pid in "$FRONTEND_PID" "$BACKEND_PID"; do
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
      # Kill the whole process group (negative PID) so child processes
      # (uvicorn reload worker, vite, esbuild) die too.
      kill -TERM -"$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true
      killed=1
    fi
  done
  if [[ "$killed" -eq 1 ]]; then
    sleep 1
    for pid in "$FRONTEND_PID" "$BACKEND_PID"; do
      if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
        kill -KILL -"$pid" 2>/dev/null || kill -KILL "$pid" 2>/dev/null || true
      fi
    done
  fi
  log "done."
}
trap cleanup EXIT INT TERM

# Prefix every line from a subprocess with a colored tag.
# Usage: prefix_stream <tag> <color_code>
prefix_stream() {
  local tag="$1" color="$2"
  local prefix
  prefix=$(printf '\033[%sm[%s]\033[0m' "$color" "$tag")
  # sed -u keeps output unbuffered on platforms that support it.
  sed -u "s/^/$prefix /" 2>/dev/null || sed "s/^/$prefix /"
}

# --- preflight ---------------------------------------------------------------

if ! command -v nmap >/dev/null 2>&1; then
  err "nmap not found. Install it first: brew install nmap  (or apt install nmap)"
  exit 1
fi

if [[ ! -d "$BACKEND/.venv" ]]; then
  log "creating backend venv..."
  python3 -m venv "$BACKEND/.venv"
  "$BACKEND/.venv/bin/pip" install --quiet --upgrade pip
  "$BACKEND/.venv/bin/pip" install --quiet -e "$BACKEND"
fi

if [[ ! -d "$FRONTEND/node_modules" ]]; then
  log "installing frontend dependencies..."
  (cd "$FRONTEND" && npm install --silent)
fi

# Ensure the SQLite schema is up to date (always — create_all won't add columns).
log "running alembic migration..."
(cd "$BACKEND" && .venv/bin/alembic upgrade head)

# Load .env if present so the backend sees LIGHTHOUSE_* vars.
if [[ -f "$BACKEND/.env" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "$BACKEND/.env"
  set +a
fi

BIND_HOST="${LIGHTHOUSE_BIND_HOST:-127.0.0.1}"
BIND_PORT="${LIGHTHOUSE_BIND_PORT:-8000}"
FRONTEND_PORT=5173

# --- launch ------------------------------------------------------------------

log "starting backend on http://$BIND_HOST:$BIND_PORT ..."
(
  cd "$BACKEND"
  exec .venv/bin/uvicorn app.main:app --host "$BIND_HOST" --port "$BIND_PORT" --reload
) 2>&1 | prefix_stream "backend" "36" &
BACKEND_PID=$!

log "starting frontend on http://127.0.0.1:$FRONTEND_PORT ..."
(
  cd "$FRONTEND"
  exec npm run dev -- --host 127.0.0.1 --port "$FRONTEND_PORT" --strictPort
) 2>&1 | prefix_stream "frontend" "35" &
FRONTEND_PID=$!

# Wait a moment for ports to come up, then probe health.
sleep 2
if curl -sf "http://$BIND_HOST:$BIND_PORT/api/health" >/dev/null 2>&1; then
  log "backend healthy"
else
  log "backend not responding yet (it may still be starting)"
fi

cat <<EOF

  $(bold 'Lighthouse is running.')

    frontend :  http://127.0.0.1:$FRONTEND_PORT
    backend  :  http://$BIND_HOST:$BIND_PORT/api

  $(printf '\033[90mPress Ctrl-C to stop both services.\033[0m')

EOF

# --- wait --------------------------------------------------------------------

# Wait for either child to exit; if one dies, bring down the other and quit.
wait -n "$BACKEND_PID" "$FRONTEND_PID" 2>/dev/null || true
EXIT_CODE=$?
echo
err "a service exited (code $EXIT_CODE); stopping the other..."
exit "$EXIT_CODE"
