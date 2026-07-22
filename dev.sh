#!/usr/bin/env bash
# Launch Lighthouse backend + frontend together, stream their output with
# prefixed lines, and tear both down when this script exits (Ctrl-C or kill).
# On startup, reclaim backend/frontend ports left by a previous non-graceful exit.
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

# PIDs listening on a TCP port (macOS + Linux via lsof).
pids_on_port() {
  local port="$1"
  if ! command -v lsof >/dev/null 2>&1; then
    return 0
  fi
  # -n/-P: skip DNS/port name lookups (faster, quieter).
  lsof -nP -tiTCP:"$port" -sTCP:LISTEN 2>/dev/null || true
}

# Definitively test whether a TCP port can be bound on host:port.
# Catches live listeners that lsof misses (permissions, Docker proxy, system
# services). SO_REUSEADDR mirrors uvicorn/asyncio behavior, so TIME_WAIT
# sockets from a recent shutdown don't cause false positives — only an active
# listener will fail the bind.
port_is_bindable() {
  local host="$1" port="$2"
  python3 - "$host" "$port" <<'PY' 2>/dev/null
import socket, sys
host, port = sys.argv[1], int(sys.argv[2])
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    s.bind((host, port))
    s.close()
    sys.exit(0)
except OSError:
    sys.exit(1)
PY
}

# Signal a list of PIDs (and their process groups when possible).
signal_pids() {
  local sig="$1"
  shift
  local pid
  for pid in "$@"; do
    [[ -n "$pid" ]] || continue
    kill -"$sig" -"$pid" 2>/dev/null || kill -"$sig" "$pid" 2>/dev/null || true
  done
}

# Free a listen port left behind by a previous non-graceful exit
# (terminal closed, kill -9, crash). Safe no-op if the port is clear.
# Falls back to a bind test so a listener lsof can't see (Docker proxy,
# system service, different user) is still detected.
free_port() {
  local host="$1" port="$2" label="$3"
  local pids
  pids=$(pids_on_port "$port")
  # shellcheck disable=SC2086
  set -- $pids
  if [[ $# -gt 0 ]]; then
    log "port $port still in use (stale $label from a previous run); freeing..."
    signal_pids TERM "$@"
    sleep 1
    pids=$(pids_on_port "$port")
    # shellcheck disable=SC2086
    set -- $pids
    if [[ $# -gt 0 ]]; then
      signal_pids KILL "$@"
      sleep 0.3
    fi
  fi
  if [[ -n "$(pids_on_port "$port")" ]]; then
    err "could not free port $port — stop the process manually and retry"
    exit 1
  fi
  if ! port_is_bindable "$host" "$port"; then
    err "port $port is in use, but lsof found no process to stop."
    err "  it may be held by a Docker container, a launchd/system service,"
    err "  or a process owned by another user. Stop it manually and retry."
    exit 1
  fi
}

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

# Reclaim ports left by a previous non-graceful exit before we bind.
free_port "$BIND_HOST" "$BIND_PORT" "backend"
free_port "127.0.0.1" "$FRONTEND_PORT" "frontend"

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

# If the backend pipeline already exited, it failed to start (most likely the
# port was already in use). Don't lie about health — report and bail out so the
# user sees the real failure instead of a stale process on the same port.
if [[ -n "$BACKEND_PID" ]] && ! kill -0 "$BACKEND_PID" 2>/dev/null; then
  echo
  err "backend failed to start (exit). Common cause: port $BIND_PORT is already in use"
  err "  by a process lsof couldn't see (Docker, launchd, another user). See the"
  err "  [backend] stream above for the underlying error."
  exit 1
fi

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
# wait -n returns the exit code of whichever pipeline finished first, but not
# which one. Identify it so the message is actionable (a uvicorn bind failure
# exits 0, so we force a non-zero exit code to signal failure to the shell).
if [[ -n "$FRONTEND_PID" ]] && ! kill -0 "$FRONTEND_PID" 2>/dev/null; then
  err "frontend exited (code $EXIT_CODE); stopping backend..."
elif [[ -n "$BACKEND_PID" ]] && ! kill -0 "$BACKEND_PID" 2>/dev/null; then
  err "backend exited (code $EXIT_CODE); stopping frontend..."
  EXIT_CODE=1
else
  err "a service exited (code $EXIT_CODE); stopping the other..."
fi
exit "$EXIT_CODE"
