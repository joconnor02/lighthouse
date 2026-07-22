# Lighthouse

A locally hosted, web-based network visibility tool. Lighthouse scans your LAN
for devices and open ports, stores results in SQLite, and surfaces a dashboard
with alerts when new devices appear, new ports open, or previously open ports
close.

## What it does

- **Device discovery** — uses `nmap` to find live hosts on a CIDR (ARP/ping).
- **Port & service detection** — TCP connect scans by default (no root needed);
  SYN, version, and OS detection scans available when run with privileges.
- **Persistent history** — every scan is stored in SQLite so you can see trends.
- **Alerts** — new devices, newly open ports, and closed ports are flagged.
- **Recurring scans** — optional cron schedule, run via APScheduler.
- **Dashboard** — React UI with stats, device table, port history, and alerts.

## Architecture

```
backend/   FastAPI + python-nmap + SQLAlchemy + APScheduler + SQLite
frontend/  React + Vite + TypeScript + Tailwind + TanStack Query + Recharts
```

The backend exposes `/api/*` endpoints and serves the scanner. The frontend is a
Vite dev server that proxies `/api` to the backend on `127.0.0.1:8000`.

## Prerequisites

- Python 3.11+
- Node.js 18+
- `nmap` installed and on your `PATH` (`brew install nmap`, `apt install nmap`, etc.)

## Setup

### Backend

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
cp ../.env.example .env   # then edit LIGHTHOUSE_AUTH_TOKEN
alembic upgrade head       # create SQLite schema
./run.sh                   # starts uvicorn on 127.0.0.1:8000
```

On first run, if you did not set `LIGHTHOUSE_AUTH_TOKEN`, the server will print
an auto-generated token to its logs. Copy it into the Settings page in the UI
(or set it in `.env` and restart).

### Frontend

```bash
cd frontend
npm install
npm run dev                # starts Vite on http://127.0.0.1:5173
```

Open http://127.0.0.1:5173, paste your auth token into Settings if auth is
enabled, then trigger a scan from the Dashboard.

## Scan types

| Type       | nmap flags        | Needs root | Notes                                   |
|------------|-------------------|------------|-----------------------------------------|
| `fast`     | `-sn -PE -PA...`  | no         | Host discovery only (no port scan)     |
| `connect`  | `-sT -T4`         | no         | TCP connect scan; safe default          |
| `syn`      | `-sS -T4`         | yes        | SYN scan; faster, needs `sudo`/`cap_net_raw` |
| `intense`  | `-sS -sV -O -A`   | yes        | Version + OS detection; slowest         |

To enable SYN/intense scans without running the whole server as root, grant the
`cap_net_raw` capability to the Python binary that runs uvicorn:

```bash
# Find the python binary inside your venv
sudo setcap cap_net_raw,cap_net_admin+eip backend/.venv/bin/python
```

## API

All endpoints under `/api` require a `Authorization: Bearer <token>` header
unless `LIGHTHOUSE_AUTH_DISABLED=true`.

| Method | Path                  | Description                          |
|--------|-----------------------|--------------------------------------|
| GET    | `/api/health`         | Liveness probe                       |
| GET    | `/api/stats`          | Dashboard summary counts             |
| POST   | `/api/scans`          | Start a scan (async)                |
| GET    | `/api/scans`          | List scans                          |
| GET    | `/api/scans/{id}`     | Scan detail (incl. raw nmap output) |
| GET    | `/api/devices`        | Latest device snapshot              |
| GET    | `/api/devices/{id}`   | Device detail + port history        |
| GET    | `/api/ports`          | All open ports (aggregate)          |
| GET    | `/api/alerts`         | Alert feed (filter by `acknowledged`, `kind`) |
| PATCH  | `/api/alerts/{id}`    | Acknowledge an alert                |
| GET    | `/api/settings`       | Read default settings               |
| PUT    | `/api/settings`       | Update settings (reschedules cron)  |

## Security & safety

- **Bind to localhost by default.** `run.sh` uses `LIGHTHOUSE_BIND_HOST=127.0.0.1`.
  Do not expose this on an untrusted network without enabling auth and TLS.
- **Auth.** All `/api` routes require a bearer token. Set
  `LIGHTHOUSE_AUTH_TOKEN` to a long random value in `.env`. The token is stored
  in the browser's localStorage on the Settings page.
- **No remote command execution.** Scan targets are validated against a strict
  regex (`[A-Za-z0-9._:\-/]+`) before being passed to `nmap` via python-nmap's
  API — never through a shell.
- **Authorization.** Only scan networks you own or are explicitly authorized
  to scan. Scanning networks you don't own may be illegal.
- **nmap privileges.** SYN and OS-detection scans need root or `cap_net_raw`.
  Prefer `connect` scans if you don't want to grant privileges.

## Development

```bash
# backend with auto-reload
cd backend && ./run.sh

# frontend with hot reload
cd frontend && npm run dev

# run tests (once added)
cd backend && pytest
```

## Optional: Docker

See `docker-compose.yml` for a one-command run of both services. Note that
nmap inside the container needs `NET_RAW` / `NET_ADMIN` capabilities to do
SYN/OS scans, which the compose file grants.

## Roadmap (out of scope for v0.1)

- CVE matching against detected service versions
- Live packet capture / flow analysis
- Multi-user auth and RBAC
- Email/webhook alert delivery
