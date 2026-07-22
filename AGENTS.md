# Lighthouse — agent & developer notes

Technical reference for AI agents and contributors. User-facing setup and usage live in [README.md](./README.md).

## Project overview

Lighthouse is a locally hosted LAN visibility tool: nmap-based discovery + port scanning, SQLite persistence, FastAPI backend, React dashboard, optional APScheduler cron scans, and alerts on device/port diffs.

## Layout

```
backend/                 FastAPI app (Python 3.11+)
  app/
    main.py              App entry, CORS, lifespan (DB init + scheduler)
    config.py            pydantic-settings; env prefix LIGHTHOUSE_
    api/                 Route modules: scans, devices, ports, alerts, stats, settings
    api/schemas.py       Pydantic request/response models
    core/
      scanner.py         nmap invocation + scan_type → flags mapping
      differ.py          Diff scans → Alert rows (new_device, new_port, port_closed)
      scheduler.py       APScheduler cron refresh from settings
      auth.py            Bearer token dependency
    db/
      models.py          SQLAlchemy models (Scan, Device, Port, Alert, Setting)
      session.py         Engine / SessionLocal / init_db
      seed.py            Default settings seed
  alembic/               Migrations (0001_initial, 0002_add_progress_log)
  run.sh                 uvicorn with reload
frontend/                React + Vite + TypeScript + Tailwind
  src/
    api/client.ts        Fetch wrapper; Authorization from localStorage
    pages/               Dashboard, Devices, DeviceDetail, Scans, Alerts, Settings
    components/          ScanForm, DeviceTable, AlertRow, StatCard, PortBadge
    lib/time.ts          Display timezone helpers (America/New_York oriented)
dev.sh                   One-command local launch (venv, npm, alembic, both servers)
docker-compose.yml       Host-networked backend + frontend; NET_RAW/NET_ADMIN caps
.env.example             Template for backend/.env
```

Stack summary:

| Layer | Tech |
|-------|------|
| API | FastAPI, uvicorn, pydantic-settings |
| Scanner | python-nmap → system `nmap` |
| DB | SQLAlchemy 2.x + SQLite + Alembic |
| Jobs | APScheduler |
| UI | React 18, Vite 5, TanStack Query, React Router, Recharts, Tailwind |

## Runtime model

- Backend listens on `LIGHTHOUSE_BIND_HOST`:`LIGHTHOUSE_BIND_PORT` (default `127.0.0.1:8000`).
- Frontend Vite dev server on `127.0.0.1:5173`; proxies `/api` → backend.
- Scans are started asynchronously (`POST /api/scans` creates a row and runs nmap off the request path).
- After a scan, `differ.py` compares against prior state and writes alerts.
- Settings (`default_cidr`, `schedule_cron`, `port_range`, `scan_type`) live in the DB `settings` table; updating them refreshes the scheduler.

## Auth

- All `/api/*` routes except health require `Authorization: Bearer <token>` unless `LIGHTHOUSE_AUTH_DISABLED=true`.
- Token from `LIGHTHOUSE_AUTH_TOKEN`. If left as `change-me-please`, startup replaces it with an ephemeral `auto-…` value and logs it.
- Frontend stores the token in `localStorage` (Settings page).

## Scan types (`backend/app/core/scanner.py`)

| Type | nmap args | Root? | Notes |
|------|-----------|-------|-------|
| `fast` | `-sn -PE -PA80,443` | no | Host discovery only |
| `connect` | `-sT -T4` | no | Default TCP connect |
| `syn` | `-sS -T4` | yes | Needs root or `cap_net_raw` |
| `intense` | `-sS -sV -O -T4 -A` | yes | Version + OS detection |

Port range is appended for non-`fast` types when configured. Targets are validated as IP/CIDR/hostname (leading `-` rejected) and passed after `--` to nmap via subprocess (never a shell).

### Persistence / alert semantics

- `Device.scan_id` is a mutable “latest scan” pointer, not historical membership.
- `Scan.device_count` is snapshotted when a scan finishes — use it for history, don’t recompute from `Device.scan_id`.
- Open-port counts (`/api/stats`, `/api/devices`, `/api/ports`) only include `Port` rows where `Port.scan_id == Device.scan_id`.
- `port_closed` alerts compare previous `Port.scan_id == prev_scan.id` against hosts still present in the current scan (offline hosts do not generate port_closed).
- On startup, scans left `pending`/`running` are marked `error` (“Interrupted by server restart”).

To enable SYN/intense without running the whole server as root:

```bash
sudo setcap cap_net_raw,cap_net_admin+eip backend/.venv/bin/python
```

## API surface

Prefix `/api`. Bearer auth unless disabled.

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/health` | Liveness (no auth) |
| GET | `/api/stats` | Dashboard counts |
| POST | `/api/scans` | Start scan (async) |
| GET | `/api/scans` | List scans |
| GET | `/api/scans/{id}` | Detail incl. raw nmap / progress |
| GET | `/api/devices` | Latest device snapshot |
| GET | `/api/devices/{id}` | Device + port history |
| GET | `/api/ports` | Aggregate open ports |
| GET | `/api/alerts` | Alert feed (`acknowledged`, `kind` filters) |
| PATCH | `/api/alerts/{id}` | Acknowledge |
| GET | `/api/settings` | Read defaults |
| PUT | `/api/settings` | Update defaults; reschedules cron |

Routers are registered in `app/main.py`. Schemas live in `app/api/schemas.py`.

## Data model (SQLite)

- **Scan** — target CIDR, type, status (`pending|running|done|error`), nmap XML path, stdout, `progress_log`
- **Device** — ip/mac/hostname/vendor/os_guess, first/last seen; unique on `(mac, ip)`
- **Port** — per device/scan; unique on `(device_id, port, protocol, scan_id)`
- **Alert** — `kind`: `new_device` | `new_port` | `port_closed`; severity + JSON detail
- **Setting** — key/value app settings

DB path: `LIGHTHOUSE_DB_PATH` (relative paths resolve under `backend/`). Migrations via Alembic (`alembic upgrade head`).

## Environment variables

| Var | Default | Notes |
|-----|---------|-------|
| `LIGHTHOUSE_AUTH_TOKEN` | `change-me-please` → auto | Required for real installs |
| `LIGHTHOUSE_BIND_HOST` | `127.0.0.1` | |
| `LIGHTHOUSE_BIND_PORT` | `8000` | |
| `LIGHTHOUSE_DB_PATH` | `lighthouse.db` | |
| `LIGHTHOUSE_NMAP_XML_DIR` | `nmap_xml` | Raw XML storage |
| `LIGHTHOUSE_AUTH_DISABLED` | `false` | Local-only convenience |

Loaded from `backend/.env` via pydantic-settings (`env_prefix=LIGHTHOUSE_`).

## Local development

```bash
./dev.sh                          # preferred: both services + auto setup
cd backend && ./run.sh            # API only, reload
cd frontend && npm run dev        # UI only
cd backend && alembic upgrade head
cd backend && pytest              # when tests exist; optional deps: pip install -e '.[dev]'
```

Lint backend with ruff (`[tool.ruff]` in `pyproject.toml`, line length 100, py311).

Docker: `docker compose up --build` — both services use `network_mode: host`; backend gets `NET_RAW` / `NET_ADMIN`.

## Conventions for agents

- Prefer minimal, task-scoped diffs; do not drive-by refactor.
- Keep user docs in `README.md`; keep architecture/API/dev detail here.
- Do not weaken auth, target validation, or localhost-default binding without an explicit request.
- Only scan / automate against networks the operator is authorized to scan.
- Frontend timezone display helpers live in `frontend/src/lib/time.ts` — preserve consistent formatting when touching scan timestamps.
- Scan progress is stored on `Scan.progress_log` (migration `0002`); surface it rather than inventing a parallel channel.

## Out of scope (v0.1)

CVE matching, live capture, multi-user RBAC, email/webhook delivery — see README roadmap.
