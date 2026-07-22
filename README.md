# Lighthouse

See what's on your local network — devices, open ports, and changes over time — from a simple dashboard in your browser.

Lighthouse runs entirely on your machine. It scans your LAN, remembers what it finds, and alerts you when something new shows up or when a previously open port disappears.

## Features

- **Find devices** on your network (phones, laptops, printers, IoT gadgets, and more)
- **See open ports and services** so you know what each device is exposing
- **Track history** across scans so trends and one-off appearances are visible
- **Get alerts** when new devices appear, new ports open, or ports close
- **Schedule recurring scans** so you don't have to remember to run them
- **Stay local** — no cloud account, no phone-home; data stays in a SQLite file on your machine

## Quick start

**Requirements:** Python 3.11+, Node.js 18+, and [nmap](https://nmap.org/) on your `PATH`.

```bash
# Install nmap if needed
# macOS:  brew install nmap
# Linux:  sudo apt install nmap

./dev.sh
```

That starts both the API and the web UI. Open **http://127.0.0.1:5173**.

On first launch, check the backend logs for an auth token (or set one in `backend/.env` — see below). Paste it into **Settings** in the UI. Host discovery starts automatically; open **Devices** (home) to scan individual hosts or scan all.

### Manual setup (optional)

If you prefer to run the pieces yourself:

```bash
# Backend
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
cp ../.env.example .env   # then edit LIGHTHOUSE_AUTH_TOKEN
alembic upgrade head
./run.sh                  # http://127.0.0.1:8000

# Frontend (separate terminal)
cd frontend
npm install
npm run dev               # http://127.0.0.1:5173
```

### Docker (optional)

```bash
docker compose up --build
```

The compose file grants network capabilities so deeper scan types can work inside the container.

## Using Lighthouse

1. Open the app — **Devices** is the home page. Host discovery runs on launch and every 5 minutes.
2. Use **Scan** on a row or **Scan all** for a thorough port scan (uses Settings scan type when it is connect/syn/intense; otherwise **intense**).
3. Watch per-host and scan-all progress bars; when scans finish, ports and alerts update.
4. Check **Alerts** for anything that changed since the last scan.
5. Optionally enable **deep scan on new device discovery** under **Settings**.

### Choosing a scan type

| Type | What it does | Privileges |
|------|----------------|------------|
| **fast** | Finds live hosts only (no port scan) — used by automatic discovery | None |
| **connect** | Scans TCP ports the normal way | None |
| **syn** | Faster SYN port scan | Root / elevated network capability |
| **intense** | Ports + service versions + OS guesses — default for Devices thorough actions | Root / elevated network capability |

Only scan networks you own or are explicitly allowed to scan.

## Security notes

- Bound to **localhost** by default — do not expose it on an untrusted network without auth and TLS.
- API calls require a bearer token (`LIGHTHOUSE_AUTH_TOKEN` in `.env`). The UI stores that token in your browser's localStorage via Settings.
- Prefer **connect** scans unless you intentionally need SYN/OS detection and understand the privilege trade-off.

## Configuration

Copy `.env.example` to `backend/.env` and adjust as needed:

| Variable | Purpose |
|----------|---------|
| `LIGHTHOUSE_AUTH_TOKEN` | Shared secret for the API / UI |
| `LIGHTHOUSE_BIND_HOST` | Listen address (default `127.0.0.1`) |
| `LIGHTHOUSE_BIND_PORT` | API port (default `8000`) |
| `LIGHTHOUSE_DB_PATH` | SQLite database path |

## Roadmap

Ideas for later versions (not in v0.1):

- Live traffic analysis (packet capture / flow visibility)
- CVE matching against detected service versions

## For contributors & agents

Architecture, API reference, and development details live in **[AGENTS.md](./AGENTS.md)**.
