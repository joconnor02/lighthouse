"""FastAPI application entrypoint."""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.core.scheduler import (
    enqueue_host_discovery,
    shutdown as scheduler_shutdown,
    start_host_discovery_schedule,
)
from app.core.scanner import recover_stale_scans, shutdown_executor
from app.db.session import init_db
from app.api import alerts, devices, ports, scans, settings as settings_router, stats


logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("lighthouse")


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    recover_stale_scans()
    start_host_discovery_schedule()
    if settings.discovery_on_startup:
        enqueue_host_discovery()
    if settings.auth_token.startswith("auto-"):
        log.warning(
            "Using auto-generated auth token (set LIGHTHOUSE_AUTH_TOKEN to fix): %s",
            settings.auth_token,
        )
    yield
    scheduler_shutdown()
    shutdown_executor()


app = FastAPI(
    title="Lighthouse",
    description="Local network visibility tool",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health", tags=["health"])
def health() -> dict:
    return {"status": "ok"}


app.include_router(scans.router, prefix="/api")
app.include_router(devices.router, prefix="/api")
app.include_router(ports.router, prefix="/api")
app.include_router(alerts.router, prefix="/api")
app.include_router(stats.router, prefix="/api")
app.include_router(settings_router.router, prefix="/api")
