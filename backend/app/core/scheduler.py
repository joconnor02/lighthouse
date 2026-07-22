"""APScheduler integration for automatic host discovery."""
from __future__ import annotations

import logging

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger

from app.db.models import Scan
from app.db.session import SessionLocal
from app.db.seed import get_setting
from app.core.scanner import enqueue_scan, validate_target


log = logging.getLogger(__name__)

_scheduler: BackgroundScheduler | None = None
DISCOVERY_JOB_ID = "host_discovery"


def enqueue_host_discovery() -> int | None:
    """Enqueue a fast host-discovery scan against default_cidr.

    Skips only when an identical fast discovery is already pending/running.
    Returns the new scan id, or None if skipped / invalid.
    """
    db = SessionLocal()
    try:
        target = get_setting(db, "default_cidr") or "192.168.1.0/24"
        try:
            target = validate_target(target)
        except ValueError as e:
            log.error("Host discovery skipped: %s", e)
            return None

        active = (
            db.query(Scan)
            .filter(
                Scan.status.in_(("pending", "running")),
                Scan.scan_type == "fast",
                Scan.target_cidr == target,
            )
            .first()
        )
        if active is not None:
            log.info(
                "Host discovery skipped: scan %s still %s for %s",
                active.id,
                active.status,
                target,
            )
            return None

        scan = Scan(
            target_cidr=target,
            scan_type="fast",
            port_range=None,
            status="pending",
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        enqueue_scan(scan.id)
        log.info("Host discovery scan %d enqueued for %s", scan.id, target)
        return scan.id
    finally:
        db.close()


def get_scheduler() -> BackgroundScheduler:
    global _scheduler
    if _scheduler is None:
        _scheduler = BackgroundScheduler(daemon=True)
        _scheduler.start()
    return _scheduler


def start_host_discovery_schedule() -> None:
    """Register always-on discovery every 5 minutes."""
    sched = get_scheduler()
    sched.add_job(
        enqueue_host_discovery,
        trigger=IntervalTrigger(minutes=5),
        id=DISCOVERY_JOB_ID,
        replace_existing=True,
    )
    log.info("Host discovery scheduled every 5 minutes")


def shutdown() -> None:
    global _scheduler
    if _scheduler is not None:
        _scheduler.shutdown(wait=False)
        _scheduler = None
