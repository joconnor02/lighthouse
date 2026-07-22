"""APScheduler integration for recurring scans."""
from __future__ import annotations

import logging
from typing import Any

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

from app.db.models import Scan
from app.db.session import SessionLocal
from app.db.seed import get_setting
from app.core.scanner import (
    enqueue_scan,
    validate_port_range,
    validate_scan_type,
    validate_target,
)


log = logging.getLogger(__name__)

_scheduler: BackgroundScheduler | None = None
JOB_ID = "recurring_scan"


def _run_scheduled_scan() -> None:
    db = SessionLocal()
    try:
        target = get_setting(db, "default_cidr") or "192.168.1.0/24"
        scan_type = get_setting(db, "scan_type") or "fast"
        port_range = get_setting(db, "port_range") or "1-1024"
        try:
            target = validate_target(target)
            port_range = validate_port_range(port_range)
            scan_type = validate_scan_type(scan_type)
        except ValueError as e:
            log.error("Scheduled scan skipped: %s", e)
            return
        # Don't pile on if a scan is already in flight.
        active = (
            db.query(Scan)
            .filter(Scan.status.in_(("pending", "running")))
            .first()
        )
        if active is not None:
            log.info("Scheduled scan skipped: scan %s still %s", active.id, active.status)
            return
        scan = Scan(target_cidr=target, scan_type=scan_type, port_range=port_range, status="pending")
        db.add(scan)
        db.commit()
        db.refresh(scan)
        enqueue_scan(scan.id)
        log.info("Scheduled scan %d enqueued for %s", scan.id, target)
    finally:
        db.close()


def get_scheduler() -> BackgroundScheduler:
    global _scheduler
    if _scheduler is None:
        _scheduler = BackgroundScheduler(daemon=True)
        _scheduler.start()
    return _scheduler


def refresh_schedule() -> None:
    """Re-read schedule_cron setting and reschedule the job."""
    db = SessionLocal()
    try:
        cron = (get_setting(db, "schedule_cron") or "").strip()
    finally:
        db.close()

    sched = get_scheduler()
    try:
        sched.remove_job(JOB_ID)
    except Exception:
        pass

    if not cron:
        log.info("Recurring scan disabled (no cron set)")
        return

    try:
        trigger = CronTrigger.from_crontab(cron)
    except Exception as e:  # noqa: BLE001
        log.error("Invalid cron %r: %s", cron, e)
        return

    sched.add_job(_run_scheduled_scan, trigger=trigger, id=JOB_ID, replace_existing=True)
    log.info("Recurring scan scheduled with cron %r", cron)


def shutdown() -> None:
    global _scheduler
    if _scheduler is not None:
        _scheduler.shutdown(wait=False)
        _scheduler = None
