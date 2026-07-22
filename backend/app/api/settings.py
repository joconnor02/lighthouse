"""Settings endpoints."""
from __future__ import annotations

from apscheduler.triggers.cron import CronTrigger
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.auth import require_token
from app.core.scanner import VALID_SCAN_TYPES, validate_port_range, validate_target
from app.core.scheduler import refresh_schedule
from app.db.seed import DEFAULTS, get_setting, set_setting
from app.db.session import get_db

from app.api.schemas import SettingsOut, SettingsUpdate


router = APIRouter(prefix="/settings", tags=["settings"], dependencies=[Depends(require_token)])


@router.get("", response_model=SettingsOut)
def get_settings(db: Session = Depends(get_db)) -> dict:
    return {k: (get_setting(db, k) or default) for k, default in DEFAULTS.items()}


@router.put("", response_model=SettingsOut)
def update_settings(payload: SettingsUpdate, db: Session = Depends(get_db)) -> dict:
    if payload.scan_type is not None and payload.scan_type not in VALID_SCAN_TYPES:
        raise HTTPException(status_code=400, detail="Invalid scan_type")

    if payload.default_cidr is not None:
        try:
            validate_target(payload.default_cidr)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e

    if payload.port_range is not None and payload.port_range.strip():
        try:
            validate_port_range(payload.port_range)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e

    if payload.schedule_cron is not None and payload.schedule_cron.strip():
        try:
            CronTrigger.from_crontab(payload.schedule_cron.strip())
        except Exception as e:  # noqa: BLE001
            raise HTTPException(status_code=400, detail=f"Invalid cron: {e}") from e

    for field in ("default_cidr", "schedule_cron", "port_range", "scan_type"):
        value = getattr(payload, field)
        if value is not None:
            set_setting(db, field, value)

    if payload.schedule_cron is not None:
        refresh_schedule()

    return {k: (get_setting(db, k) or default) for k, default in DEFAULTS.items()}
