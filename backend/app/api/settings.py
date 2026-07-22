"""Settings endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.auth import require_token
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
    if payload.scan_type is not None and payload.scan_type not in {"fast", "connect", "syn", "intense"}:
        raise HTTPException(status_code=400, detail="Invalid scan_type")
    for field in ("default_cidr", "schedule_cron", "port_range", "scan_type"):
        value = getattr(payload, field)
        if value is not None:
            set_setting(db, field, value)

    # If the cron schedule changed, reschedule the job.
    if payload.schedule_cron is not None:
        refresh_schedule()

    return {k: (get_setting(db, k) or default) for k, default in DEFAULTS.items()}
