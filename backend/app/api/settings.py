"""Settings endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app import config as app_config
from app.core.auth import require_token
from app.core.scanner import PORT_OBSERVING_TYPES, _persist_lock, validate_port_range, validate_target
from app.db.models import Alert, Device, Port, Scan, Setting
from app.db.seed import DEFAULTS, get_setting, set_setting
from app.db.session import get_db

from app.api.schemas import SettingsOut, SettingsUpdate, WipeResult


router = APIRouter(prefix="/settings", tags=["settings"], dependencies=[Depends(require_token)])


def _settings_dict(db: Session) -> dict:
    scan_type = get_setting(db, "scan_type") or DEFAULTS["scan_type"]
    if scan_type not in PORT_OBSERVING_TYPES:
        scan_type = DEFAULTS["scan_type"]
    return {
        "default_cidr": get_setting(db, "default_cidr") or DEFAULTS["default_cidr"],
        "port_range": get_setting(db, "port_range") or DEFAULTS["port_range"],
        "scan_type": scan_type,
        "deep_scan_on_new_device": (get_setting(db, "deep_scan_on_new_device") or "false")
        .strip()
        .lower()
        in ("1", "true", "yes", "on"),
    }


@router.get("", response_model=SettingsOut)
def get_settings(db: Session = Depends(get_db)) -> dict:
    return _settings_dict(db)


@router.put("", response_model=SettingsOut)
def update_settings(payload: SettingsUpdate, db: Session = Depends(get_db)) -> dict:
    if payload.scan_type is not None and payload.scan_type not in PORT_OBSERVING_TYPES:
        raise HTTPException(
            status_code=400,
            detail="scan_type must be connect, syn, or intense (host discovery is always fast)",
        )

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

    if payload.default_cidr is not None:
        set_setting(db, "default_cidr", payload.default_cidr)
    if payload.port_range is not None:
        set_setting(db, "port_range", payload.port_range)
    if payload.scan_type is not None:
        set_setting(db, "scan_type", payload.scan_type)
    if payload.deep_scan_on_new_device is not None:
        set_setting(
            db,
            "deep_scan_on_new_device",
            "true" if payload.deep_scan_on_new_device else "false",
        )

    return _settings_dict(db)


@router.post("/wipe", response_model=WipeResult)
def wipe_database(db: Session = Depends(get_db)) -> WipeResult:
    """Delete all scan history (devices, ports, alerts, scans) and reset settings."""
    active = db.scalar(
        select(func.count())
        .select_from(Scan)
        .where(Scan.status.in_(("pending", "running")))
    )
    if active:
        raise HTTPException(
            status_code=409,
            detail="Cannot wipe while a scan is pending or running — wait for it to finish",
        )

    with _persist_lock:
        deleted = {
            "ports": db.execute(delete(Port)).rowcount or 0,
            "alerts": db.execute(delete(Alert)).rowcount or 0,
            "devices": db.execute(delete(Device)).rowcount or 0,
            "scans": db.execute(delete(Scan)).rowcount or 0,
            "settings": db.execute(delete(Setting)).rowcount or 0,
        }
        for key, value in DEFAULTS.items():
            db.add(Setting(key=key, value=value))
        db.commit()

    xml_dir = app_config.settings.xml_dir
    if xml_dir.is_dir():
        for path in xml_dir.glob("scan_*.xml"):
            try:
                path.unlink()
            except OSError:
                pass

    return WipeResult(ok=True, deleted=deleted)
