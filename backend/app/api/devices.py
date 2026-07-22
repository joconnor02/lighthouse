"""Device endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.core.auth import require_token
from app.db.models import Device, Port
from app.db.session import get_db

from app.api.schemas import DeviceDetail, DeviceOut


router = APIRouter(prefix="/devices", tags=["devices"], dependencies=[Depends(require_token)])


def _current_open_port_count(db: Session, device: Device) -> int:
    """Open ports on the device's latest scan only (not historical open rows)."""
    if device.scan_id is None:
        return 0
    return (
        db.scalar(
            select(func.count(Port.id)).where(
                Port.device_id == device.id,
                Port.state == "open",
                Port.scan_id == device.scan_id,
            )
        )
        or 0
    )


@router.get("", response_model=list[DeviceOut])
def list_devices(db: Session = Depends(get_db)) -> list[dict]:
    rows = db.query(Device).order_by(desc(Device.last_seen)).all()
    out = []
    for d in rows:
        out.append(
            {
                "id": d.id,
                "ip": d.ip,
                "mac": d.mac,
                "hostname": d.hostname,
                "vendor": d.vendor,
                "os_guess": d.os_guess,
                "first_seen": d.first_seen,
                "last_seen": d.last_seen,
                "open_port_count": _current_open_port_count(db, d),
            }
        )
    return out


@router.get("/{device_id}", response_model=DeviceDetail)
def get_device(device_id: int, db: Session = Depends(get_db)) -> dict:
    d = db.get(Device, device_id)
    if d is None:
        raise HTTPException(status_code=404, detail="Device not found")
    ports = (
        db.query(Port)
        .where(Port.device_id == d.id)
        .order_by(desc(Port.last_seen))
        .all()
    )
    return {
        "id": d.id,
        "ip": d.ip,
        "mac": d.mac,
        "hostname": d.hostname,
        "vendor": d.vendor,
        "os_guess": d.os_guess,
        "first_seen": d.first_seen,
        "last_seen": d.last_seen,
        "open_port_count": _current_open_port_count(db, d),
        "ports": ports,
        "scan_id": d.scan_id,
    }
