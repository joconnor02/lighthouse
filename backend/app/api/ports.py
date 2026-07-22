"""Aggregate open-ports view."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.core.auth import require_token
from app.db.models import Device, Port
from app.db.session import get_db

from app.api.schemas import PortAggregate


router = APIRouter(prefix="/ports", tags=["ports"], dependencies=[Depends(require_token)])


@router.get("", response_model=list[PortAggregate])
def list_open_ports(db: Session = Depends(get_db)) -> list[dict]:
    rows = (
        db.query(Port, Device)
        .join(Device, Port.device_id == Device.id)
        .filter(Port.state == "open")
        .order_by(desc(Port.last_seen))
        .all()
    )
    out = []
    for port, device in rows:
        out.append(
            {
                "port": port.port,
                "protocol": port.protocol,
                "service": port.service,
                "version": port.version,
                "device_id": device.id,
                "ip": device.ip,
                "hostname": device.hostname,
                "last_seen": port.last_seen,
            }
        )
    return out
