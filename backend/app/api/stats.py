"""Dashboard stats endpoint."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.core.auth import require_token
from app.db.models import Alert, Device, Port, Scan
from app.db.session import get_db

from app.api.schemas import StatsOut


router = APIRouter(prefix="/stats", tags=["stats"], dependencies=[Depends(require_token)])


@router.get("", response_model=StatsOut)
def get_stats(db: Session = Depends(get_db)) -> dict:
    device_count = db.scalar(select(func.count(Device.id))) or 0
    # Current open ports only: rows belonging to each device's latest scan.
    open_port_count = (
        db.scalar(
            select(func.count(Port.id))
            .select_from(Port)
            .join(Device, Port.device_id == Device.id)
            .where(Port.state == "open", Port.scan_id == Device.scan_id)
        )
        or 0
    )
    unack_alert_count = db.scalar(
        select(func.count(Alert.id)).where(Alert.acknowledged == False)  # noqa: E712
    ) or 0
    last_scan = db.query(Scan).order_by(desc(Scan.id)).first()
    return {
        "device_count": device_count,
        "open_port_count": open_port_count,
        "unack_alert_count": unack_alert_count,
        "last_scan_at": last_scan.started_at if last_scan else None,
        "last_scan_status": last_scan.status if last_scan else None,
    }
