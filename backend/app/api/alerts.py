"""Alert endpoints."""
from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.core.auth import require_token
from app.db.models import Alert
from app.db.session import get_db

from app.api.schemas import AlertOut


router = APIRouter(prefix="/alerts", tags=["alerts"], dependencies=[Depends(require_token)])


def _to_out(a: Alert) -> dict:
    return {
        "id": a.id,
        "scan_id": a.scan_id,
        "device_id": a.device_id,
        "kind": a.kind,
        "severity": a.severity,
        "detail": json.loads(a.detail_json or "{}"),
        "acknowledged": a.acknowledged,
        "created_at": a.created_at,
    }


@router.get("", response_model=list[AlertOut])
def list_alerts(
    acknowledged: bool | None = None,
    kind: str | None = None,
    limit: int = 200,
    db: Session = Depends(get_db),
) -> list[dict]:
    q = db.query(Alert)
    if acknowledged is not None:
        q = q.filter(Alert.acknowledged == acknowledged)
    if kind:
        q = q.filter(Alert.kind == kind)
    rows = q.order_by(desc(Alert.created_at)).limit(limit).all()
    return [_to_out(a) for a in rows]


@router.patch("/{alert_id}", response_model=AlertOut)
def acknowledge_alert(alert_id: int, db: Session = Depends(get_db)) -> dict:
    a = db.get(Alert, alert_id)
    if a is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    a.acknowledged = True
    db.commit()
    db.refresh(a)
    return _to_out(a)
