"""Scan endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.core.auth import require_token
from app.core.scanner import enqueue_scan, validate_target, validate_port_range
from app.db.models import Alert, Device, Port, Scan
from app.db.session import get_db

from app.api.schemas import ScanCreate, ScanDetail, ScanOut


router = APIRouter(prefix="/scans", tags=["scans"], dependencies=[Depends(require_token)])


@router.post("", response_model=ScanOut, status_code=status.HTTP_201_CREATED)
def create_scan(payload: ScanCreate, db: Session = Depends(get_db)) -> Scan:
    try:
        target = validate_target(payload.target)
        port_range = validate_port_range(payload.port_range)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e

    scan = Scan(target_cidr=target, scan_type=payload.scan_type, port_range=port_range, status="pending")
    db.add(scan)
    db.commit()
    db.refresh(scan)
    enqueue_scan(scan.id)
    return scan


@router.get("", response_model=list[ScanOut])
def list_scans(limit: int = 50, db: Session = Depends(get_db)) -> list[dict]:
    rows = db.query(Scan).order_by(desc(Scan.id)).limit(limit).all()
    out = []
    for s in rows:
        device_count = db.scalar(
            select(func.count(Device.id)).where(Device.scan_id == s.id)
        ) or 0
        alert_count = db.scalar(
            select(func.count(Alert.id)).where(Alert.scan_id == s.id)
        ) or 0
        out.append(
            {
                "id": s.id,
                "started_at": s.started_at,
                "finished_at": s.finished_at,
                "target_cidr": s.target_cidr,
                "scan_type": s.scan_type,
                "port_range": s.port_range,
                "status": s.status,
                "error": s.error,
                "device_count": device_count,
                "alert_count": alert_count,
            }
        )
    return out


@router.get("/{scan_id}", response_model=ScanDetail)
def get_scan(scan_id: int, db: Session = Depends(get_db)) -> dict:
    s = db.get(Scan, scan_id)
    if s is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    device_count = db.scalar(select(func.count(Device.id)).where(Device.scan_id == s.id)) or 0
    alert_count = db.scalar(select(func.count(Alert.id)).where(Alert.scan_id == s.id)) or 0
    return {
        "id": s.id,
        "started_at": s.started_at,
        "finished_at": s.finished_at,
        "target_cidr": s.target_cidr,
        "scan_type": s.scan_type,
        "port_range": s.port_range,
        "status": s.status,
        "error": s.error,
        "device_count": device_count,
        "alert_count": alert_count,
        "nmap_xml_path": s.nmap_xml_path,
        "nmap_stdout": s.nmap_stdout,
    }
