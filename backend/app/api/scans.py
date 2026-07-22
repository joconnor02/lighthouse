"""Scan endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.core.auth import require_token
from app.core.scanner import (
    enqueue_scan,
    resolve_thorough_scan_type,
    validate_port_range,
    validate_scan_type,
    validate_target,
)
from app.db.models import Alert, Device, Scan
from app.db.seed import get_setting
from app.db.session import get_db

from app.api.schemas import ScanAllCreate, ScanAllOut, ScanCreate, ScanDetail, ScanOut


router = APIRouter(prefix="/scans", tags=["scans"], dependencies=[Depends(require_token)])


def _scan_dict(s: Scan, alert_count: int) -> dict:
    return {
        "id": s.id,
        "started_at": s.started_at,
        "finished_at": s.finished_at,
        "target_cidr": s.target_cidr,
        "scan_type": s.scan_type,
        "port_range": s.port_range,
        "status": s.status,
        "error": s.error,
        "device_count": s.device_count or 0,
        "alert_count": alert_count,
        "progress_pct": float(s.progress_pct or 0),
    }


@router.post("", response_model=ScanOut, status_code=status.HTTP_201_CREATED)
def create_scan(payload: ScanCreate, db: Session = Depends(get_db)) -> Scan:
    try:
        target = validate_target(payload.target)
        port_range = validate_port_range(payload.port_range)
        scan_type = validate_scan_type(payload.scan_type)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e

    scan = Scan(
        target_cidr=target,
        scan_type=scan_type,
        port_range=port_range,
        status="pending",
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    enqueue_scan(scan.id)
    return scan


@router.post("/all", response_model=ScanAllOut, status_code=status.HTTP_201_CREATED)
def create_scans_for_all_devices(
    payload: ScanAllCreate | None = None,
    db: Session = Depends(get_db),
) -> dict:
    """Enqueue a thorough scan for every known device IP."""
    payload = payload or ScanAllCreate()
    settings_type = get_setting(db, "scan_type") or "intense"
    settings_ports = get_setting(db, "port_range") or "1-1024"

    try:
        if payload.scan_type:
            scan_type = validate_scan_type(payload.scan_type)
            if scan_type == "fast":
                raise ValueError("scan_type for scan-all must be a port scan (not fast)")
        else:
            scan_type = resolve_thorough_scan_type(settings_type)
        port_range = validate_port_range(
            payload.port_range if payload.port_range is not None else settings_ports
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e

    devices = (
        db.query(Device)
        .filter(Device.ip.isnot(None), Device.ip != "")
        .order_by(Device.ip)
        .all()
    )
    created: list[dict] = []
    skipped: list[str] = []

    for device in devices:
        try:
            target = validate_target(device.ip)
        except ValueError:
            skipped.append(device.ip)
            continue

        active = (
            db.query(Scan)
            .filter(
                Scan.target_cidr == target,
                Scan.status.in_(("pending", "running")),
            )
            .first()
        )
        if active is not None:
            skipped.append(target)
            continue

        scan = Scan(
            target_cidr=target,
            scan_type=scan_type,
            port_range=port_range,
            status="pending",
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        enqueue_scan(scan.id)
        created.append(_scan_dict(scan, 0))

    return {
        "scans": created,
        "skipped_targets": skipped,
        "scan_type": scan_type,
        "port_range": port_range,
    }


@router.get("", response_model=list[ScanOut])
def list_scans(limit: int = 50, db: Session = Depends(get_db)) -> list[dict]:
    rows = db.query(Scan).order_by(desc(Scan.id)).limit(limit).all()
    out = []
    for s in rows:
        alert_count = db.scalar(
            select(func.count(Alert.id)).where(Alert.scan_id == s.id)
        ) or 0
        out.append(_scan_dict(s, alert_count))
    return out


@router.get("/{scan_id}", response_model=ScanDetail)
def get_scan(scan_id: int, db: Session = Depends(get_db)) -> dict:
    s = db.get(Scan, scan_id)
    if s is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    alert_count = db.scalar(select(func.count(Alert.id)).where(Alert.scan_id == s.id)) or 0
    return {
        **_scan_dict(s, alert_count),
        "nmap_xml_path": s.nmap_xml_path,
        "nmap_stdout": s.nmap_stdout,
        "progress_log": s.progress_log or "",
    }
