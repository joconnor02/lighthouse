"""Pydantic schemas for request/response."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class ScanCreate(BaseModel):
    target: str = Field(..., description="CIDR or IP to scan, e.g. 192.168.1.0/24")
    scan_type: str = Field("fast", description="fast | connect | syn | intense")
    port_range: str | None = Field(None, description="e.g. 1-1024 or 22,80,443")


class ScanAllCreate(BaseModel):
    scan_type: str | None = Field(
        None, description="connect | syn | intense (default: thorough from settings)"
    )
    port_range: str | None = Field(None, description="e.g. 1-1024 or 22,80,443")


class ScanOut(BaseModel):
    id: int
    started_at: datetime
    finished_at: datetime | None
    target_cidr: str
    scan_type: str
    port_range: str | None
    status: str
    error: str | None
    device_count: int = 0
    alert_count: int = 0
    progress_pct: float = 0.0

    class Config:
        from_attributes = True


class ScanDetail(ScanOut):
    nmap_xml_path: str | None
    nmap_stdout: str | None
    progress_log: str = ""


class ScanAllOut(BaseModel):
    scans: list[ScanOut]
    skipped_targets: list[str] = []
    scan_type: str
    port_range: str | None


class PortOut(BaseModel):
    id: int
    port: int
    protocol: str
    state: str
    service: str | None
    version: str | None
    first_seen: datetime
    last_seen: datetime
    scan_id: int | None

    class Config:
        from_attributes = True


class DeviceOut(BaseModel):
    id: int
    ip: str
    mac: str | None
    hostname: str | None
    vendor: str | None
    os_guess: str | None
    first_seen: datetime
    last_seen: datetime
    open_port_count: int = 0

    class Config:
        from_attributes = True


class DeviceDetail(DeviceOut):
    ports: list[PortOut] = []
    scan_id: int | None


class PortAggregate(BaseModel):
    port: int
    protocol: str
    service: str | None
    version: str | None
    device_id: int
    ip: str
    hostname: str | None
    last_seen: datetime


class AlertOut(BaseModel):
    id: int
    scan_id: int | None
    device_id: int | None
    kind: str
    severity: str
    detail: dict[str, Any]
    acknowledged: bool
    created_at: datetime

    class Config:
        from_attributes = True


class StatsOut(BaseModel):
    device_count: int
    open_port_count: int
    unack_alert_count: int
    last_scan_at: datetime | None
    last_scan_status: str | None


class SettingsOut(BaseModel):
    default_cidr: str
    port_range: str
    scan_type: str
    deep_scan_on_new_device: bool = False


class SettingsUpdate(BaseModel):
    default_cidr: str | None = None
    port_range: str | None = None
    scan_type: str | None = None
    deep_scan_on_new_device: bool | None = None
