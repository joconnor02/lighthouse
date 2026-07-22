"""SQLAlchemy ORM models."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    target_cidr: Mapped[str] = mapped_column(String(255), index=True)
    scan_type: Mapped[str] = mapped_column(String(32), default="fast")
    port_range: Mapped[str | None] = mapped_column(String(64), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="pending")  # pending|running|done|error
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    nmap_xml_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    nmap_stdout: Mapped[str | None] = mapped_column(Text, nullable=True)
    progress_log: Mapped[str] = mapped_column(Text, default="", nullable=False)
    # 0–100; updated from nmap --stats-every / -v timing lines while running.
    progress_pct: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    # Snapshot of hosts found when the scan finished (stable; not derived from Device.scan_id).
    device_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    devices: Mapped[list["Device"]] = relationship(
        back_populates="scan",
    )
    alerts: Mapped[list["Alert"]] = relationship(back_populates="scan")


class Device(Base):
    __tablename__ = "devices"
    __table_args__ = (UniqueConstraint("mac", "ip", name="uq_device_mac_ip"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int | None] = mapped_column(ForeignKey("scans.id", ondelete="SET NULL"), nullable=True, index=True)
    ip: Mapped[str] = mapped_column(String(64), index=True)
    mac: Mapped[str | None] = mapped_column(String(64), index=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    vendor: Mapped[str | None] = mapped_column(String(255), nullable=True)
    os_guess: Mapped[str | None] = mapped_column(String(255), nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    scan: Mapped[Scan | None] = relationship(back_populates="devices")
    ports: Mapped[list["Port"]] = relationship(
        back_populates="device", cascade="all, delete-orphan"
    )


class Port(Base):
    __tablename__ = "ports"
    __table_args__ = (
        UniqueConstraint("device_id", "port", "protocol", "scan_id", name="uq_port_per_scan"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    scan_id: Mapped[int | None] = mapped_column(ForeignKey("scans.id", ondelete="SET NULL"), nullable=True, index=True)
    port: Mapped[int] = mapped_column(Integer, index=True)
    protocol: Mapped[str] = mapped_column(String(16), default="tcp")
    state: Mapped[str] = mapped_column(String(32), default="open")
    service: Mapped[str | None] = mapped_column(String(128), nullable=True)
    version: Mapped[str | None] = mapped_column(String(255), nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    device: Mapped[Device] = relationship(back_populates="ports")


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int | None] = mapped_column(ForeignKey("scans.id", ondelete="SET NULL"), nullable=True, index=True)
    device_id: Mapped[int | None] = mapped_column(ForeignKey("devices.id", ondelete="SET NULL"), nullable=True, index=True)
    kind: Mapped[str] = mapped_column(String(32), index=True)  # new_device | new_port | port_closed
    severity: Mapped[str] = mapped_column(String(16), default="info")  # info | warn | critical
    detail_json: Mapped[str] = mapped_column(Text, default="{}")
    acknowledged: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    scan: Mapped[Scan | None] = relationship(back_populates="alerts")

    @property
    def detail(self) -> dict[str, Any]:
        return json.loads(self.detail_json or "{}")

    @detail.setter
    def detail(self, value: dict[str, Any]) -> None:
        self.detail_json = json.dumps(value)


class Setting(Base):
    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(Text, default="")
