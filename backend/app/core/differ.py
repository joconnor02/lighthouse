"""Compute diffs between scans and persist alerts."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from app.db.models import Alert, Device, Scan


@dataclass
class DiffResult:
    new_devices: list[Device] = field(default_factory=list)
    new_ports: list[tuple[Device, dict]] = field(default_factory=list)
    closed_ports: list[tuple[Device, dict]] = field(default_factory=list)
    alerts: list[Alert] = field(default_factory=list)


def compute_diff(
    db,
    scan: Scan,
    new_devices: list[Device],
    new_ports: list[tuple[Device, dict]],
    closed_ports: list[tuple[Device, dict]],
) -> DiffResult:
    result = DiffResult(new_devices=new_devices, new_ports=new_ports, closed_ports=closed_ports)

    for dev in new_devices:
        a = Alert(
            scan_id=scan.id,
            device_id=dev.id,
            kind="new_device",
            severity="warn",
            detail_json=json.dumps(
                {"ip": dev.ip, "mac": dev.mac, "hostname": dev.hostname, "vendor": dev.vendor}
            ),
        )
        db.add(a)
        result.alerts.append(a)

    for dev, p in new_ports:
        a = Alert(
            scan_id=scan.id,
            device_id=dev.id,
            kind="new_port",
            severity="warn",
            detail_json=json.dumps(
                {
                    "ip": dev.ip,
                    "mac": dev.mac,
                    "hostname": dev.hostname,
                    "port": p["port"],
                    "protocol": p["protocol"],
                    "service": p.get("service"),
                    "version": p.get("version"),
                }
            ),
        )
        db.add(a)
        result.alerts.append(a)

    for dev, p in closed_ports:
        a = Alert(
            scan_id=scan.id,
            device_id=dev.id,
            kind="port_closed",
            severity="info",
            detail_json=json.dumps(
                {
                    "ip": dev.ip,
                    "mac": dev.mac,
                    "hostname": dev.hostname,
                    "port": p["port"],
                    "protocol": p["protocol"],
                    "service": p.get("service"),
                }
            ),
        )
        db.add(a)
        result.alerts.append(a)

    return result


def persist_alerts(db, diff: DiffResult) -> None:
    # Alerts were added in compute_diff; just flush.
    db.flush()
