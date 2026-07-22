"""Unit tests for scanner validation and closed-port detection."""
from __future__ import annotations

import pytest

from app.core.scanner import (
    validate_port_range,
    validate_scan_type,
    validate_target,
    _persist_hosts,
)
from app.db.models import Alert, Device, Port, Scan


def test_validate_target_accepts_normal_values():
    assert validate_target("192.168.1.0/24") == "192.168.1.0/24"
    assert validate_target("10.0.0.1") == "10.0.0.1"
    assert validate_target("router.local") == "router.local"
    assert validate_target("my_host.local") == "my_host.local"


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "-oN/tmp/pwned",
        "-sV",
        "--privileged",
        "host;rm",
        "host$(id)",
        "192.168.1.0/24 -oN /tmp/x",
        "../../../etc/passwd",
    ],
)
def test_validate_target_rejects_injection(bad: str):
    with pytest.raises(ValueError):
        validate_target(bad)


def test_validate_scan_type():
    assert validate_scan_type("connect") == "connect"
    with pytest.raises(ValueError):
        validate_scan_type("nope")


def test_validate_port_range():
    assert validate_port_range("1-1024") == "1-1024"
    with pytest.raises(ValueError):
        validate_port_range("1-1024; id")


def test_closed_ports_detected_for_live_host(client):
    """Regression: closed ports must not rely on mutable Device.scan_id membership."""
    from app.db.session import SessionLocal

    db = SessionLocal()
    try:
        s1 = Scan(target_cidr="192.168.1.0/24", scan_type="connect", status="done", device_count=1)
        db.add(s1)
        db.flush()
        device = Device(scan_id=s1.id, ip="192.168.1.10", mac="aa:bb:cc:dd:ee:ff")
        db.add(device)
        db.flush()
        db.add(
            Port(
                device_id=device.id,
                scan_id=s1.id,
                port=22,
                protocol="tcp",
                state="open",
                service="ssh",
            )
        )
        db.add(
            Port(
                device_id=device.id,
                scan_id=s1.id,
                port=80,
                protocol="tcp",
                state="open",
                service="http",
            )
        )
        db.commit()

        s2 = Scan(target_cidr="192.168.1.0/24", scan_type="connect", status="running")
        db.add(s2)
        db.commit()
        db.refresh(s2)

        hosts = [
            {
                "ip": "192.168.1.10",
                "mac": "aa:bb:cc:dd:ee:ff",
                "hostname": None,
                "vendor": None,
                "os_guess": None,
                "ports": [
                    {
                        "port": 22,
                        "protocol": "tcp",
                        "state": "open",
                        "service": "ssh",
                        "version": None,
                    }
                ],
            }
        ]
        _persist_hosts(db, s2, hosts)
        s2.status = "done"
        s2.device_count = 1
        db.commit()

        alerts = db.query(Alert).filter(Alert.scan_id == s2.id).all()
        kinds = {a.kind for a in alerts}
        assert "port_closed" in kinds
        closed = [a for a in alerts if a.kind == "port_closed"]
        assert any('"port": 80' in a.detail_json for a in closed)
        assert not any('"port": 22' in a.detail_json and a.kind == "port_closed" for a in closed)
    finally:
        db.close()


def test_open_port_count_is_current_only(client):
    from app.db.session import SessionLocal

    db = SessionLocal()
    try:
        s1 = Scan(target_cidr="10.0.0.0/24", scan_type="connect", status="done", device_count=1)
        db.add(s1)
        db.flush()
        device = Device(scan_id=s1.id, ip="10.0.0.5", mac=None)
        db.add(device)
        db.flush()
        for port_num in (22, 80):
            db.add(
                Port(
                    device_id=device.id,
                    scan_id=s1.id,
                    port=port_num,
                    protocol="tcp",
                    state="open",
                )
            )
        db.commit()

        s2 = Scan(target_cidr="10.0.0.0/24", scan_type="connect", status="running")
        db.add(s2)
        db.commit()
        db.refresh(s2)

        hosts = [
            {
                "ip": "10.0.0.5",
                "mac": "",
                "hostname": None,
                "vendor": None,
                "os_guess": None,
                "ports": [
                    {
                        "port": 22,
                        "protocol": "tcp",
                        "state": "open",
                        "service": "ssh",
                        "version": None,
                    }
                ],
            }
        ]
        _persist_hosts(db, s2, hosts)
        s2.status = "done"
        s2.device_count = 1
        db.commit()
    finally:
        db.close()

    stats = client.get("/api/stats").json()
    assert stats["open_port_count"] == 1

    devices = client.get("/api/devices").json()
    assert len(devices) == 1
    assert devices[0]["open_port_count"] == 1

    ports = client.get("/api/ports").json()
    assert len(ports) == 1
    assert ports[0]["port"] == 22


def test_create_scan_rejects_bad_target_and_type(client):
    bad_target = client.post(
        "/api/scans",
        json={"target": "-oN/tmp/x", "scan_type": "fast"},
    )
    assert bad_target.status_code == 400

    bad_type = client.post(
        "/api/scans",
        json={"target": "192.168.0.0/24", "scan_type": "banana"},
    )
    assert bad_type.status_code == 400


def test_settings_reject_invalid_cron(client):
    res = client.put("/api/settings", json={"schedule_cron": "not a cron"})
    assert res.status_code == 400


def test_scan_device_count_persists(client):
    """device_count on older scans must not shrink when Device.scan_id moves."""
    from app.db.session import SessionLocal

    db = SessionLocal()
    try:
        s1 = Scan(target_cidr="172.16.0.0/24", scan_type="fast", status="done", device_count=3)
        db.add(s1)
        db.flush()
        # Only one device still pointing at s1 — would under-count if derived live.
        db.add(Device(scan_id=s1.id, ip="172.16.0.1"))
        db.commit()
        s1_id = s1.id
    finally:
        db.close()

    rows = client.get("/api/scans").json()
    match = next(r for r in rows if r["id"] == s1_id)
    assert match["device_count"] == 3


def test_fast_scan_does_not_wipe_ports_or_emit_closed(client):
    """Discovery-only scans must not redefine the open-port baseline."""
    from app.db.session import SessionLocal

    db = SessionLocal()
    try:
        s1 = Scan(target_cidr="192.168.9.0/24", scan_type="connect", status="done", device_count=1)
        db.add(s1)
        db.flush()
        device = Device(scan_id=s1.id, ip="192.168.9.10", mac="aa:bb:cc:dd:ee:01")
        db.add(device)
        db.flush()
        db.add(
            Port(
                device_id=device.id,
                scan_id=s1.id,
                port=22,
                protocol="tcp",
                state="open",
                service="ssh",
            )
        )
        db.commit()
        port_scan_id = s1.id

        s2 = Scan(target_cidr="192.168.9.0/24", scan_type="fast", status="running")
        db.add(s2)
        db.commit()
        db.refresh(s2)

        hosts = [
            {
                "ip": "192.168.9.10",
                "mac": "AA:BB:CC:DD:EE:01",  # mixed case — should normalize/match
                "hostname": None,
                "vendor": None,
                "os_guess": None,
                "ports": [],
            }
        ]
        _persist_hosts(db, s2, hosts)
        s2.status = "done"
        s2.device_count = 1
        db.commit()

        alerts = db.query(Alert).filter(Alert.scan_id == s2.id).all()
        assert not any(a.kind == "port_closed" for a in alerts)

        db.refresh(device)
        assert device.scan_id == port_scan_id  # port baseline unchanged
        assert device.mac == "aa:bb:cc:dd:ee:01"
    finally:
        db.close()

    stats = client.get("/api/stats").json()
    assert stats["open_port_count"] == 1
    devices = client.get("/api/devices").json()
    assert devices[0]["open_port_count"] == 1
