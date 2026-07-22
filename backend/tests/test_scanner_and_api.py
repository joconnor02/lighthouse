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


def test_parse_progress_pct():
    from app.core.scanner import parse_progress_pct

    assert parse_progress_pct("SYN Stealth Scan Timing: About 12.34% done; ETC: 12:00") == 12.34
    assert parse_progress_pct("About 100% done") == 100.0
    assert parse_progress_pct("About 0.5% done") == 0.5
    assert parse_progress_pct("no percentage here") is None


def test_resolve_thorough_scan_type():
    from app.core.scanner import resolve_thorough_scan_type

    assert resolve_thorough_scan_type("fast") == "intense"
    assert resolve_thorough_scan_type(None) == "intense"
    assert resolve_thorough_scan_type("connect") == "connect"
    assert resolve_thorough_scan_type("syn") == "syn"
    assert resolve_thorough_scan_type("intense") == "intense"


def test_scan_all_enqueues_per_device(client):
    from app.db.session import SessionLocal

    db = SessionLocal()
    try:
        s0 = Scan(target_cidr="10.0.0.0/24", scan_type="fast", status="done", device_count=2)
        db.add(s0)
        db.flush()
        db.add(Device(scan_id=s0.id, ip="10.0.0.1", mac="aa:bb:cc:00:00:01"))
        db.add(Device(scan_id=s0.id, ip="10.0.0.2", mac="aa:bb:cc:00:00:02"))
        db.commit()
    finally:
        db.close()

    res = client.post("/api/scans/all", json={})
    assert res.status_code == 201
    body = res.json()
    assert body["scan_type"] == "intense"  # settings default thorough type
    assert len(body["scans"]) == 2
    targets = {s["target_cidr"] for s in body["scans"]}
    assert targets == {"10.0.0.1", "10.0.0.2"}
    assert all(s["progress_pct"] == 0 for s in body["scans"])

    # Second call should skip while pending/running (enqueue stubbed; still pending).
    res2 = client.post("/api/scans/all", json={"scan_type": "connect"})
    assert res2.status_code == 201
    body2 = res2.json()
    assert body2["scans"] == []
    assert set(body2["skipped_targets"]) == {"10.0.0.1", "10.0.0.2"}


def test_scan_all_rejects_fast_override(client):
    res = client.post("/api/scans/all", json={"scan_type": "fast"})
    assert res.status_code == 400


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


def test_settings_reject_invalid_scan_type_and_accept_deep_scan_flag(client):
    bad = client.put("/api/settings", json={"scan_type": "fast"})
    assert bad.status_code == 400

    res = client.put(
        "/api/settings",
        json={"deep_scan_on_new_device": True, "scan_type": "connect"},
    )
    assert res.status_code == 200
    body = res.json()
    assert body["deep_scan_on_new_device"] is True
    assert body["scan_type"] == "connect"
    assert "schedule_cron" not in body


def test_wipe_database_clears_data_and_resets_settings(client):
    from app.config import settings as app_settings
    from app.db.session import SessionLocal

    xml_dir = app_settings.xml_dir
    leftover = xml_dir / "scan_99.xml"
    leftover.write_text("<nmaprun/>")

    db = SessionLocal()
    try:
        scan = Scan(target_cidr="10.0.0.0/24", scan_type="connect", status="done", device_count=1)
        db.add(scan)
        db.flush()
        device = Device(scan_id=scan.id, ip="10.0.0.5", mac="11:22:33:44:55:66")
        db.add(device)
        db.flush()
        db.add(
            Port(
                device_id=device.id,
                scan_id=scan.id,
                port=443,
                protocol="tcp",
                state="open",
                service="https",
            )
        )
        db.add(
            Alert(
                kind="new_device",
                severity="info",
                detail_json="{}",
                scan_id=scan.id,
                device_id=device.id,
            )
        )
        db.commit()
    finally:
        db.close()

    client.put("/api/settings", json={"default_cidr": "10.0.0.0/24", "scan_type": "syn"})

    res = client.post("/api/settings/wipe")
    assert res.status_code == 200
    body = res.json()
    assert body["ok"] is True
    assert body["deleted"]["scans"] >= 1
    assert body["deleted"]["devices"] >= 1
    assert body["deleted"]["ports"] >= 1
    assert body["deleted"]["alerts"] >= 1

    assert client.get("/api/devices").json() == []
    assert client.get("/api/scans").json() == []
    assert client.get("/api/alerts").json() == []

    settings = client.get("/api/settings").json()
    assert settings["default_cidr"] == "192.168.1.0/24"
    assert settings["scan_type"] == "intense"
    assert settings["deep_scan_on_new_device"] is False
    assert not leftover.exists()


def test_wipe_database_rejects_when_scan_running(client):
    from app.db.session import SessionLocal

    db = SessionLocal()
    try:
        db.add(Scan(target_cidr="10.0.0.0/24", scan_type="fast", status="running"))
        db.commit()
    finally:
        db.close()

    res = client.post("/api/settings/wipe")
    assert res.status_code == 409
    assert client.get("/api/scans").json()  # still present


def test_enqueue_deep_scans_for_new_devices(client, monkeypatch):
    from app.core import scanner as scanner_mod
    from app.db.seed import set_setting
    from app.db.session import SessionLocal

    enqueued: list[int] = []
    monkeypatch.setattr(scanner_mod, "enqueue_scan", lambda scan_id: enqueued.append(scan_id))

    db = SessionLocal()
    try:
        set_setting(db, "deep_scan_on_new_device", "true")
        set_setting(db, "scan_type", "syn")
        set_setting(db, "port_range", "22,80")
    finally:
        db.close()

    scanner_mod._enqueue_deep_scans_for_new_devices(["10.9.9.1", "bad host"])
    assert len(enqueued) == 1

    db = SessionLocal()
    try:
        scan = db.get(Scan, enqueued[0])
        assert scan is not None
        assert scan.target_cidr == "10.9.9.1"
        assert scan.scan_type == "syn"
        assert scan.port_range == "22,80"
    finally:
        db.close()

    db = SessionLocal()
    try:
        set_setting(db, "deep_scan_on_new_device", "false")
    finally:
        db.close()
    before = len(enqueued)
    scanner_mod._enqueue_deep_scans_for_new_devices(["10.9.9.2"])
    assert len(enqueued) == before


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
