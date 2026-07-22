"""nmap wrapper that runs scans in a thread and persists results."""
from __future__ import annotations

import logging
import os
import re
import shlex
import shutil
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from app.config import settings
from app.db.models import Device, Port, Scan
from app.db.session import SessionLocal
from app.core.differ import DiffResult, compute_diff


log = logging.getLogger(__name__)

# Hostnames / IPv4 / IPv4-CIDR / IPv6. Reject leading dashes so nmap never treats
# the target as an extra flag (argv injection). Underscores allowed in host labels
# (common on LANs).
_TARGET_RE = re.compile(
    r"^(?:"
    r"(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?"
    r"|(?:[0-9A-Fa-f:]+)"
    r"|(?:[A-Za-z0-9_](?:[A-Za-z0-9_\-]{0,61}[A-Za-z0-9_])?"
    r"(?:\.[A-Za-z0-9_](?:[A-Za-z0-9_\-]{0,61}[A-Za-z0-9_])?)*)"
    r")$"
)
_PORT_RE = re.compile(r"^[0-9,\- ]+$")
# nmap --stats-every / -v timing lines, e.g. "About 12.34% done"
_PROGRESS_PCT_RE = re.compile(r"About\s+(\d+(?:\.\d+)?)%\s+done", re.IGNORECASE)

# Maps our scan_type -> nmap arguments. We avoid aggressive OS/SYN scans by
# default since those need root; users can opt in via settings.
SCAN_ARGS = {
    # Host discovery only: ICMP echo + TCP SYN/ACK probes (still -sn, no ports).
    "fast": "-sn -PE -PP -PS21,22,80,443,3389 -PA80,443,8080 -PR",
    "connect": "-sT -T4",  # TCP connect scan (no root needed)
    "syn": "-sS -T4",  # SYN scan (needs root)
    "intense": "-sS -sV -O -T4 -A",  # version + OS detection (needs root)
}
VALID_SCAN_TYPES = frozenset(SCAN_ARGS)
PORT_OBSERVING_TYPES = frozenset({"connect", "syn", "intense"})


def validate_target(target: str) -> str:
    target = target.strip()
    if not target or target.startswith("-") or not _TARGET_RE.match(target):
        raise ValueError(f"Invalid scan target: {target!r}")
    return target


def validate_port_range(port_range: str | None) -> str | None:
    if not port_range:
        return None
    pr = port_range.strip()
    if not _PORT_RE.match(pr):
        raise ValueError(f"Invalid port range: {port_range!r}")
    return pr or None


def validate_scan_type(scan_type: str) -> str:
    st = (scan_type or "").strip()
    if st not in VALID_SCAN_TYPES:
        raise ValueError(f"Invalid scan_type: {scan_type!r}")
    return st


def resolve_thorough_scan_type(settings_type: str | None) -> str:
    """Pick scan type for Devices thorough actions.

    Uses settings when port-observing; otherwise defaults to intense.
    """
    st = (settings_type or "").strip()
    if st in PORT_OBSERVING_TYPES:
        return st
    return "intense"


def parse_progress_pct(line: str) -> float | None:
    """Extract 0–100 progress from an nmap verbose/stats line, if present."""
    m = _PROGRESS_PCT_RE.search(line)
    if not m:
        return None
    try:
        pct = float(m.group(1))
    except ValueError:
        return None
    return max(0.0, min(100.0, pct))


def _nmap_arguments(scan_type: str, port_range: str | None) -> list[str]:
    """Build the nmap argument list (never a shell string) for a scan type."""
    base = SCAN_ARGS[scan_type]
    args = shlex.split(base)
    if port_range and scan_type != "fast":
        args += ["-p", port_range]
    return args


def _max_scan_workers() -> int:
    cpus = os.cpu_count() or 2
    return max(2, min(8, cpus + 2))


# Concurrent nmap processes; DB upserts serialized via _persist_lock (SQLite).
_executor = ThreadPoolExecutor(max_workers=_max_scan_workers())
_persist_lock = threading.Lock()


def _normalize_mac(mac: str | None) -> str:
    return (mac or "").strip().lower()


def _scan_observes_ports(scan: Scan) -> bool:
    """Host-discovery (fast) does not enumerate ports — must not redefine open set."""
    return scan.scan_type != "fast"


def shutdown_executor() -> None:
    """Stop accepting new scans (called on app shutdown)."""
    _executor.shutdown(wait=False, cancel_futures=True)


def recover_stale_scans() -> int:
    """Mark scans left pending/running after a crash/restart as error."""
    db = SessionLocal()
    try:
        stale = (
            db.query(Scan)
            .filter(Scan.status.in_(("pending", "running")))
            .all()
        )
        now = datetime.now(timezone.utc)
        for scan in stale:
            scan.status = "error"
            scan.error = "Interrupted by server restart"
            scan.finished_at = now
        if stale:
            db.commit()
            log.warning("Marked %d interrupted scan(s) as error", len(stale))
        return len(stale)
    finally:
        db.close()


def run_scan(scan_id: int) -> None:
    """Background entry point: load the Scan row, run nmap, persist results.

    Any unexpected exception sets the scan status to 'error' so the UI never
    sees a stuck 'running' state. The nmap child is always terminated.
    """
    db = SessionLocal()
    proc: subprocess.Popen | None = None
    try:
        scan = db.get(Scan, scan_id)
        if scan is None:
            log.error("Scan %s not found", scan_id)
            return
        scan.status = "running"
        db.commit()

        try:
            target = validate_target(scan.target_cidr)
            port_range = validate_port_range(scan.port_range)
            scan_type = validate_scan_type(scan.scan_type)
            args = _nmap_arguments(scan_type, port_range)

            nmap_bin = shutil.which("nmap")
            if not nmap_bin:
                _fail(db, scan, "nmap binary not found on PATH")
                return

            # Drive nmap as a subprocess so we can stream its verbose stats
            # output into progress_log. XML via -oX; stderr piped for progress.
            # "--" ensures the target can never be parsed as a flag.
            xml_path = settings.xml_dir / f"scan_{scan_id}.xml"
            cmd = [
                nmap_bin,
                *args,
                "-v",
                "--stats-every",
                "5s",
                "-oX",
                str(xml_path),
                "--",
                target,
            ]
            log.info("Running nmap against %s with args: %s", target, " ".join(cmd))

            try:
                proc = subprocess.Popen(  # noqa: S603 — controlled arg list, no shell
                    cmd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1,
                )
            except Exception as e:  # noqa: BLE001
                _fail(db, scan, f"nmap failed to start: {e}")
                log.exception("nmap failed to start")
                return

            assert proc.stderr is not None
            try:
                for line in proc.stderr:
                    scan.progress_log = (scan.progress_log or "") + line
                    pct = parse_progress_pct(line)
                    if pct is not None:
                        # Cap below 100 until the scan fully finishes.
                        scan.progress_pct = min(99.0, pct)
                    db.commit()
            finally:
                proc.stderr.close()
            proc.wait()

            if proc.returncode != 0:
                tail = " | ".join((scan.progress_log or "").strip().splitlines()[-5:])
                _fail(db, scan, f"nmap exited {proc.returncode}: {tail}".rstrip())
                log.error("nmap exited %s for scan %s", proc.returncode, scan_id)
                return

            try:
                import nmap  # python-nmap

                xml_text = xml_path.read_text()
                nm = nmap.PortScanner()
                nm.analyse_nmap_xml_scan(nmap_xml_output=xml_text)
            except Exception as e:  # noqa: BLE001
                _fail(db, scan, f"nmap xml parse failed: {e}")
                log.exception("Failed to parse nmap XML")
                return

            scan.nmap_xml_path = str(xml_path)

            try:
                csv_output = nm.csv() if callable(nm.csv) else (nm.csv or "")
            except Exception:
                csv_output = ""
            scan.nmap_stdout = csv_output or ""

            hosts = _extract_hosts(nm)
            try:
                new_ips: list[str] = []
                # Serialize upserts so parallel nmap workers don't race on SQLite.
                with _persist_lock:
                    diff = _persist_hosts(db, scan, hosts)
                    new_ips = [
                        (d.ip or "").strip()
                        for d in diff.new_devices
                        if (d.ip or "").strip()
                    ]
                    scan.status = "done"
                    scan.progress_pct = 100.0
                    scan.finished_at = datetime.now(timezone.utc)
                    scan.device_count = len(hosts)
                    db.commit()
                log.info("Scan %s done: %d hosts", scan_id, len(hosts))
                if scan.scan_type == "fast" and new_ips:
                    _enqueue_deep_scans_for_new_devices(new_ips)
            except Exception as e:  # noqa: BLE001
                # Roll back partial device/port/alert upserts before marking error.
                db.rollback()
                scan = db.get(Scan, scan_id)
                if scan is not None:
                    _fail(db, scan, f"persist failed: {e}")
                log.exception("Failed to persist scan %s", scan_id)
        except Exception as e:  # noqa: BLE001
            try:
                db.rollback()
                scan = db.get(Scan, scan_id)
                if scan is not None:
                    _fail(db, scan, f"scan failed: {e}")
            except Exception:  # noqa: BLE001
                log.exception("Failed to mark scan %s as error", scan_id)
            log.exception("Scan %s failed", scan_id)
    finally:
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except Exception:  # noqa: BLE001
                proc.kill()
        db.close()


def _fail(db, scan: Scan, message: str) -> None:
    scan.status = "error"
    scan.error = message
    scan.finished_at = datetime.now(timezone.utc)
    db.commit()


def _extract_hosts(nm) -> list[dict]:
    """Build a list of host dicts from a python-nmap PortScanner."""
    hosts: list[dict] = []
    for host_ip in nm.all_hosts():
        host = nm[host_ip]
        status = host.get("status", {}).get("state")
        if status != "up":
            continue
        addresses = host.get("addresses", {}) or {}
        ip = addresses.get("ipv4") or addresses.get("ipv6") or host_ip
        mac = addresses.get("mac")
        vendor = None
        vendors = host.get("vendor", {}) or {}
        if mac and mac in vendors:
            vendor = vendors[mac]
        hostnames = host.get("hostnames", []) or []
        hostname = None
        if hostnames:
            first = hostnames[0]
            if isinstance(first, dict):
                hostname = first.get("name")
            elif isinstance(first, str):
                hostname = first
        os_matches = host.get("osmatch", []) or []
        os_guess = os_matches[0].get("name") if os_matches else None

        ports = []
        for proto in ("tcp", "udp", "sctp"):
            proto_ports = host.get(proto, {}) or {}
            for port_str, info in proto_ports.items():
                try:
                    port_num = int(port_str)
                except (TypeError, ValueError):
                    continue
                ports.append(
                    {
                        "port": port_num,
                        "protocol": proto,
                        "state": info.get("state", "unknown"),
                        "service": info.get("name"),
                        "version": info.get("version"),
                    }
                )
        hosts.append(
            {
                "ip": ip,
                "mac": mac,
                "hostname": hostname,
                "vendor": vendor,
                "os_guess": os_guess,
                "ports": ports,
            }
        )
    return hosts


def _persist_hosts(db, scan: Scan, hosts: list[dict]) -> DiffResult:
    """Upsert devices/ports for this scan and generate alerts."""
    now = datetime.now(timezone.utc)
    new_devices: list[Device] = []
    new_ports: list[tuple[Device, dict]] = []
    observes_ports = _scan_observes_ports(scan)

    for h in hosts:
        mac = _normalize_mac(h.get("mac"))
        ip = (h.get("ip") or "").strip()
        if not ip and not mac:
            continue
        device = _find_device(db, mac, ip)
        if device is None:
            device = Device(
                scan_id=scan.id,
                ip=ip,
                mac=mac or None,
                hostname=h.get("hostname"),
                vendor=h.get("vendor"),
                os_guess=h.get("os_guess"),
                first_seen=now,
                last_seen=now,
            )
            db.add(device)
            db.flush()
            new_devices.append(device)
        else:
            # Discovery-only scans must not move the port baseline pointer.
            if observes_ports:
                device.scan_id = scan.id
            device.last_seen = now
            # Keep identity fresh across DHCP / newly-learned MAC.
            if ip:
                _claim_ip(db, device, ip)
            if mac:
                device.mac = mac
            if h.get("hostname"):
                device.hostname = h["hostname"]
            if h.get("vendor"):
                device.vendor = h["vendor"]
            if h.get("os_guess"):
                device.os_guess = h["os_guess"]

        if observes_ports:
            for p in h.get("ports", []):
                if p["state"] != "open":
                    continue
                existing = (
                    db.query(Port)
                    .filter(
                        Port.device_id == device.id,
                        Port.port == p["port"],
                        Port.protocol == p["protocol"],
                        Port.scan_id == scan.id,
                    )
                    .first()
                )
                if existing is None:
                    prior = (
                        db.query(Port)
                        .filter(
                            Port.device_id == device.id,
                            Port.port == p["port"],
                            Port.protocol == p["protocol"],
                            Port.scan_id != scan.id,
                        )
                        .first()
                    )
                    port = Port(
                        device_id=device.id,
                        scan_id=scan.id,
                        port=p["port"],
                        protocol=p["protocol"],
                        state="open",
                        service=p.get("service"),
                        version=p.get("version"),
                        first_seen=now,
                        last_seen=now,
                    )
                    db.add(port)
                    if prior is None:
                        new_ports.append((device, p))
                else:
                    existing.last_seen = now
                    if p.get("service"):
                        existing.service = p["service"]
                    if p.get("version"):
                        existing.version = p["version"]

    db.flush()
    closed_ports = _detect_closed_ports(db, scan, hosts) if observes_ports else []

    return compute_diff(db, scan, new_devices, new_ports, closed_ports)


def _claim_ip(db, device: Device, ip: str) -> None:
    """Assign IP to device; clear it from any other device (DHCP move)."""
    conflicts = (
        db.query(Device)
        .filter(Device.ip == ip, Device.id != device.id)
        .all()
    )
    for other in conflicts:
        other.ip = ""
    device.ip = ip


def _find_device(db, mac: str, ip: str):
    from sqlalchemy import func, or_

    if mac:
        row = db.query(Device).filter(func.lower(Device.mac) == mac).first()
        if row:
            return row
    if ip:
        row = db.query(Device).filter(
            Device.ip == ip,
            or_(Device.mac == None, Device.mac == ""),  # noqa: E711
        ).first()
        if row:
            return row
        # Sighting without MAC: still match a MAC-bearing row on the same IP.
        if not mac:
            row = db.query(Device).filter(Device.ip == ip).first()
            if row:
                return row
    return None


def _detect_closed_ports(
    db, scan: Scan, current_hosts: list[dict]
) -> list[tuple[Device, dict]]:
    """Find ports open on the previous *port* scan that are missing on live hosts now.

    Uses Port.scan_id for history — Device.scan_id is a mutable "latest port scan"
    pointer and cannot be used for membership in the previous scan.
    Skipped entirely for discovery-only scans (caller).
    """
    from sqlalchemy import desc

    prev_scan = (
        db.query(Scan)
        .filter(
            Scan.target_cidr == scan.target_cidr,
            Scan.id < scan.id,
            Scan.status == "done",
            Scan.scan_type != "fast",
        )
        .order_by(desc(Scan.id))
        .first()
    )
    if prev_scan is None:
        return []

    current_by_mac: dict[str, set[tuple[int, str]]] = {}
    current_by_ip: dict[str, set[tuple[int, str]]] = {}
    for h in current_hosts:
        open_set = {
            (p["port"], p["protocol"]) for p in h.get("ports", []) if p["state"] == "open"
        }
        mac = _normalize_mac(h.get("mac"))
        ip = (h.get("ip") or "").strip()
        if mac:
            current_by_mac[mac] = open_set
        if ip:
            current_by_ip[ip] = open_set

    prev_ports = (
        db.query(Port)
        .filter(Port.scan_id == prev_scan.id, Port.state == "open")
        .all()
    )

    closed: list[tuple[Device, dict]] = []
    seen: set[tuple[int, int, str]] = set()
    for port in prev_ports:
        device = db.get(Device, port.device_id)
        if device is None:
            continue

        cur_set: set[tuple[int, str]] | None = None
        if device.mac and device.mac.lower() in current_by_mac:
            cur_set = current_by_mac[device.mac.lower()]
        elif device.ip in current_by_ip:
            cur_set = current_by_ip[device.ip]
        else:
            # Host not present in this scan — skip (offline ≠ port closed).
            continue

        dedupe_key = (device.id, port.port, port.protocol)
        if dedupe_key in seen:
            continue
        if (port.port, port.protocol) not in cur_set:
            seen.add(dedupe_key)
            closed.append(
                (
                    device,
                    {
                        "port": port.port,
                        "protocol": port.protocol,
                        "service": port.service,
                    },
                )
            )
    return closed


def enqueue_scan(scan_id: int) -> None:
    _executor.submit(run_scan, scan_id)


def _enqueue_deep_scans_for_new_devices(ips: list[str]) -> None:
    """If enabled, queue thorough scans for newly discovered host IPs."""
    from app.db.seed import get_setting, setting_bool

    db = SessionLocal()
    try:
        if not setting_bool(db, "deep_scan_on_new_device"):
            return
        scan_type = resolve_thorough_scan_type(get_setting(db, "scan_type"))
        try:
            port_range = validate_port_range(get_setting(db, "port_range") or "1-1024")
        except ValueError as e:
            log.error("Deep scan on discovery skipped: %s", e)
            return

        for ip in ips:
            try:
                target = validate_target(ip)
            except ValueError:
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
                log.info(
                    "Deep scan skipped for %s: scan %s still %s",
                    target,
                    active.id,
                    active.status,
                )
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
            log.info(
                "Deep scan %d enqueued for newly discovered host %s (%s)",
                scan.id,
                target,
                scan_type,
            )
    finally:
        db.close()
