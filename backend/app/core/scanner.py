"""nmap wrapper that runs scans in a thread and persists results."""
from __future__ import annotations

import logging
import re
import shlex
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from app.config import settings
from app.db.models import Device, Port, Scan
from app.db.session import SessionLocal
from app.core.differ import DiffResult, compute_diff


log = logging.getLogger(__name__)

# Validate a target: IPv4, IPv4 CIDR, IPv6, hostname. No shell metachars allowed.
_TARGET_RE = re.compile(r"^[A-Za-z0-9._:\-/]+$")
_PORT_RE = re.compile(r"^[0-9,\- ]+$")


def validate_target(target: str) -> str:
    target = target.strip()
    if not target or not _TARGET_RE.match(target):
        raise ValueError(f"Invalid scan target: {target!r}")
    return target


def validate_port_range(port_range: str | None) -> str | None:
    if not port_range:
        return None
    pr = port_range.strip()
    if not _PORT_RE.match(pr):
        raise ValueError(f"Invalid port range: {port_range!r}")
    return pr or None


# Maps our scan_type -> nmap arguments. We avoid aggressive OS/SYN scans by
# default since those need root; users can opt in via settings.
SCAN_ARGS = {
    "fast": "-sn -PE -PA80,443",   # host discovery only (ping + ARP)
    "connect": "-sT -T4",          # TCP connect scan (no root needed)
    "syn": "-sS -T4",              # SYN scan (needs root)
    "intense": "-sS -sV -O -T4 -A",  # version + OS detection (needs root)
}


def _nmap_arguments(scan_type: str, port_range: str | None) -> list[str]:
    """Build the nmap argument list (never a shell string) for a scan type.

    The flag logic and SCAN_ARGS values are unchanged; we just shlex-split the
    stored flag string into a list so it can be passed to subprocess without a
    shell. A `-p <range>` pair is appended for non-discovery scans when a port
    range is supplied.
    """
    base = SCAN_ARGS.get(scan_type, SCAN_ARGS["fast"])
    args = shlex.split(base)
    if port_range and scan_type != "fast":
        args += ["-p", port_range]
    return args


_executor = ThreadPoolExecutor(max_workers=2)


def run_scan(scan_id: int) -> None:
    """Background entry point: load the Scan row, run nmap, persist results.

    Any exception sets the scan status to 'error' so the UI never sees a stuck
    'running' state.
    """
    db = SessionLocal()
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
            args = _nmap_arguments(scan.scan_type, port_range)
        except ValueError as e:
            _fail(db, scan, str(e))
            return

        # Drive nmap as a subprocess so we can stream its verbose stats output
        # into progress_log while the scan runs. XML is written to a file via
        # -oX (so stdout is unused and we only pipe stderr, which avoids the
        # classic stdout-pipe-buffer deadlock); the XML file is then handed to
        # python-nmap for parsing. We never invoke a shell — args is a list.
        nmap_bin = shutil.which("nmap")
        if not nmap_bin:
            _fail(db, scan, "nmap binary not found on PATH")
            return

        xml_path = settings.xml_dir / f"scan_{scan_id}.xml"
        cmd = [nmap_bin, *args, "-v", "--stats-every", "5s", "-oX", str(xml_path), target]
        log.info("Running nmap against %s with args: %s", target, " ".join(cmd))

        try:
            proc = subprocess.Popen(  # noqa: S603 — args is a controlled list, no shell
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
                db.commit()
        finally:
            proc.stderr.close()
        proc.wait()

        if proc.returncode != 0:
            tail = " | ".join((scan.progress_log or "").strip().splitlines()[-5:])
            _fail(db, scan, f"nmap exited {proc.returncode}: {tail}".rstrip())
            log.error("nmap exited %s for scan %s", proc.returncode, scan_id)
            return

        # Parse the XML nmap wrote via -oX using python-nmap's XML parser, which
        # populates the PortScanner in place; nm.csv() then works as it does
        # after a normal scan.
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

        # Capture CSV for the UI's "raw output" panel.
        try:
            csv_output = nm.csv() if callable(nm.csv) else (nm.csv or "")
        except Exception:
            csv_output = ""
        scan.nmap_stdout = csv_output or ""

        hosts = _extract_hosts(nm)
        try:
            _persist_hosts(db, scan, hosts)
            scan.status = "done"
            scan.finished_at = datetime.now(timezone.utc)
            db.commit()
            log.info("Scan %s done: %d hosts", scan_id, len(hosts))
        except Exception as e:  # noqa: BLE001
            _fail(db, scan, f"persist failed: {e}")
            log.exception("Failed to persist scan results")
    finally:
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
        # python-nmap returns hostnames as a list of dicts like {"name": ..., "type": ...}
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
    from sqlalchemy import or_

    now = datetime.now(timezone.utc)
    new_devices: list[Device] = []
    new_ports: list[tuple[Device, dict]] = []

    for h in hosts:
        mac = h.get("mac") or ""
        ip = h.get("ip") or ""
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
            device.scan_id = scan.id
            device.last_seen = now
            if h.get("hostname") and not device.hostname:
                device.hostname = h["hostname"]
            if h.get("vendor") and not device.vendor:
                device.vendor = h["vendor"]
            if h.get("os_guess") and not device.os_guess:
                device.os_guess = h["os_guess"]

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
                if p.get("service") and not existing.service:
                    existing.service = p["service"]
                if p.get("version") and not existing.version:
                    existing.version = p["version"]

    db.flush()
    closed_ports = _detect_closed_ports(db, scan, hosts)

    diff = compute_diff(db, scan, new_devices, new_ports, closed_ports)
    return diff


def _find_device(db, mac: str, ip: str):
    from sqlalchemy import or_

    if mac:
        row = db.query(Device).filter(Device.mac == mac).first()
        if row:
            return row
    if ip:
        row = db.query(Device).filter(
            Device.ip == ip, or_(Device.mac == None, Device.mac == "")  # noqa: E711
        ).first()
        if row:
            return row
    return None


def _detect_closed_ports(db, scan: Scan, current_hosts: list[dict]) -> list[tuple[Device, dict]]:
    """Find ports open in the previous scan for the same target that are not open now."""
    from sqlalchemy import desc

    prev_scan = (
        db.query(Scan)
        .filter(Scan.target_cidr == scan.target_cidr, Scan.id < scan.id, Scan.status == "done")
        .order_by(desc(Scan.id))
        .first()
    )
    if prev_scan is None:
        return []

    current_open: dict[tuple[str, str], set[tuple[int, str]]] = {}
    for h in current_hosts:
        key = (h.get("mac") or "", h.get("ip") or "")
        current_open[key] = {
            (p["port"], p["protocol"]) for p in h.get("ports", []) if p["state"] == "open"
        }

    closed: list[tuple[Device, dict]] = []
    prev_devices = db.query(Device).filter(Device.scan_id == prev_scan.id).all()
    for dev in prev_devices:
        key = (dev.mac or "", dev.ip or "")
        for port in dev.ports:
            if port.state != "open":
                continue
            cur_set = current_open.get(key, set())
            if (port.port, port.protocol) not in cur_set:
                closed.append(
                    (
                        dev,
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
