"""Populate default settings on first run."""
from __future__ import annotations

from app.db.models import Setting
from app.db.session import SessionLocal


DEFAULTS = {
    "default_cidr": "192.168.1.0/24",
    "port_range": "1-1024",
    # Thorough / deep scan type for Devices + auto deep-scan-on-discovery.
    "scan_type": "intense",  # connect | syn | intense
    "deep_scan_on_new_device": "false",
}


def seed_defaults() -> None:
    db = SessionLocal()
    try:
        for key, value in DEFAULTS.items():
            if db.get(Setting, key) is None:
                db.add(Setting(key=key, value=value))
        db.commit()
    finally:
        db.close()


def get_setting(db, key: str) -> str | None:
    row = db.get(Setting, key)
    return row.value if row else None


def set_setting(db, key: str, value: str) -> None:
    row = db.get(Setting, key)
    if row is None:
        db.add(Setting(key=key, value=value))
    else:
        row.value = value
    db.commit()


def setting_bool(db, key: str, default: bool = False) -> bool:
    raw = get_setting(db, key)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")
