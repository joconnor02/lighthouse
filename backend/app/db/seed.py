"""Populate default settings on first run."""
from __future__ import annotations

from app.db.models import Setting
from app.db.session import SessionLocal


DEFAULTS = {
    "default_cidr": "192.168.1.0/24",
    "schedule_cron": "",  # empty = off
    "port_range": "1-1024",
    "scan_type": "fast",  # fast | syn | connect | intense
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
