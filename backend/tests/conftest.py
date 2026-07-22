"""Shared pytest fixtures."""
from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    db_path = tmp_path / "test.db"
    xml_dir = tmp_path / "nmap_xml"
    xml_dir.mkdir()

    monkeypatch.setenv("LIGHTHOUSE_AUTH_DISABLED", "true")
    monkeypatch.setenv("LIGHTHOUSE_AUTH_TOKEN", "test-token")
    monkeypatch.setenv("LIGHTHOUSE_DB_PATH", str(db_path))
    monkeypatch.setenv("LIGHTHOUSE_NMAP_XML_DIR", str(xml_dir))

    import app.config as config_mod
    import app.db.session as session_mod
    import app.core.scanner as scanner_mod
    import app.core.auth as auth_mod
    import app.core.scheduler as scheduler_mod
    import app.main as main_mod

    test_settings = config_mod.Settings(
        auth_token="test-token",
        auth_disabled=True,
        db_path=str(db_path),
        nmap_xml_dir=str(xml_dir),
    )
    monkeypatch.setattr(config_mod, "settings", test_settings)
    monkeypatch.setattr(auth_mod, "settings", test_settings)
    monkeypatch.setattr(scanner_mod, "settings", test_settings)
    monkeypatch.setattr(main_mod, "settings", test_settings)

    from sqlalchemy import create_engine, event
    from sqlalchemy.orm import sessionmaker

    engine = create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False, "timeout": 30},
        future=True,
    )

    @event.listens_for(engine, "connect")
    def _pragmas(dbapi_conn, _):
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA busy_timeout=30000")
        cur.close()

    TestSessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
    monkeypatch.setattr(session_mod, "engine", engine)
    monkeypatch.setattr(session_mod, "SessionLocal", TestSessionLocal)
    monkeypatch.setattr(scanner_mod, "SessionLocal", TestSessionLocal)
    monkeypatch.setattr(scheduler_mod, "SessionLocal", TestSessionLocal)

    import app.db.seed as seed_mod

    monkeypatch.setattr(seed_mod, "SessionLocal", TestSessionLocal)

    def _override_get_db():
        db = TestSessionLocal()
        try:
            yield db
        finally:
            db.close()

    from app.db.models import Base

    Base.metadata.create_all(bind=engine)
    seed_mod.seed_defaults()

    monkeypatch.setattr(scanner_mod, "enqueue_scan", lambda scan_id: None)
    monkeypatch.setattr(scanner_mod, "recover_stale_scans", lambda: 0)
    monkeypatch.setattr(scanner_mod, "shutdown_executor", lambda: None)
    monkeypatch.setattr(scheduler_mod, "start_host_discovery_schedule", lambda: None)
    monkeypatch.setattr(scheduler_mod, "enqueue_host_discovery", lambda: None)
    monkeypatch.setattr(scheduler_mod, "shutdown", lambda: None)
    monkeypatch.setattr(main_mod, "recover_stale_scans", lambda: 0)
    monkeypatch.setattr(main_mod, "start_host_discovery_schedule", lambda: None)
    monkeypatch.setattr(main_mod, "enqueue_host_discovery", lambda: None)
    monkeypatch.setattr(main_mod, "scheduler_shutdown", lambda: None)
    monkeypatch.setattr(main_mod, "shutdown_executor", lambda: None)
    monkeypatch.setattr(main_mod, "init_db", lambda: None)

    # Depends() captured the original get_db callable — override it on the app.
    main_mod.app.dependency_overrides[session_mod.get_db] = _override_get_db
    try:
        with TestClient(main_mod.app) as c:
            yield c
    finally:
        main_mod.app.dependency_overrides.pop(session_mod.get_db, None)
