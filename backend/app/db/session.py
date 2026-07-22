"""SQLAlchemy engine + session factory."""
from __future__ import annotations

from collections.abc import Iterator

from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker, declarative_base

from app.config import settings


engine = create_engine(
    settings.db_url,
    connect_args={"check_same_thread": False, "timeout": 30},
    future=True,
)


@event.listens_for(engine, "connect")
def _set_sqlite_pragmas(dbapi_conn, _connection_record) -> None:
    """WAL + busy timeout so scan progress commits don't lock out API readers."""
    cursor = dbapi_conn.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA busy_timeout=30000")
    cursor.close()


SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)

Base = declarative_base()


def get_db() -> Iterator[Session]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Create tables (used when Alembic isn't run)."""
    from app.db import models  # noqa: F401  ensure models are imported

    Base.metadata.create_all(bind=engine)
    from app.db.seed import seed_defaults

    seed_defaults()
