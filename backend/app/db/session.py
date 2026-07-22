"""SQLAlchemy engine + session factory."""
from __future__ import annotations

from collections.abc import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker, declarative_base

from app.config import settings


engine = create_engine(
    settings.db_url,
    connect_args={"check_same_thread": False},
    future=True,
)

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
