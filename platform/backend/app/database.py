# Author: Avinash Krishna — Team AVV Elites (SIH26153)
"""
platform/backend/app/database.py

SQLAlchemy setup. All queries elsewhere in the app go through the ORM
(Session.query / select()) with bound parameters — never raw string-formatted
SQL — which is what makes SQL injection structurally hard to introduce by
accident (SECURITY.md §6).
"""
from __future__ import annotations

from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import get_settings

settings = get_settings()

_connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
engine = create_engine(settings.database_url, connect_args=_connect_args, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency: one session per request, always closed. Routers
    depend on this rather than importing SessionLocal directly, so tests can
    override it with an isolated test database (see tests/conftest.py)."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Creates tables if they don't exist. Fine for a hackathon-stage demo;
    a real deployment should switch to Alembic migrations before its first
    schema change against real data — see platform/README.md."""
    import app.models  # noqa: F401 — ensures models are registered on Base.metadata before create_all

    Base.metadata.create_all(bind=engine)
