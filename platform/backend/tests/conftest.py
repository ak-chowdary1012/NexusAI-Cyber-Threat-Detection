"""
platform/backend/tests/conftest.py

Isolated per-test-session SQLite database (never the dev/prod DATABASE_URL)
plus a TestClient with email sending swapped for a capturing stub so tests
can pull the verification/reset token out without needing a real mailbox.
"""
from __future__ import annotations

import os

os.environ["ENVIRONMENT"] = "test"
os.environ["DATABASE_URL"] = "sqlite:///./test_nexusai.db"
os.environ["SECRET_KEY"] = "test-secret-key-not-for-production-use-only-in-ci"
os.environ["CORS_ALLOWED_ORIGINS"] = '["http://testserver"]'

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base, get_db
from app.main import app
from app.services import email_service

TEST_DB_PATH = "./test_nexusai.db"
engine = create_engine(f"sqlite:///{TEST_DB_PATH}", connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def _override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = _override_get_db


class CapturingEmailBackend(email_service.EmailBackend):
    """Swaps real/console email sending for an in-memory list the tests can
    inspect — captures verification and password-reset links without
    needing an SMTP server in CI."""
    def __init__(self):
        self.sent: list[dict] = []

    def send(self, to_address: str, subject: str, body: str) -> None:
        self.sent.append({"to": to_address, "subject": subject, "body": body})


@pytest.fixture(scope="function", autouse=True)
def fresh_database():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="function", autouse=True)
def fresh_rate_limiter():
    """The rate limits (5/min login, 5/hour register, ...) are production
    values, deliberately tight — reset the in-memory limiter state before
    every test so tests run in any order/combination without one test's
    requests counting against another's budget. Tests that specifically
    exercise rate limiting (test_login_rate_limited_by_ip) still work: they
    just need to exceed the limit within their OWN request burst, which a
    clean slate makes deterministic instead of order-dependent."""
    from app.rate_limit import limiter
    limiter.reset()
    yield
    limiter.reset()


@pytest.fixture()
def email_backend(monkeypatch):
    backend = CapturingEmailBackend()
    monkeypatch.setattr(email_service, "get_email_service", lambda: backend)
    return backend


@pytest.fixture()
def client():
    return TestClient(app)


def extract_token_from_link(body: str) -> str:
    """Pulls the `?token=...` value out of a captured email body."""
    marker = "token="
    idx = body.index(marker) + len(marker)
    end = idx
    while end < len(body) and body[end] not in " \n\r\t":
        end += 1
    return body[idx:end]


def register_and_verify(client: TestClient, email_backend: CapturingEmailBackend, *,
                         email: str = "analyst@acme-corp.io", password: str = "CorrectHorse9Battery",
                         full_name: str = "Ada Analyst", org: str = "Acme Corp") -> None:
    res = client.post("/api/auth/register", json={
        "email": email, "password": password, "full_name": full_name, "organization_name": org,
    })
    assert res.status_code == 201, res.text
    verify_token = extract_token_from_link(email_backend.sent[-1]["body"])
    res = client.post("/api/auth/verify-email", json={"token": verify_token})
    assert res.status_code == 200, res.text


def login(client: TestClient, email: str = "analyst@acme-corp.io", password: str = "CorrectHorse9Battery") -> dict:
    res = client.post("/api/auth/login", json={"email": email, "password": password})
    assert res.status_code == 200, res.text
    return res.json()
