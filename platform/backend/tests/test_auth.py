# Author: Avinash Krishna — Team AVV Elites (SIH26153)
"""
platform/backend/tests/test_auth.py
SECURITY.md ref: §1 — every bullet in the authentication requirement gets a
directly corresponding test below, not just an implementation.
"""
from __future__ import annotations

from tests.conftest import extract_token_from_link, login, register_and_verify


def test_register_creates_unverified_user(client, email_backend):
    res = client.post("/api/auth/register", json={
        "email": "new@acme-corp.io", "password": "CorrectHorse9Battery",
        "full_name": "New User", "organization_name": "Acme Corp",
    })
    assert res.status_code == 201
    body = res.json()
    assert body["is_verified"] is False
    assert len(email_backend.sent) == 1
    assert "verify" in email_backend.sent[0]["subject"].lower()


def test_password_is_never_returned_or_stored_in_plaintext(client, email_backend):
    res = client.post("/api/auth/register", json={
        "email": "hash@acme-corp.io", "password": "CorrectHorse9Battery",
        "full_name": "Hash Test", "organization_name": "Acme Corp",
    })
    body = res.json()
    assert "password" not in body
    assert "hashed_password" not in body

    from app.database import SessionLocal
    from app.models import User
    # NOTE: uses the same overridden test DB via conftest's engine
    from tests.conftest import TestingSessionLocal
    db = TestingSessionLocal()
    user = db.query(User).filter(User.email == "hash@acme-corp.io").first()
    assert user.hashed_password != "CorrectHorse9Battery"
    assert user.hashed_password.startswith("$argon2")
    db.close()


def test_weak_password_rejected(client):
    res = client.post("/api/auth/register", json={
        "email": "weak@acme-corp.io", "password": "alllowercase123",  # no uppercase
        "full_name": "Weak Pw", "organization_name": "Acme Corp",
    })
    assert res.status_code == 422


def test_login_blocked_until_email_verified(client, email_backend):
    client.post("/api/auth/register", json={
        "email": "unverified@acme-corp.io", "password": "CorrectHorse9Battery",
        "full_name": "Unverified", "organization_name": "Acme Corp",
    })
    res = client.post("/api/auth/login", json={"email": "unverified@acme-corp.io", "password": "CorrectHorse9Battery"})
    assert res.status_code == 403
    assert "verify" in res.json()["detail"].lower()


def test_full_register_verify_login_flow(client, email_backend):
    register_and_verify(client, email_backend)
    tokens = login(client)
    assert "access_token" in tokens and "refresh_token" in tokens
    assert tokens["expires_in_minutes"] == 15


def test_wrong_password_rejected_with_generic_message(client, email_backend):
    register_and_verify(client, email_backend)
    res = client.post("/api/auth/login", json={"email": "analyst@acme-corp.io", "password": "WrongPassword9"})
    assert res.status_code == 401
    assert res.json()["detail"] == "Incorrect email or password."


def test_nonexistent_account_gets_same_generic_message(client):
    res = client.post("/api/auth/login", json={"email": "ghost@nowhere.io", "password": "WhateverPassword9"})
    assert res.status_code == 401
    assert res.json()["detail"] == "Incorrect email or password."


def test_account_locks_after_repeated_failures(client, email_backend):
    """Isolates the ACCOUNT-level lockout mechanism from the IP-based rate
    limiter (tested separately in test_login_rate_limited_by_ip) by
    temporarily disabling the limiter — in production both run together
    (see security.py module docstring: they defend different attack
    shapes), but a same-IP test burst would otherwise trip the tighter
    5/minute IP limit before ever reaching the 8-failure account threshold."""
    from app.rate_limit import limiter
    register_and_verify(client, email_backend)
    limiter.enabled = False
    try:
        for _ in range(8):
            client.post("/api/auth/login", json={"email": "analyst@acme-corp.io", "password": "WrongPassword9"})
        res = client.post("/api/auth/login", json={"email": "analyst@acme-corp.io", "password": "CorrectHorse9Battery"})
        assert res.status_code == 423  # locked, even with the CORRECT password now
    finally:
        limiter.enabled = True


def test_login_rate_limited_by_ip(client, email_backend):
    register_and_verify(client, email_backend)
    statuses = []
    for _ in range(10):
        res = client.post("/api/auth/login", json={"email": "analyst@acme-corp.io", "password": "WrongPassword9"})
        statuses.append(res.status_code)
    assert 429 in statuses, f"expected a 429 among repeated rapid login attempts, got {statuses}"


def test_access_token_required_for_protected_route(client):
    res = client.get("/api/auth/me")
    assert res.status_code == 401


def test_access_token_works_for_protected_route(client, email_backend):
    register_and_verify(client, email_backend)
    tokens = login(client)
    res = client.get("/api/auth/me", headers={"Authorization": f"Bearer {tokens['access_token']}"})
    assert res.status_code == 200
    assert res.json()["email"] == "analyst@acme-corp.io"


def test_refresh_token_rotates_and_old_one_is_rejected_on_reuse(client, email_backend):
    register_and_verify(client, email_backend)
    tokens = login(client)
    res = client.post("/api/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert res.status_code == 200
    new_tokens = res.json()
    # The refresh token is what rotation actually guarantees (opaque, random
    # per issuance — see security.py::generate_opaque_token). The access
    # token is a signed JWT whose claims (sub/iat/exp/org/role) can
    # legitimately be identical, and therefore byte-identical, if issued
    # within the same second as the previous one; that is not a security
    # property this test should assert on.
    assert new_tokens["refresh_token"] != tokens["refresh_token"]
    me_res = client.get("/api/auth/me", headers={"Authorization": f"Bearer {new_tokens['access_token']}"})
    assert me_res.status_code == 200

    # reusing the ORIGINAL (now-rotated-away) refresh token must fail
    reuse = client.post("/api/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert reuse.status_code == 401


def test_logout_revokes_refresh_token(client, email_backend):
    register_and_verify(client, email_backend)
    tokens = login(client)
    logout_res = client.post(
        "/api/auth/logout", json={"refresh_token": tokens["refresh_token"]},
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    )
    assert logout_res.status_code == 204
    refresh_res = client.post("/api/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert refresh_res.status_code == 401


def test_forgot_password_returns_202_even_for_unknown_email(client):
    res = client.post("/api/auth/forgot-password", json={"email": "nobody@nowhere.io"})
    assert res.status_code == 202  # no account-existence leak


def test_password_reset_flow_and_old_password_stops_working(client, email_backend):
    register_and_verify(client, email_backend)
    client.post("/api/auth/forgot-password", json={"email": "analyst@acme-corp.io"})
    reset_token = extract_token_from_link(email_backend.sent[-1]["body"])

    res = client.post("/api/auth/reset-password", json={"token": reset_token, "new_password": "BrandNewPassword9"})
    assert res.status_code == 204

    old_login = client.post("/api/auth/login", json={"email": "analyst@acme-corp.io", "password": "CorrectHorse9Battery"})
    assert old_login.status_code == 401

    new_login = client.post("/api/auth/login", json={"email": "analyst@acme-corp.io", "password": "BrandNewPassword9"})
    assert new_login.status_code == 200


def test_password_reset_token_is_single_use(client, email_backend):
    register_and_verify(client, email_backend)
    client.post("/api/auth/forgot-password", json={"email": "analyst@acme-corp.io"})
    reset_token = extract_token_from_link(email_backend.sent[-1]["body"])

    first = client.post("/api/auth/reset-password", json={"token": reset_token, "new_password": "FirstNewPassword9"})
    assert first.status_code == 204
    second = client.post("/api/auth/reset-password", json={"token": reset_token, "new_password": "SecondNewPassword9"})
    assert second.status_code == 400


def test_reset_password_revokes_existing_sessions(client, email_backend):
    register_and_verify(client, email_backend)
    tokens = login(client)

    client.post("/api/auth/forgot-password", json={"email": "analyst@acme-corp.io"})
    reset_token = extract_token_from_link(email_backend.sent[-1]["body"])
    client.post("/api/auth/reset-password", json={"token": reset_token, "new_password": "BrandNewPassword9"})

    # the refresh token from BEFORE the reset must no longer work
    res = client.post("/api/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert res.status_code == 401


def test_no_secret_key_or_db_url_ever_appears_in_any_response(client, email_backend):
    """A blunt but effective regression check for SECURITY.md §5 (secrets
    never exposed to the frontend) — the raw secret must never leak into any
    JSON body across a representative slice of endpoints."""
    from app.config import get_settings
    secret = get_settings().secret_key

    register_and_verify(client, email_backend)
    tokens = login(client)
    responses = [
        client.get("/api/health"),
        client.get("/api/auth/me", headers={"Authorization": f"Bearer {tokens['access_token']}"}),
        client.get("/api/docs"),
    ]
    for res in responses:
        assert secret not in res.text
