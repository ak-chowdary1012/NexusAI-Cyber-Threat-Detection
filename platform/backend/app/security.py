<<<<<<< HEAD
# Author: Avinash Krishna — Team AVV Elites (SIH26153)
=======
>>>>>>> 77949f2bb89fea05df3ee4faf24abd4771ef1671
"""
platform/backend/app/security.py
SECURITY.md ref: §1 — passwords securely hashed, sessions expire, secrets never exposed to frontend

Password hashing: Argon2id via passlib, OWASP's current recommended default
for new applications (memory-hard, GPU-cracking resistant — a materially
stronger choice than bcrypt or, far worse, unsalted SHA-256, which is the
single most common "authentication system" mistake this module exists to
rule out).

Tokens: short-lived JWT access tokens signed with HS256 using a server-only
secret (never sent to the client — the client receives the *signed token*,
which is normal and required for a stateless API, not the signing secret
itself). Refresh tokens are opaque random strings, stored only as a *hash*
in the database (mirroring password storage) so a database leak alone does
not let an attacker mint new sessions, and can be individually revoked.
"""
from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from jose import JWTError, jwt
from passlib.context import CryptContext

from app.config import get_settings

_pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")


# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------

def hash_password(plain_password: str) -> str:
    return _pwd_context.hash(plain_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return _pwd_context.verify(plain_password, hashed_password)
    except ValueError:
        # malformed hash in the DB (should never happen) — fail closed, not open
        return False


def needs_rehash(hashed_password: str) -> bool:
    """True if the stored hash was made with outdated parameters (e.g. after
    raising argon2 cost factors) — call after a successful login and
    transparently re-hash, per standard credential-hygiene practice."""
    return _pwd_context.needs_update(hashed_password)


# ---------------------------------------------------------------------------
# JWT access tokens (short-lived, stateless, carried in the Authorization header)
# ---------------------------------------------------------------------------

def create_access_token(subject: str, extra_claims: dict | None = None) -> str:
    settings = get_settings()
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=settings.access_token_expire_minutes)
    to_encode = {"sub": subject, "iat": now, "exp": expire, "type": "access"}
    if extra_claims:
        to_encode.update(extra_claims)
    return jwt.encode(to_encode, settings.secret_key, algorithm=settings.jwt_algorithm)


def decode_access_token(token: str) -> dict | None:
    settings = get_settings()
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.jwt_algorithm])
    except JWTError:
        return None
    if payload.get("type") != "access":
        return None  # a refresh token (or forged type claim) must never be accepted here
    return payload


# ---------------------------------------------------------------------------
# Opaque, hashed-at-rest tokens: refresh tokens, email verification, password reset
# ---------------------------------------------------------------------------

def generate_opaque_token() -> tuple[str, str, str]:
    """Returns (raw_token, token_hash, lookup_prefix).

    raw_token is sent to the user (in the Set-Cookie/response body, or the
    verification email) and never stored. token_hash (SHA-256 of the raw
    token) is what's persisted — mirroring password storage, so a DB dump
    doesn't hand out usable session/reset tokens the way storing them in
    plaintext would. lookup_prefix (first 12 hex chars of the hash) lets the
    DB query find the *candidate* row by an indexed column before doing the
    real hash comparison, without ever indexing the full sensitive hash in a
    way that a timing side-channel on a LIKE-prefix query could exploit
    further than it already reveals (12 hex chars is not the secret; the
    full 64-char hash still has to match).
    """
    raw = secrets.token_urlsafe(48)
    token_hash = hashlib.sha256(raw.encode()).hexdigest()
    return raw, token_hash, token_hash[:12]


def hash_opaque_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode()).hexdigest()


def constant_time_compare(a: str, b: str) -> bool:
    return secrets.compare_digest(a, b)


def ensure_utc(dt: datetime) -> datetime:
    """Normalizes a datetime that may have lost its tzinfo on the round trip
    through the database. SQLite (used for local dev/test — see
    database.py) has no native timezone-aware datetime type, so a value
    written as UTC-aware can come back naive; PostgreSQL (production) does
    not have this problem, but calling this unconditionally is harmless
    there too. Every comparison anywhere in this codebase between a
    database-sourced datetime and datetime.now(timezone.utc) must go
    through this function first, or it will raise TypeError on SQLite."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt
