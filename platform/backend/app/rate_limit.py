<<<<<<< HEAD
# Author: Avinash Krishna — Team AVV Elites (SIH26153)
=======
>>>>>>> 77949f2bb89fea05df3ee4faf24abd4771ef1671
"""
platform/backend/app/rate_limit.py
SECURITY.md ref: §4 — abuse protection for login, registration, uploads, and
AI/copilot generation requests.

Backed by Redis (via REDIS_URL) when configured, so limits are enforced
correctly across multiple backend worker processes/replicas — an in-memory
limiter's counters are per-process and silently under-enforce the moment you
run more than one worker, which is exactly the kind of gap that makes rate
limiting look present in code review but not actually hold in production.
Falls back to in-memory automatically when REDIS_URL is unset, which is
fine for local development but is intentionally flagged by
config.py::_validate_production_secrets() if it happens in production.
"""
from __future__ import annotations

from slowapi import Limiter
from slowapi.util import get_remote_address

from app.config import get_settings

settings = get_settings()

limiter = Limiter(
    key_func=get_remote_address,
    storage_uri=settings.redis_url or "memory://",
    default_limits=[settings.default_rate_limit],
    headers_enabled=False,  # see module docstring below: avoids a slowapi/
    # FastAPI interaction that requires every @limiter.limit()-decorated
    # endpoint to accept an injected Response object, which conflicts with
    # this API's use of Pydantic response_model serialization throughout.
    # The 429 status code and JSON body (main.py::rate_limit_handler) are
    # unaffected — only the optional X-RateLimit-* informational headers
    # are skipped.
)


def account_key_func(email: str) -> str:
    """A second limiter key, used ON TOP OF the IP-based limiter for login,
    keyed by the *attempted* email rather than source IP. This is what stops
    a distributed credential-stuffing attempt (many source IPs, one target
    account) that a pure IP-based limiter would not catch — see
    routers/auth.py::login for where both are checked together."""
    return f"account:{email.lower().strip()}"
