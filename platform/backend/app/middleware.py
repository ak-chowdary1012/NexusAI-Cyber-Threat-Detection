<<<<<<< HEAD
# Author: Avinash Krishna — Team AVV Elites (SIH26153)
=======
>>>>>>> 77949f2bb89fea05df3ee4faf24abd4771ef1671
"""
platform/backend/app/middleware.py
SECURITY.md ref: §3 — logging for authentication attempts, API errors, and
unusual traffic patterns; secure deployment headers.

Two middlewares:
  RequestLoggingMiddleware — structured (JSON-lines) log of every request:
    method, path, status, latency, client IP. 5xx responses are logged at
    ERROR with a request id that also appears in the response header, so a
    report of "I got an error at 14:32" is traceable to one exact log line
    without asking the user to paste a stack trace (which, per below, they
    never see in production anyway).
  SecurityHeadersMiddleware — the standard defensive header set: HSTS (only
    when actually served over HTTPS — see main.py), X-Content-Type-Options,
    X-Frame-Options, Referrer-Policy, and a Content-Security-Policy scoped to
    this app's own server-rendered frontend (no inline-script allowance
    beyond what the templates need), which is the structural backstop
    against script injection even if a template auto-escaping gap ever slips
    through review (SECURITY.md §6).
"""
from __future__ import annotations

import json
import logging
import time
import uuid
from collections.abc import Awaitable, Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from app.config import get_settings

audit_logger = logging.getLogger("nexusai.audit")
access_logger = logging.getLogger("nexusai.access")

for _logger in (audit_logger, access_logger):
    if not _logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(message)s"))  # each message is already a JSON line
        _logger.addHandler(handler)
        _logger.setLevel(logging.INFO)
        _logger.propagate = False


def log_audit_event(event_type: str, *, user_id: str | None = None, organization_id: str | None = None,
                     ip_address: str | None = None, detail: str | None = None) -> None:
    """Security-relevant event log, separate from general access logging.
    Also persisted to the AuditLog table by callers that have a DB session
    (see routers/auth.py) — this function additionally always emits to
    stdout so events are captured even if the DB write itself is what's
    failing."""
    audit_logger.info(json.dumps({
        "log": "audit", "event_type": event_type, "user_id": user_id,
        "organization_id": organization_id, "ip_address": ip_address, "detail": detail,
        "ts": time.time(),
    }))


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        request_id = str(uuid.uuid4())
        start = time.monotonic()
        client_ip = request.client.host if request.client else "unknown"

        try:
            response = await call_next(request)
        except Exception as exc:  # noqa: BLE001 — this IS the top-level safety net
            duration_ms = round((time.monotonic() - start) * 1000, 1)
            access_logger.error(json.dumps({
                "log": "access", "request_id": request_id, "method": request.method,
                "path": request.url.path, "status": 500, "duration_ms": duration_ms,
                "client_ip": client_ip, "error": type(exc).__name__,
            }))
            raise  # re-raised so FastAPI's exception handlers (main.py) still produce the client-facing response

        duration_ms = round((time.monotonic() - start) * 1000, 1)
        level = logging.ERROR if response.status_code >= 500 else (
            logging.WARNING if response.status_code >= 400 else logging.INFO
        )
        access_logger.log(level, json.dumps({
            "log": "access", "request_id": request_id, "method": request.method,
            "path": request.url.path, "status": response.status_code,
            "duration_ms": duration_ms, "client_ip": client_ip,
        }))
        response.headers["X-Request-ID"] = request_id
        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        response = await call_next(request)
        settings = get_settings()

        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "  # templates use a small amount of inline style; scripts remain locked to 'self'
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none'"
        )
        if settings.environment == "production":
            # Only advertise HSTS when we're actually confident the deployment
            # terminates TLS (nginx, see ../../nginx/nginx.conf) — sending it
            # over plain HTTP in a dev environment would be actively wrong.
            response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
        return response
