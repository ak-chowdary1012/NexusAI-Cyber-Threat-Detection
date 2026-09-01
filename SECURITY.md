# Security Design

This document maps every item of the project's security requirements to
concrete implementation, with file references and honest notes on what's
demo-grade versus what a real production rollout would still need. It also
explains one thing worth being upfront about: **the offline `src/`/`app/`
pipeline required by the problem statement has no user accounts, sessions,
or API endpoints of its own — it's a single-analyst, fully offline tool by
design.** The security work described below therefore applies to the
`platform/` layer, the secure multi-analyst web platform built on top of
that pipeline. This is a deliberate architecture, not a reinterpretation:
it lets the project be faithful to the literal spec (see `ARCHITECTURE.md`
§3) while also being genuinely securable, since "secure" only means
something concrete once there's authentication, ownership, and a network
surface to secure.

Where a numbered requirement is quoted, it's followed by exactly what
implements it.

---

## 1. Authentication system

> Passwords securely hashed, sessions expire, email verification is
> enabled, password reset tokens expire, login attempts are rate limited,
> authentication secrets are never exposed to the frontend.

| Requirement | Implementation |
|---|---|
| Password hashing | Argon2id via `passlib` (`platform/backend/app/security.py::hash_password`) — OWASP's current recommendation, memory-hard against GPU cracking. Verified in `tests/test_auth.py::test_password_is_never_returned_or_stored_in_plaintext`. |
| Sessions expire | Access tokens: 15-minute JWTs (`config.py::access_token_expire_minutes`). Refresh tokens: opaque random strings, 7-day expiry, stored **hashed** in the DB (`RefreshToken.token_hash`) so a database leak alone can't mint sessions. |
| Sessions can be ended, not just time out | `POST /auth/logout` revokes the specific refresh token; `POST /auth/reset-password` revokes **every** session on the account (`auth.py::reset_password`) — a password reset assumes the old password may be compromised, so old sessions must not survive it. |
| Refresh rotation | Every `/auth/refresh` call revokes the presented token and issues a new one. Reuse of an already-rotated token is logged as `refresh_token_reuse_detected` (a strong signal of token theft) and rejected. Tested in `test_refresh_token_rotates_and_old_one_is_rejected_on_reuse`. |
| Email verification | Enabled and enforced: `User.is_verified` gates login entirely (`auth.py::login`), not just a UI badge. Verification tokens are opaque, hashed at rest, single-use, 24h expiry. |
| Password reset tokens expire | 60 minutes, single-use (`PasswordResetToken.used_at`), hashed at rest. Tested in `test_password_reset_token_is_single_use`. |
| Login rate limiting | Two independent layers, because they stop different attack shapes: an IP-based limiter (5/min, `slowapi`) stops one IP hammering any account; an account-level lockout (8 consecutive failures → 15-minute lock, `User.failed_login_attempts`/`locked_until`) stops credential stuffing spread across many source IPs. Both tested (`test_login_rate_limited_by_ip`, `test_account_locks_after_repeated_failures`). |
| Secrets never exposed to the frontend | `SECRET_KEY`, `DATABASE_URL`, SMTP/Anthropic credentials are read exclusively from environment variables by `config.py` and never appear in any response — regression-tested directly in `test_no_secret_key_or_db_url_ever_appears_in_any_response`. The client only ever receives the *signed JWT* (expected and required for a stateless API), never the signing secret. |
| Additional hardening | Timing-safe login failures (a real Argon2 hash is checked even for a nonexistent email, so response timing can't be used to enumerate accounts — `auth.py::_DUMMY_HASH_FOR_TIMING_SAFETY`); generic error messages that don't distinguish "wrong password" from "no such account"; automatic re-hash on login if Argon2 parameters are later strengthened (`needs_rehash`). |

**Known trade-off**: access/refresh tokens are stored in the browser's
`localStorage` (a standard pattern for a Bearer-token JSON API), not an
`httpOnly` cookie. This is bounded by a short (15-minute) access-token
lifetime and a strict Content-Security-Policy that blocks the third-party
script injection this trade-off is mainly exposed to (see §6). A team
wanting defense-in-depth beyond CSP can migrate the refresh token to an
`httpOnly`, `Secure`, `SameSite=Lax` cookie plus a CSRF token on
state-changing requests — noted here as a deliberate scope cut, not an
oversight.

---

## 2. IDOR prevention

> Every request verifies the logged-in user owns the data being accessed,
> before reading, modifying, or deleting any resource.

Every ownership-sensitive table (`NetworkSegment`, `Forecast`) carries an
`organization_id` foreign key (`platform/backend/app/models.py`). The one
and only way a router is allowed to fetch such a row by ID is
`deps.py::owned_or_404`, which filters by **primary key AND
organization_id in the same query** and returns 404 — not 403 — on a
cross-organization attempt, so a forbidden ID and a nonexistent ID are
indistinguishable to the caller (403 would itself leak that the ID exists).
List endpoints filter by `organization_id` directly rather than exposing an
unscoped "list everything" route at all.

This isn't just a design description — `platform/backend/tests/test_idor.py`
is seven tests that create two separate organizations and assert, for every
resource type and every verb (read, list, delete, and the two-step
"attach a forecast to someone else's segment" case), that cross-organization
access is **structurally impossible**, not just checked-and-forbidden. All
seven pass against the real database and real ownership logic, not mocks.

---

## 3. Secure deployment

> Enforce HTTPS, store secrets securely, restrict direct database access
> from the public internet, log authentication attempts / API errors /
> unusual traffic.

- **HTTPS**: `nginx/nginx.conf` — port 80 does nothing but 301-redirect to
  443; TLS 1.2+/1.3 only; the backend container has no published port and
  is reachable exclusively through nginx (`docker-compose.yml`).
- **Secrets storage**: every secret comes from environment variables
  (`.env`, git-ignored — see §5), read once through `config.py`, never
  hardcoded, never logged.
- **Database not publicly reachable**: `docker-compose.yml`'s `postgres`
  and `redis` services have **no `ports:` mapping** — only `backend`, on
  the same internal Docker network, can reach them. There is no path from
  the public internet to port 5432 or 6379.
- **Logging**: `platform/backend/app/middleware.py` — every request is
  logged (method, path, status, latency, client IP, request ID); every
  authentication event (`login_success`, `login_failure`,
  `refresh_token_reuse_detected`, `password_reset_requested`, ...) is
  additionally written to a dedicated `AuditLog` table plus stdout, so
  security review doesn't depend on parsing general access logs; every
  unhandled exception is logged server-side **and never returns a stack
  trace to the client** (`main.py::unhandled_exception_handler`) —
  information disclosure via error messages is exactly as real a bug class
  as anything else on this list.
- **Production boot-time guardrails**: `config.py::_validate_production_secrets`
  refuses to start in `ENVIRONMENT=production` with a short/default
  `SECRET_KEY`, a SQLite `DATABASE_URL`, or `DEBUG=true` — the failure mode
  for a misconfigured deployment is "won't start," not "starts insecurely."

---

## 4. Abuse protection

> Rate limiting for login, API endpoints, account creation, and AI
> generation requests; prevent bots/scripts from repeatedly calling
> endpoints or scraping data.

All limits are configured in one place (`config.py`) and enforced via
`slowapi` (`rate_limit.py`), Redis-backed in production so limits hold
correctly across multiple worker processes (an in-memory limiter's counters
are per-process and silently under-enforce past one worker — flagged
explicitly if `REDIS_URL` is unset in production):

| Endpoint | Limit | Why this one specifically |
|---|---|---|
| `POST /auth/login` | 5/min per IP + account lockout | credential stuffing / brute force |
| `POST /auth/register` | 5/hour per IP | mass fake-account creation |
| `POST /auth/forgot-password` | 3/hour per IP | email-bombing a target address |
| `POST /segments/{id}/forecasts` (upload) | 10/min per IP | this is the compute-expensive path (runs the full ML pipeline) |
| `POST /copilot/explain` | 15/min per IP | the "AI generation request" the requirement names explicitly — separately limited from the general API default |
| everything else | 100/min per IP | general scraping/automation resistance |

nginx additionally applies a connection-rate limit ahead of the
application layer (`nginx/nginx.conf`) as defense-in-depth.

**Note on CAPTCHA**: full bot resistance for public registration typically
also includes a CAPTCHA (hCaptcha/Turnstile) — deliberately not wired in
here since it requires a third-party account/API key with no reasonable
placeholder; `routers/auth.py::register` is structured so adding a
`captcha_token` field to `RegisterRequest` and verifying it before account
creation is a small, isolated change.

---

## 5. Secrets and credentials scanning

> API keys, database keys, and tokens never exposed in frontend code or
> committed to the repository; all secrets in environment variables, used
> server-side only.

- **`.gitignore`**: `.env`, `*.pem`, `*.key`, and `nginx/certs/` are
  excluded outright.
- **`.env.example`**: every variable documented with an obviously-fake
  placeholder value — never real, never functional as-is.
- **`.pre-commit-config.yaml`**: runs `gitleaks` (secret pattern scanning)
  and `detect-private-key` on every commit, locally, before anything
  reaches git history.
- **CI enforcement**: `.github/workflows/ci.yml`'s `secret-scan` job runs
  gitleaks against full repository history on every push/PR — a secret has
  to get past both the local hook and this CI job to land on a shared
  branch.
- **Server-side-only usage**: `ANTHROPIC_API_KEY`, `SECRET_KEY`,
  `DATABASE_URL`, and SMTP credentials are read once in `config.py` and
  used only inside backend service modules (`security.py`,
  `rag_service.py`, `email_service.py`) — never serialized into any
  Pydantic response schema, which is what `schemas.py` and the regression
  test in §1 (`test_no_secret_key_or_db_url_ever_appears_in_any_response`)
  are structurally enforcing, not just documenting.
- The frontend (`platform/frontend/`) contains **zero** API keys or
  secrets of any kind — it only ever holds the short-lived JWT issued to
  the signed-in user, by design (see §1 known trade-off).

---

## 6. Input validation and sanitization

> Validate/sanitize every entry point — forms, APIs, uploads, query
> parameters — against SQL injection, command injection, script injection,
> unsafe file uploads; reject invalid data, enforce strict types.

- **SQL injection**: every database query goes through SQLAlchemy's ORM
  with bound parameters (`db.query(Model).filter(...)`) — there is no raw,
  string-formatted SQL anywhere in this codebase to inject into.
- **Command injection**: no code path shells out with user-controlled
  input; PCAP parsing uses Scapy's Python API directly (`packet_features.py`),
  never a subprocess call built from request data.
- **Script injection (XSS)**: the frontend is server-rendered Jinja2 with
  autoescaping on by default; `middleware.py::SecurityHeadersMiddleware`
  additionally sets a `Content-Security-Policy` with `script-src 'self'`
  and no inline-script allowance — even a template autoescaping mistake
  would still be blocked from executing a third-party payload. Rendered
  identifiers (e.g. `host_identifier`) are also constrained at the schema
  level (see below) as an independent second layer.
- **Strict input types**: every API request body is a Pydantic model
  (`schemas.py`) with explicit types and constraints — `EmailStr` for
  emails, `Field(min_length=..., max_length=...)` on every string,
  a regex `pattern` on `host_identifier` restricting it to
  IP/hostname-shaped characters, enums where the value space is closed.
  FastAPI rejects anything that doesn't match with a 422 before a single
  line of handler code runs.
- **File uploads** (`routers/uploads.py`): extension allow-list (`.csv`,
  `.pcap`, `.pcapng`), a hard size cap (50MB, configurable), a byte-level
  sniff check that rejects binary/null-byte content disguised with a `.csv`
  extension, and a row cap (`pd.read_csv(..., nrows=200_000)`) applied even
  within the size limit, so a small but adversarially-crafted file can't
  cause unbounded memory use during parsing. The offline Streamlit app
  (`app/streamlit_app.py::validate_upload`) applies the same checks
  independently, since it's a second, separate entry point for the same
  kind of input.
- **Reject, don't coerce**: invalid input is rejected with a 422/400 and a
  clear message, never silently "fixed" and processed — matching the
  explicit "reject invalid data" requirement rather than best-effort
  sanitization.

---

## What this checklist doesn't cover (and why that's fine)

A few standard hardening items that don't have a natural home in the six
requirements above, addressed briefly for completeness: dependency
vulnerability scanning (`pip-audit`/`safety` — not wired into CI here, a
reasonable next addition); the Docker image runs as a non-root user
(`platform/backend/Dockerfile`); Alembic migrations are not set up (the
demo uses `Base.metadata.create_all`) — appropriate for a hackathon-stage
schema that's still moving, called out explicitly in `platform/README.md`
as the first thing to add before any real production data is stored.
