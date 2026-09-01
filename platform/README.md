# platform/ — Secure Multi-Analyst SOC Platform

This directory is a production-oriented extension of the core World Model
pipeline in `../src/`. It exists to answer a question the hackathon spec
doesn't have to answer but a real SOC deployment does: *how do multiple
analysts, across an organization, securely use this together?*

It is **not** required to satisfy the literal SIH26153 problem statement
(that's `../app/streamlit_app.py` — offline, single-analyst, zero network
calls). It exists because the project's own viability argument describes
a real rollout ("piloted on one network segment before wider SOC
rollout"), and because the person who commissioned this build asked
explicitly for the full production security treatment: authenticated
sessions, per-organization data isolation, rate limiting, secrets
management, and input validation. See `../SECURITY.md` for the full design
and how each requirement maps to actual code.

## Structure

```
platform/
├── backend/           # FastAPI application
│   ├── app/
│   │   ├── main.py          # app assembly, middleware, exception handlers
│   │   ├── config.py        # settings — every secret from env vars only
│   │   ├── security.py      # password hashing, JWT, opaque tokens
│   │   ├── rate_limit.py    # slowapi configuration
│   │   ├── models.py        # SQLAlchemy ORM — org-scoped throughout
│   │   ├── schemas.py       # Pydantic request/response validation
│   │   ├── deps.py          # current_user + IDOR-safe ownership lookup
│   │   ├── middleware.py    # audit logging, security headers
│   │   ├── routers/         # auth, forecasts, uploads, copilot
│   │   └── services/        # email, ml_bridge (calls into ../../src), rag_service
│   ├── tests/                # 26 tests: full auth flow + explicit IDOR regression
│   └── Dockerfile
└── frontend/           # server-rendered dashboard (Jinja2 + vanilla JS)
    ├── templates/       # login, register, dashboard, copilot
    └── static/           # design-token CSS, API client JS
```

## Why server-rendered HTML instead of a React SPA

A deliberate choice, not a shortcut: the ML pipeline and backend are both
Python, and a server-rendered frontend keeps the whole platform to one
language, one Docker image, no separate Node build toolchain, and — not
incidentally — one fewer external dependency in a security-focused tool
that may need to run in a network-restricted SOC environment. The frontend
makes **zero third-party network calls** (no font CDNs, no analytics, no
external scripts), matching the same "nothing leaves this network unless
you explicitly configure it to" posture as the offline pipeline. If your
team wants a richer SPA later, the FastAPI backend already exposes a full
JSON API (`/api/docs`) that a separate React/Next frontend could consume
without any backend changes.

## Before this touches real production data

This is a genuinely secure **reference implementation**, verified by a
real, passing test suite — not security theater. Two things are explicitly
scoped out and should be the first additions before real analyst data goes
through it:

1. **Alembic migrations.** The demo uses `Base.metadata.create_all()`
   (`database.py::init_db`) for simplicity. Fine while the schema is still
   moving; switch to Alembic before the first schema change against data
   you care about.
2. **A managed secrets store** (AWS Secrets Manager, HashiCorp Vault, or
   equivalent) in place of a `.env` file, for teams deploying beyond a
   single Docker host.

Everything else described in `../SECURITY.md` — hashing, session
expiry/rotation, IDOR scoping, rate limiting, TLS, audit logging, input
validation — is real, tested, and ready.
