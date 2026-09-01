<<<<<<< HEAD
# Author: Avinash Krishna — Team AVV Elites (SIH26153)
=======
>>>>>>> 77949f2bb89fea05df3ee4faf24abd4771ef1671
"""
platform/backend/app/main.py

Assembles the FastAPI application. Run with:
    uvicorn app.main:app --host 0.0.0.0 --port 8000   (dev)
    (production: behind gunicorn+uvicorn workers behind nginx — see
    Dockerfile and ../../docker-compose.yml)
"""
from __future__ import annotations

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from slowapi.errors import RateLimitExceeded

from app.config import get_settings
from app.database import init_db
from app.middleware import RequestLoggingMiddleware, SecurityHeadersMiddleware, log_audit_event
from app.rate_limit import limiter
from app.routers import auth, copilot, forecasts, uploads
from app.services.ml_bridge import pipeline_ready
from app.utils_logging import get_logger

logger = get_logger(__name__)
settings = get_settings()

app = FastAPI(
    title="NexusAI Forecast — Secure SOC Platform",
    description="Production deployment layer for SIH26153. The core World Model pipeline "
                "(src/*) is unchanged and still runs fully offline via app/streamlit_app.py; "
                "this API is the secure, multi-analyst extension described in SECURITY.md.",
    version="0.1.0",
    docs_url="/api/docs" if settings.environment != "production" else None,  # Swagger UI off by
    redoc_url="/api/redoc" if settings.environment != "production" else None,  # default in prod —
    # an interactive schema explorer is a convenience, not something to expose to the public
    # internet by default; re-enable deliberately if you want it (SECURITY.md §3).
)

app.state.limiter = limiter


@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
    log_audit_event("rate_limited", ip_address=request.client.host if request.client else None,
                     detail=f"{request.method} {request.url.path}")
    return JSONResponse(status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                         content={"detail": "Too many requests. Please slow down and try again shortly."})


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    # Pydantic's default error body can echo back the invalid input value —
    # useful for legitimate API consumers debugging a request, but also a
    # channel that could reflect attacker-supplied strings straight into a
    # JSON response. We keep the field path and message, drop the echoed
    # "input" value, which is enough to fix a malformed request without the
    # reflection.
    sanitized = [{"loc": e["loc"], "msg": e["msg"], "type": e["type"]} for e in exc.errors()]
    return JSONResponse(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, content={"detail": sanitized})


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """SECURITY.md §3: API errors are logged; SECURITY.md §5 (secrets) and
    general hardening: a stack trace is NEVER sent to the client — that's
    an information-disclosure bug (paths, library versions, sometimes
    literal secret values in a traceback) as common as any on this
    checklist, and distinct from having secrets 'in code' in the first
    place."""
    logger.exception(f"Unhandled exception on {request.method} {request.url.path}")
    log_audit_event("api_error", ip_address=request.client.host if request.client else None,
                     detail=f"{type(exc).__name__} on {request.method} {request.url.path}")
    return JSONResponse(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                         content={"detail": "Internal server error."})


# Order matters: outermost-added runs first on the request, last on the
# response. Logging wraps everything (including error responses); security
# headers apply to every response including error paths.
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestLoggingMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_allowed_origins,  # explicit allow-list, never "*" (SECURITY.md §3)
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)

app.include_router(auth.router, prefix="/api")
app.include_router(forecasts.router, prefix="/api")
app.include_router(uploads.router, prefix="/api")
app.include_router(copilot.router, prefix="/api")

_FRONTEND_DIR = __import__("pathlib").Path(__file__).resolve().parents[2] / "frontend"
if (_FRONTEND_DIR / "static").exists():
    app.mount("/static", StaticFiles(directory=str(_FRONTEND_DIR / "static")), name="static")
_templates = Jinja2Templates(directory=str(_FRONTEND_DIR / "templates")) if (_FRONTEND_DIR / "templates").exists() else None


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def root(request: Request):
    if _templates is None:
        return HTMLResponse("<h1>NexusAI Forecast API</h1><p>Frontend templates not found.</p>")
    return _templates.TemplateResponse(request, "login.html")


@app.get("/register", response_class=HTMLResponse, include_in_schema=False)
def register_page(request: Request):
    return _templates.TemplateResponse(request, "register.html")


@app.get("/dashboard", response_class=HTMLResponse, include_in_schema=False)
def dashboard_page(request: Request):
    return _templates.TemplateResponse(request, "dashboard.html")


@app.get("/copilot", response_class=HTMLResponse, include_in_schema=False)
def copilot_page(request: Request):
    return _templates.TemplateResponse(request, "copilot.html")


@app.get("/api/health", tags=["meta"])
def health():
    """Unauthenticated liveness/readiness probe — deliberately reveals only
    a boolean, never version numbers or stack details (those belong behind
    auth if you want them at all)."""
    return {"status": "ok", "ml_pipeline_ready": pipeline_ready()}


@app.on_event("startup")
def on_startup():
    init_db()
    if not pipeline_ready():
        logger.warning(
            "ML checkpoints not found — /api/segments/*/forecasts will return 503 until "
            "`python -m src.train` has been run from the repo root."
        )
