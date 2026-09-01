# Author: Avinash Krishna — Team AVV Elites (SIH26153)
# platform/backend/Dockerfile
# Build from the REPO ROOT: docker build -f platform/backend/Dockerfile .
# (docker-compose.yml at the repo root does this automatically)
#
# The image contains both src/ (ml_core — feature extraction, models, RAG)
# and platform/backend/ (this API) because app/services/ml_bridge.py imports
# src.* directly rather than vendoring a copy — one pipeline implementation,
# shared by the offline Streamlit demo and this deployed API, never two
# copies that could silently drift apart.

FROM python:3.12-slim AS base

# Non-root user — a container running as root that gets compromised via any
# future dependency vulnerability hands the attacker root in the container
# for free; there is no reason this API process needs it.
RUN groupadd -r nexusai && useradd -r -g nexusai -m nexusai

WORKDIR /app

# System deps: libpq for psycopg2 (Postgres), gcc for a couple of packages
# that build C extensions (argon2-cffi, psycopg2 from source fallback)
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpq-dev gcc \
    && rm -rf /var/lib/apt/lists/*

# --- ml_core dependencies (top-level requirements.txt) ---
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# --- backend-specific dependencies ---
COPY platform/backend/requirements.txt /app/backend-requirements.txt
RUN pip install --no-cache-dir -r /app/backend-requirements.txt

# --- application code ---
COPY src/ /app/src/
COPY configs/ /app/configs/
COPY checkpoints/ /app/checkpoints/
COPY platform/backend/app/ /app/platform/backend/app/
COPY platform/frontend/ /app/platform/frontend/

WORKDIR /app/platform/backend
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN chown -R nexusai:nexusai /app
USER nexusai

EXPOSE 8000

# Multiple gunicorn workers (uvicorn worker class) — one reason REDIS_URL
# matters in production (see app/config.py): with >1 worker, an in-memory
# rate limiter's counters are per-process and under-enforce.
CMD ["gunicorn", "app.main:app", "--workers", "4", "--worker-class", "uvicorn.workers.UvicornWorker", \
     "--bind", "0.0.0.0:8000", "--access-logfile", "-", "--error-logfile", "-"]
