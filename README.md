# NexusAI Forecast

**AI-based Network Attack Forecasting from Network Traffic Data**
Smart India Hackathon 2026 · Problem Statement **SIH26153** · National Technical Research Organisation (NTRO) · Theme: Blockchain & Cybersecurity
Team **AVV Elites** · Amrita Vishwa Vidyapeetham
Author: **Avinash Krishna** · [github.com/ak-chowdary1012](https://github.com/ak-chowdary1012)

A World-Model AI system that learns the evolving state of a network from traffic telemetry, forecasts the probability and progression of malicious activity **before compromise completes**, maps predicted trajectories onto MITRE ATT&CK kill-chain stages, and explains every forecast in terms a defender can act on.

---

## What's in this repository

This repo has **two parts**, and it's worth understanding why before you run anything:

| | `src/`, `app/`, `configs/`, `notebooks/`, `data/` | `platform/` |
|---|---|---|
| **What it is** | The World Model pipeline itself, exactly as scoped by the problem statement | A secure, multi-analyst SOC web platform built on top of it |
| **Interface** | Offline Streamlit dashboard, single analyst | FastAPI + web dashboard, multiple analysts / organizations |
| **Network** | Zero outbound calls, fully offline, no cloud dependency | A real deployable API — login, sessions, HTTPS, rate limiting |
| **Why it exists** | This is the literal deliverable the problem statement and dataset rules require | This is what makes the project *"secure, world-class, production-ready"* rather than a one-off hackathon demo — see [SECURITY.md](SECURITY.md) |

Both share **one implementation** of the actual ML pipeline (`src/`) — the platform imports it directly (`platform/backend/app/services/ml_bridge.py`) rather than duplicating it, so there is never a risk of the two surfaces drifting apart or reporting different numbers.

If you only need to satisfy the hackathon submission requirements, you only need `src/`, `app/streamlit_app.py`, and `docs/`. If you want the "how would this actually get deployed to a SOC team" story, that's `platform/`.

---

## Quickstart — offline pipeline (5 minutes, no setup)

```bash
python -m venv venv && source venv/bin/activate      # or your preferred env manager
pip install -r requirements.txt

python -m src.synthetic_data      # generates a small labelled sample so you don't need
                                   # to download CIC-IDS2017/2018 or CTU-13 just to try this
python -m src.train                # trains state encoder + transition model + baseline (~1 min on CPU)
python -m src.evaluate             # writes results/eval_report.json: World Model vs baseline,
                                    # generalisation check, ATT&CK mapping agreement rate

streamlit run app/streamlit_app.py # the live demo — upload traffic, see the forecast,
                                    # SHAP + attention explainability, RAG-grounded ATT&CK guidance
```

To run against the real competition datasets instead of the synthetic sample, see [`data/README.md`](data/README.md), then pass `--data-path` to `train.py`/`evaluate.py`.

Run the test suite any time with `pytest tests/ -v` — see [`tests/test_pipeline_end_to_end.py`](tests/test_pipeline_end_to_end.py); a fresh clone should pass all of it without editing anything.

---

## Quickstart — secure platform (Docker)

```bash
cp .env.example .env
# edit .env: set SECRET_KEY and POSTGRES_PASSWORD to real random values
# (python -c "import secrets; print(secrets.token_urlsafe(48))")

python -m src.train                                # bakes a checkpoint into the backend image
mkdir -p nginx/certs
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout nginx/certs/key.pem -out nginx/certs/cert.pem -subj "/CN=localhost"

docker compose up --build
# -> https://localhost  (self-signed cert warning is expected locally)
```

Or run the backend directly without Docker for development:

```bash
cd platform/backend
pip install -r requirements.txt
uvicorn app.main:app --reload
# -> http://localhost:8000, API docs at http://localhost:8000/api/docs
```

Backend test suite (26 tests — full auth flow + explicit IDOR regression tests):
```bash
cd platform/backend && pytest tests/ -v
```

See [SECURITY.md](SECURITY.md) for the complete security design and how it maps to every item that was asked for.

---

## Architecture

Full details in [`docs/architecture.md`](docs/architecture.md). In brief:

```
Traffic (flow + packet) → Feature Extraction → State Encoder → Transition Model
                                                  (MLP+AE)      (BiLSTM+Attention)
                                                                       │
                                                              K-Step Rollout
                                                                       │
                                        ┌──────────────────────────────┼──────────────────────┐
                                        ▼                              ▼                      ▼
                              ATT&CK Stage Mapper          SHAP + Attention Explain    Infiltration
                              (rule-based × clustering)     (feature & time attrib.)   Probability Curve
                                        │                              │
                                        └──────────────┬───────────────┘
                                                        ▼
                                    RAG-Grounded Decision Support (src/rag/)
                                    retrieves matching MITRE ATT&CK techniques
                                    from a local knowledge base (BM25, fully offline)
                                    and composes a grounded, cited explanation
                                                        │
                              ┌─────────────────────────┴─────────────────────────┐
                              ▼                                                   ▼
                    Offline Streamlit demo                          Secure platform API
                    (app/streamlit_app.py)                          (platform/backend/)
                                                                     → multi-analyst dashboard
                                                                     → optional LLM narration
```

## RAG — where and why

Retrieval-augmented generation is used specifically where the problem statement asks for **"interpretable decision support for defenders"** (`src/rag/`):

- **Knowledge base** (`src/rag/attck_knowledge_base.json`): curated MITRE ATT&CK techniques across the five kill-chain stages this project forecasts, with network signatures and mitigations.
- **Retrieval** (`src/rag/retriever.py`): BM25 lexical search — chosen deliberately over neural embeddings, which would require downloading a model and would break the "fully offline, zero outbound network calls" requirement for the core system. See `docs/architecture.md` for the full justification.
- **Generation** (`src/rag/copilot.py`): a grounded, template-composed explanation — every sentence traces to a SHAP value, an attention weight, or a retrieved technique. No hallucination risk because nothing is free-form.
- **Platform enhancement** (`platform/backend/app/services/rag_service.py`): the deployed platform can *optionally* narrate that same grounded evidence in fuller prose via an LLM call, server-side only, only if `ANTHROPIC_API_KEY` is configured — never required, never replacing the grounded evidence itself.

## Repository layout

```
nexusai-forecast/
├── src/                  # the World Model pipeline (features, models, explainability, RAG)
├── app/streamlit_app.py  # offline demo dashboard
├── configs/default.yaml  # every hyperparameter, one place
├── data/                 # datasets go here (git-ignored) — see data/README.md
├── notebooks/            # exploration notebook
├── tests/                # end-to-end pipeline tests
├── docs/                 # architecture doc, demo script
├── platform/             # secure multi-analyst SOC web platform (see platform/README.md)
│   ├── backend/          # FastAPI: auth, IDOR-safe API, rate limiting, audit logging
│   └── frontend/         # server-rendered dashboard (login, forecasts, copilot)
├── docker-compose.yml    # nginx (TLS) + backend + postgres + redis
├── SECURITY.md           # the full security design — read this
└── ARCHITECTURE.md       # 2-page architecture summary (required deliverable)
```

## Required deliverables checklist

Per the project's own problem-statement documentation (`SIH_Idea.docx` §13):

- [x] Source code — this repository
- [x] README — this file
- [x] Architecture document — [`ARCHITECTURE.md`](ARCHITECTURE.md)
- [x] Demo video script — [`docs/demo_script.md`](docs/demo_script.md) (record separately, ≤2 min)
- [ ] Technical presentation (≤5 slides) — outline in `docs/demo_script.md`; build the deck from it
