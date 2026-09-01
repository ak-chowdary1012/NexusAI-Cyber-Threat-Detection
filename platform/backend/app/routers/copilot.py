# Author: Avinash Krishna — Team AVV Elites (SIH26153)
"""
platform/backend/app/routers/copilot.py
SECURITY.md ref: §4 — "AI generation requests" rate limiting, applied here
specifically since this is the one endpoint that may call an external LLM
API (rag_service.narrate, only when ANTHROPIC_API_KEY is configured).
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import get_db
from app.deps import get_current_verified_user, owned_or_404
from app.models import Forecast, User
from app.rate_limit import limiter
from app.schemas import CopilotRequest, CopilotResponse
from app.services import rag_service

router = APIRouter(tags=["copilot"])


@router.post("/copilot/explain", response_model=CopilotResponse)
@limiter.limit(get_settings().copilot_rate_limit)
def explain_forecast(request: Request, body: CopilotRequest, db: Session = Depends(get_db),
                      current_user: User = Depends(get_current_verified_user)):
    """Returns the grounded explanation already computed and stored at
    forecast-creation time (ml_bridge.run_inference) — this endpoint does
    not re-run the ML pipeline, only the (optional) LLM narration step, so
    its cost/abuse profile is deliberately much cheaper than the upload
    endpoint despite sharing the same per-minute rate-limit class."""
    forecast = owned_or_404(db, Forecast, body.forecast_id, current_user)
    explanation = dict(forecast.explanation)

    narration = rag_service.narrate(explanation)
    return CopilotResponse(
        headline=explanation["headline"],
        evidence_bullets=explanation["evidence_bullets"],
        retrieved_techniques=explanation["retrieved_techniques"],
        recommended_actions=explanation["recommended_actions"],
        llm_narration=narration,
    )
