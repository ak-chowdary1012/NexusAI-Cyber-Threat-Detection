<<<<<<< HEAD
# Author: Avinash Krishna — Team AVV Elites (SIH26153)
=======
>>>>>>> 77949f2bb89fea05df3ee4faf24abd4771ef1671
"""
platform/backend/app/services/rag_service.py
Architecture ref: docs/architecture.md § 4.8 RAG-Grounded Decision Support (platform enhancement)

The offline, template-composed explanation from src/rag/copilot.py (via
ml_bridge.run_inference) is always returned as-is — it is never replaced,
only optionally *narrated* in fuller prose by an LLM call, and only when
ANTHROPIC_API_KEY is configured server-side (never sent to, or readable by,
the frontend — see config.py and SECURITY.md §5). This keeps the retrieval
step doing the actual grounding (every technique ID and mitigation the LLM
narrates comes from the same retrieved KB entries, passed to it as context)
so the LLM cannot introduce an ungrounded claim about a specific technique —
it can only choose how to phrase the ones retrieval already selected.

If no API key is configured, `llm_narration` is simply omitted from the
response — this is an enhancement, never a hard dependency (the copilot
endpoint fully works without it, satisfying the offline-capable design goal
even for the deployed platform).
"""
from __future__ import annotations

import json

import httpx

from app.config import get_settings
from app.utils_logging import get_logger

logger = get_logger(__name__)

_ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
_ANTHROPIC_VERSION = "2023-06-01"
_MODEL = "claude-sonnet-4-6"


def narrate(explanation: dict) -> str | None:
    """explanation is the dict produced by src.rag.copilot.explanation_to_dict
    — i.e. already-retrieved, already-grounded evidence. Returns a short
    analyst-facing paragraph, or None if no API key is configured or the
    call fails (failure here must never break the copilot endpoint — the
    ungrounded-generation risk of an LLM call is exactly why the structured,
    retrieval-only explanation above is always returned regardless)."""
    settings = get_settings()
    if not settings.anthropic_api_key:
        return None

    system_prompt = (
        "You are a SOC analyst assistant. You will be given ALREADY-RETRIEVED, "
        "grounded evidence (a headline, evidence bullets, retrieved MITRE ATT&CK "
        "techniques, and recommended actions). Write a concise 2-4 sentence "
        "narration for a busy analyst. Use ONLY the facts provided — do not "
        "invent technique IDs, statistics, or mitigations not present in the "
        "input. If the input is thin, say so briefly rather than filling gaps."
    )
    user_prompt = json.dumps(explanation)

    try:
        response = httpx.post(
            _ANTHROPIC_URL,
            headers={
                "x-api-key": settings.anthropic_api_key,
                "anthropic-version": _ANTHROPIC_VERSION,
                "content-type": "application/json",
            },
            json={
                "model": _MODEL,
                "max_tokens": 300,
                "system": system_prompt,
                "messages": [{"role": "user", "content": user_prompt}],
            },
            timeout=15.0,
        )
        response.raise_for_status()
        data = response.json()
        text_blocks = [b["text"] for b in data.get("content", []) if b.get("type") == "text"]
        return "\n".join(text_blocks).strip() or None
    except Exception:
        logger.exception("LLM narration call failed — falling back to retrieval-only explanation")
        return None
