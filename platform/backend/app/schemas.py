# Author: Avinash Krishna — Team AVV Elites (SIH26153)
"""
platform/backend/app/schemas.py
SECURITY.md ref: §6 — every API input is validated through one of these
schemas (explicit types, length limits, and format constraints) rather than
accepted as a raw dict. FastAPI rejects any request that doesn't match with
a 422 before a single line of handler code runs.
"""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator


def _check_password_strength(v: str) -> str:
    # Length (>=12, enforced by each field's Field(min_length=12)) is the
    # dominant factor per NIST 800-63B, but we also reject a few classes of
    # trivially-guessable passwords a length check alone lets through.
    if v.lower() == v or v.upper() == v:
        raise ValueError("Password must mix uppercase and lowercase characters.")
    if not any(c.isdigit() for c in v):
        raise ValueError("Password must include at least one digit.")
    if v.lower() in {"password123!", "changeme123!", "qwerty123456"}:
        raise ValueError("This password is too common. Please choose another.")
    return v


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)
    full_name: str = Field(min_length=1, max_length=200)
    organization_name: str = Field(min_length=1, max_length=200)

    _validate_password = field_validator("password")(_check_password_strength)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in_minutes: int


class RefreshRequest(BaseModel):
    refresh_token: str = Field(min_length=1, max_length=500)


class VerifyEmailRequest(BaseModel):
    token: str = Field(min_length=1, max_length=500)


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token: str = Field(min_length=1, max_length=500)
    new_password: str = Field(min_length=12, max_length=128)

    _validate_password = field_validator("new_password")(_check_password_strength)


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    email: EmailStr
    full_name: str
    role: str
    organization_id: str
    is_verified: bool
    created_at: datetime


# ---------------------------------------------------------------------------
# Network segments & forecasts
# ---------------------------------------------------------------------------

class NetworkSegmentCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=2000)


class NetworkSegmentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    name: str
    description: str | None
    created_at: datetime


class ForecastCreate(BaseModel):
    network_segment_id: str = Field(min_length=1, max_length=36)
    host_identifier: str = Field(min_length=1, max_length=100, pattern=r"^[A-Za-z0-9\.\:_-]+$")
    # strict pattern: an IP/hostname-shaped identifier only — this field is
    # rendered back to the analyst in the dashboard, so constraining its
    # character set is a second, independent layer against script injection
    # beyond template auto-escaping (see platform/README.md § defense in depth).


class ForecastResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    network_segment_id: str
    host_identifier: str
    predicted_stage: str
    stage_confidence: float
    cross_validated: bool | None
    infiltration_probabilities: dict
    explanation: dict
    created_at: datetime


# ---------------------------------------------------------------------------
# Copilot (RAG)
# ---------------------------------------------------------------------------

class CopilotRequest(BaseModel):
    forecast_id: str = Field(min_length=1, max_length=36)
    question: str | None = Field(default=None, max_length=1000)

    @field_validator("question")
    @classmethod
    def _strip_control_chars(cls, v: str | None) -> str | None:
        if v is None:
            return v
        # strip non-printable/control characters — cheap, defence-in-depth
        # input sanitization independent of output-side escaping.
        cleaned = "".join(ch for ch in v if ch.isprintable())
        return cleaned.strip()


class CopilotResponse(BaseModel):
    headline: str
    evidence_bullets: list[str]
    retrieved_techniques: list[dict]
    recommended_actions: list[str]
    llm_narration: str | None = None  # populated only if ANTHROPIC_API_KEY is configured server-side
