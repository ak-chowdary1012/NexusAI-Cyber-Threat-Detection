# Author: Avinash Krishna — Team AVV Elites (SIH26153)
"""
platform/backend/app/models.py
SECURITY.md ref: §2 (IDOR prevention) — every resource below carries an
organization_id foreign key, and every router query filters on it (see
app/deps.py::owned_or_404). This is what makes "does the logged-in user own
this row" a structural property of the schema, not a rule someone has to
remember to apply in every handler.
"""
from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    JSON, Boolean, DateTime, Enum, ForeignKey, Integer, String, Text, UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


def _uuid() -> str:
    return str(uuid.uuid4())


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class UserRole(str, enum.Enum):
    analyst = "analyst"
    admin = "admin"


class Organization(Base):
    __tablename__ = "organizations"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(200), unique=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    users: Mapped[list["User"]] = relationship(back_populates="organization")


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), nullable=False, index=True)

    email: Mapped[str] = mapped_column(String(320), unique=True, nullable=False, index=True)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[str] = mapped_column(String(200), nullable=False)
    role: Mapped[UserRole] = mapped_column(Enum(UserRole), default=UserRole.analyst, nullable=False)

    is_active: Mapped[bool] = mapped_column(Boolean, default=True)      # admin-disable switch
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False)   # email verification gate (SECURITY.md §1)

    # Account-level lockout, defense-in-depth alongside the IP-based rate
    # limiter on the /login route (SECURITY.md §1 and §4) — an IP limiter
    # alone doesn't stop credential stuffing spread across many source IPs.
    failed_login_attempts: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    organization: Mapped["Organization"] = relationship(back_populates="users")


class RefreshToken(Base):
    """Opaque refresh tokens, stored hashed (never plaintext) — see
    security.py::generate_opaque_token. Individually revocable, which a pure
    stateless-JWT refresh scheme cannot offer (SECURITY.md §1: sessions expire
    *and* can be forcibly ended, e.g. on logout or suspected compromise)."""
    __tablename__ = "refresh_tokens"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    lookup_prefix: Mapped[str] = mapped_column(String(12), nullable=False, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    user_agent: Mapped[str | None] = mapped_column(String(400), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)


class EmailVerificationToken(Base):
    __tablename__ = "email_verification_tokens"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    lookup_prefix: Mapped[str] = mapped_column(String(12), nullable=False, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    lookup_prefix: Mapped[str] = mapped_column(String(12), nullable=False, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class NetworkSegment(Base):
    """One monitored network segment — matches the docs' "deployable
    incrementally, piloted on one network segment" rollout model."""
    __tablename__ = "network_segments"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    __table_args__ = (UniqueConstraint("organization_id", "name", name="uq_segment_name_per_org"),)


class Forecast(Base):
    """A single World Model forecast result. The resource IDOR tests in
    tests/test_idor.py target this table specifically — it's the one an
    analyst from another organization must never be able to read, list, or
    delete, per the explicit requirement in SECURITY.md §2."""
    __tablename__ = "forecasts"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), nullable=False, index=True)
    network_segment_id: Mapped[str] = mapped_column(ForeignKey("network_segments.id"), nullable=False, index=True)
    host_identifier: Mapped[str] = mapped_column(String(100), nullable=False)

    predicted_stage: Mapped[str] = mapped_column(String(50), nullable=False)
    stage_confidence: Mapped[float] = mapped_column(nullable=False)
    cross_validated: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    infiltration_probabilities: Mapped[dict] = mapped_column(JSON, nullable=False)  # {"1_min": 0.2, ...}
    explanation: Mapped[dict] = mapped_column(JSON, nullable=False)  # serialized CopilotExplanation

    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)


class AuditLog(Base):
    """Structured audit trail: authentication attempts, API errors, and
    upload/copilot activity (SECURITY.md §3: logging for authentication
    attempts, API errors, and unusual traffic patterns). Deliberately a
    separate table from application logs (which go to stdout/JSON, see
    app/middleware.py) so security-relevant events survive independently of
    log rotation/aggregation configuration and can be queried directly."""
    __tablename__ = "audit_logs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    event_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    # e.g. login_success, login_failure, register, email_verified,
    # password_reset_requested, password_reset_completed, rate_limited,
    # idor_denied, api_error, upload_rejected
    user_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    organization_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)
