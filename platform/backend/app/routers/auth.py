"""
platform/backend/app/routers/auth.py
SECURITY.md ref: §1 in full — this router is the authentication system.

Every endpoint here writes an AuditLog row AND emits a structured log line
(app.middleware.log_audit_event) — auth attempts are exactly what
SECURITY.md §3 requires visibility into, and this is where they happen.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import get_db
from app.deps import get_current_user
from app.middleware import log_audit_event
from app.models import AuditLog, EmailVerificationToken, Organization, PasswordResetToken, RefreshToken, User
from app.rate_limit import limiter
from app.schemas import (
    ForgotPasswordRequest, LoginRequest, RefreshRequest, RegisterRequest,
    ResetPasswordRequest, TokenResponse, UserResponse, VerifyEmailRequest,
)
from app.security import (
    create_access_token, ensure_utc, generate_opaque_token, hash_opaque_token, hash_password,
    needs_rehash, verify_password,
)
from app.services.email_service import send_password_reset_email, send_verification_email

router = APIRouter(prefix="/auth", tags=["auth"])

_LOCKOUT_THRESHOLD = 8          # consecutive failures before an account-level lockout kicks in
_LOCKOUT_DURATION = timedelta(minutes=15)
# A real, validly-formatted Argon2 hash of an unused placeholder password.
# Used only to keep the login failure path's *timing* consistent whether or
# not the submitted email exists — a malformed placeholder string would let
# passlib short-circuit before paying the real hashing cost, which would
# defeat the point (see login() below).
_DUMMY_HASH_FOR_TIMING_SAFETY = hash_password("this-is-not-a-real-account-password")


def _record_audit(db: Session, event_type: str, *, user_id: str | None, organization_id: str | None,
                   ip_address: str | None, detail: str | None) -> None:
    log_audit_event(event_type, user_id=user_id, organization_id=organization_id, ip_address=ip_address, detail=detail)
    db.add(AuditLog(event_type=event_type, user_id=user_id, organization_id=organization_id,
                     ip_address=ip_address, detail=detail))
    db.commit()


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit(get_settings().register_rate_limit)
def register(request: Request, body: RegisterRequest, db: Session = Depends(get_db)):
    """Creates the organization (if new) + first user, or a new user under an
    existing organization name. Password strength and email format are
    already enforced by RegisterRequest (schemas.py) before this body runs."""
    existing = db.query(User).filter(User.email == body.email.lower()).first()
    if existing is not None:
        # Same response whether the email is taken or not initially seems
        # tempting to hide, but registration inherently reveals this via the
        # "check your email" UX either way, and a fabricated success would
        # break password-reset for the legitimate owner's expectations — so
        # we return a clear, generic 409 rather than pretending to succeed.
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="An account with this email already exists.")

    org = db.query(Organization).filter(Organization.name == body.organization_name).first()
    if org is None:
        org = Organization(name=body.organization_name)
        db.add(org)
        db.flush()

    user = User(
        organization_id=org.id, email=body.email.lower(), hashed_password=hash_password(body.password),
        full_name=body.full_name, is_verified=False,
    )
    db.add(user)
    db.flush()

    raw_token, token_hash, prefix = generate_opaque_token()
    settings = get_settings()
    db.add(EmailVerificationToken(
        user_id=user.id, token_hash=token_hash, lookup_prefix=prefix,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=settings.email_verification_token_expire_hours),
    ))
    db.commit()
    db.refresh(user)

    send_verification_email(user.email, raw_token, base_url=str(request.base_url).rstrip("/"))
    _record_audit(db, "register", user_id=user.id, organization_id=org.id,
                  ip_address=request.client.host if request.client else None, detail=None)
    return user


@router.post("/verify-email", response_model=UserResponse)
def verify_email(body: VerifyEmailRequest, db: Session = Depends(get_db)):
    token_hash = hash_opaque_token(body.token)
    record = db.query(EmailVerificationToken).filter(EmailVerificationToken.token_hash == token_hash).first()
    if record is None or record.used_at is not None or ensure_utc(record.expires_at) < datetime.now(timezone.utc):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired verification link.")

    user = db.get(User, record.user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired verification link.")

    user.is_verified = True
    record.used_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(user)
    _record_audit(db, "email_verified", user_id=user.id, organization_id=user.organization_id, ip_address=None, detail=None)
    return user


@router.post("/login", response_model=TokenResponse)
@limiter.limit(get_settings().login_rate_limit)  # IP-based limiter
def login(request: Request, body: LoginRequest, db: Session = Depends(get_db)):
    """SECURITY.md §1: rate-limited (IP, via the decorator above) AND
    account-locked after repeated failures (below) — two independent
    mechanisms because they defend against two different attack shapes (one
    IP hammering one account, vs many IPs hammering one account)."""
    settings = get_settings()
    client_ip = request.client.host if request.client else None
    generic_error = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect email or password.")

    user = db.query(User).filter(User.email == body.email.lower()).first()

    if user is not None and user.locked_until and ensure_utc(user.locked_until) > datetime.now(timezone.utc):
        _record_audit(db, "login_failure", user_id=user.id, organization_id=user.organization_id,
                      ip_address=client_ip, detail="account locked")
        raise HTTPException(status_code=status.HTTP_423_LOCKED,
                             detail=f"Account temporarily locked due to repeated failed attempts. Try again later.")

    # Constant-shape failure path: run verify_password against a real hash
    # even when the account doesn't exist, so response timing doesn't reveal
    # account existence (a classic authentication-system timing side-channel).
    password_ok = verify_password(body.password, user.hashed_password) if user else (
        verify_password(body.password, _DUMMY_HASH_FOR_TIMING_SAFETY) and False
    )

    if user is None or not password_ok:
        if user is not None:
            user.failed_login_attempts += 1
            if user.failed_login_attempts >= _LOCKOUT_THRESHOLD:
                user.locked_until = datetime.now(timezone.utc) + _LOCKOUT_DURATION
            db.commit()
        _record_audit(db, "login_failure", user_id=user.id if user else None,
                      organization_id=user.organization_id if user else None,
                      ip_address=client_ip, detail=f"email={body.email.lower()}")
        raise generic_error

    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="This account has been disabled.")
    if not user.is_verified:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Please verify your email before logging in.")

    if needs_rehash(user.hashed_password):
        user.hashed_password = hash_password(body.password)

    user.failed_login_attempts = 0
    user.locked_until = None
    user.last_login_at = datetime.now(timezone.utc)

    access_token = create_access_token(subject=user.id, extra_claims={"org": user.organization_id, "role": user.role.value})
    raw_refresh, refresh_hash, refresh_prefix = generate_opaque_token()
    db.add(RefreshToken(
        user_id=user.id, token_hash=refresh_hash, lookup_prefix=refresh_prefix,
        expires_at=datetime.now(timezone.utc) + timedelta(days=settings.refresh_token_expire_days),
        user_agent=request.headers.get("user-agent", "")[:400], ip_address=client_ip,
    ))
    db.commit()

    _record_audit(db, "login_success", user_id=user.id, organization_id=user.organization_id, ip_address=client_ip, detail=None)
    return TokenResponse(access_token=access_token, refresh_token=raw_refresh,
                          expires_in_minutes=settings.access_token_expire_minutes)


@router.post("/refresh", response_model=TokenResponse)
def refresh(body: RefreshRequest, db: Session = Depends(get_db)):
    """Refresh-token rotation: the presented token is revoked and a new one
    issued on every use. If a REVOKED token is ever presented again, that's
    a strong signal of token theft (the legitimate holder already rotated
    past it) — we revoke the entire token, and log it as a security event,
    rather than silently accepting the reuse."""
    token_hash = hash_opaque_token(body.refresh_token)
    record = db.query(RefreshToken).filter(RefreshToken.token_hash == token_hash).first()

    if record is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token.")
    if record.revoked_at is not None:
        log_audit_event("refresh_token_reuse_detected", user_id=record.user_id, detail="possible token theft")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token.")
    if ensure_utc(record.expires_at) < datetime.now(timezone.utc):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token expired, please log in again.")

    user = db.get(User, record.user_id)
    if user is None or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token.")

    record.revoked_at = datetime.now(timezone.utc)
    settings = get_settings()
    access_token = create_access_token(subject=user.id, extra_claims={"org": user.organization_id, "role": user.role.value})
    raw_refresh, refresh_hash, refresh_prefix = generate_opaque_token()
    db.add(RefreshToken(
        user_id=user.id, token_hash=refresh_hash, lookup_prefix=refresh_prefix,
        expires_at=datetime.now(timezone.utc) + timedelta(days=settings.refresh_token_expire_days),
    ))
    db.commit()
    return TokenResponse(access_token=access_token, refresh_token=raw_refresh,
                          expires_in_minutes=settings.access_token_expire_minutes)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(body: RefreshRequest, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Revokes the presented refresh token — 'sessions expire' also means a
    session can be explicitly ended, not just time out (SECURITY.md §1)."""
    token_hash = hash_opaque_token(body.refresh_token)
    record = db.query(RefreshToken).filter(
        RefreshToken.token_hash == token_hash, RefreshToken.user_id == current_user.id
    ).first()
    if record is not None:
        record.revoked_at = datetime.now(timezone.utc)
        db.commit()
    return None


@router.post("/forgot-password", status_code=status.HTTP_202_ACCEPTED)
@limiter.limit(get_settings().password_reset_rate_limit)
def forgot_password(request: Request, body: ForgotPasswordRequest, db: Session = Depends(get_db)):
    """Always returns 202 regardless of whether the email exists — this is
    the one place account-enumeration protection is more important than a
    precise error, since the whole point of this endpoint is to be safely
    callable by anyone who merely knows (or is guessing) an email address."""
    user = db.query(User).filter(User.email == body.email.lower()).first()
    if user is not None:
        raw_token, token_hash, prefix = generate_opaque_token()
        settings = get_settings()
        db.add(PasswordResetToken(
            user_id=user.id, token_hash=token_hash, lookup_prefix=prefix,
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=settings.password_reset_token_expire_minutes),
        ))
        db.commit()
        send_password_reset_email(user.email, raw_token, base_url=str(request.base_url).rstrip("/"))
        _record_audit(db, "password_reset_requested", user_id=user.id, organization_id=user.organization_id,
                      ip_address=request.client.host if request.client else None, detail=None)
    return {"detail": "If that email is registered, a reset link has been sent."}


@router.post("/reset-password", status_code=status.HTTP_204_NO_CONTENT)
def reset_password(body: ResetPasswordRequest, db: Session = Depends(get_db)):
    token_hash = hash_opaque_token(body.token)
    record = db.query(PasswordResetToken).filter(PasswordResetToken.token_hash == token_hash).first()
    if record is None or record.used_at is not None or ensure_utc(record.expires_at) < datetime.now(timezone.utc):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired reset link.")

    user = db.get(User, record.user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired reset link.")

    user.hashed_password = hash_password(body.new_password)
    record.used_at = datetime.now(timezone.utc)
    user.failed_login_attempts = 0
    user.locked_until = None

    # Password reset also revokes every existing session — if a reset was
    # needed because a password leaked, any session an attacker already
    # holds must not survive the reset.
    for rt in db.query(RefreshToken).filter(RefreshToken.user_id == user.id, RefreshToken.revoked_at.is_(None)).all():
        rt.revoked_at = datetime.now(timezone.utc)

    db.commit()
    _record_audit(db, "password_reset_completed", user_id=user.id, organization_id=user.organization_id,
                  ip_address=None, detail=None)
    return None


@router.get("/me", response_model=UserResponse)
def me(current_user: User = Depends(get_current_user)):
    return current_user
