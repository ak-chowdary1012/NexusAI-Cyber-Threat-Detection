# Author: Avinash Krishna — Team AVV Elites (SIH26153)
"""
platform/backend/app/deps.py
SECURITY.md ref: §2 — this module is the single choke point every
ownership-sensitive route must pass through. owned_or_404() is the one
function that decides whether the logged-in user is allowed to touch a
given row; routers never write their own ad hoc "if resource.org_id ==
user.org_id" check inline, specifically so that check can't be forgotten or
written slightly wrong in one particular handler.
"""
from __future__ import annotations

from typing import TypeVar

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User
from app.security import decode_access_token

_bearer_scheme = HTTPBearer(auto_error=False)

ModelT = TypeVar("ModelT")


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
    db: Session = Depends(get_db),
) -> User:
    """Resolves the bearer JWT to a User row. Every check below is a reason
    to reject with the *same* 401 (never leaking which specific check
    failed — token missing vs expired vs user deleted are indistinguishable
    to the caller, which avoids handing an attacker a user-enumeration or
    token-validity oracle)."""
    unauthorized = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials")
    if credentials is None:
        raise unauthorized
    payload = decode_access_token(credentials.credentials)
    if payload is None:
        raise unauthorized
    user = db.get(User, payload.get("sub"))
    if user is None or not user.is_active:
        raise unauthorized
    return user


def get_current_verified_user(user: User = Depends(get_current_user)) -> User:
    """Stricter dependency for routes that must not be usable by an
    unverified account even if somehow holding a valid access token (e.g.
    forecast creation) — see SECURITY.md §1."""
    if not user.is_verified:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Email not verified")
    return user


def owned_or_404(db: Session, model: type[ModelT], resource_id: str, current_user: User) -> ModelT:
    """The IDOR guard (SECURITY.md §2). Looks up `model` by primary key AND
    organization_id in the SAME query — a row belonging to another
    organization is indistinguishable from a row that doesn't exist, which
    is deliberate: returning 403 instead of 404 would confirm to an attacker
    that a given resource_id exists, just not theirs (an enumeration leak of
    its own). Every resource router (forecasts.py, uploads.py, ...) calls
    this instead of `db.get(model, resource_id)` — a bare db.get() by
    primary key alone is precisely the IDOR bug this project was asked to
    rule out.
    """
    row = (
        db.query(model)
        .filter(model.id == resource_id, model.organization_id == current_user.organization_id)
        .first()
    )
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"{model.__name__} not found")
    return row
