"""
platform/backend/app/routers/forecasts.py
SECURITY.md ref: §2 in full. Every read, list, and delete below either
filters by current_user.organization_id directly in the query, or goes
through deps.owned_or_404 — there is no code path in this file that fetches
a NetworkSegment or Forecast by primary key alone.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.deps import get_current_verified_user, owned_or_404
from app.models import Forecast, NetworkSegment, User
from app.schemas import ForecastResponse, NetworkSegmentCreate, NetworkSegmentResponse

router = APIRouter(tags=["forecasts"])


@router.post("/segments", response_model=NetworkSegmentResponse, status_code=status.HTTP_201_CREATED)
def create_segment(body: NetworkSegmentCreate, db: Session = Depends(get_db),
                    current_user: User = Depends(get_current_verified_user)):
    existing = db.query(NetworkSegment).filter(
        NetworkSegment.organization_id == current_user.organization_id, NetworkSegment.name == body.name
    ).first()
    if existing is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="A segment with this name already exists.")
    segment = NetworkSegment(
        organization_id=current_user.organization_id, name=body.name,
        description=body.description, created_by=current_user.id,
    )
    db.add(segment)
    db.commit()
    db.refresh(segment)
    return segment


@router.get("/segments", response_model=list[NetworkSegmentResponse])
def list_segments(db: Session = Depends(get_db), current_user: User = Depends(get_current_verified_user)):
    # Scoped by organization_id directly in the query — the IDOR-safe
    # equivalent of "list my stuff" (there is no unscoped list-all route).
    return db.query(NetworkSegment).filter(NetworkSegment.organization_id == current_user.organization_id).all()


@router.get("/segments/{segment_id}", response_model=NetworkSegmentResponse)
def get_segment(segment_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_verified_user)):
    return owned_or_404(db, NetworkSegment, segment_id, current_user)


@router.delete("/segments/{segment_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_segment(segment_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_verified_user)):
    segment = owned_or_404(db, NetworkSegment, segment_id, current_user)
    db.delete(segment)
    db.commit()
    return None


@router.get("/forecasts", response_model=list[ForecastResponse])
def list_forecasts(segment_id: str | None = None, limit: int = 50, db: Session = Depends(get_db),
                    current_user: User = Depends(get_current_verified_user)):
    limit = max(1, min(limit, 200))  # server-side cap regardless of what the client asks for
    query = db.query(Forecast).filter(Forecast.organization_id == current_user.organization_id)
    if segment_id is not None:
        # Confirm the caller's own org actually owns this segment before
        # filtering by it — otherwise segment_id becomes a second, easier
        # IDOR vector even though the outer query is already org-scoped
        # (an attacker could still use another org's segment_id purely to
        # probe whether it exists via an empty-vs-error response shape).
        owned_or_404(db, NetworkSegment, segment_id, current_user)
        query = query.filter(Forecast.network_segment_id == segment_id)
    return query.order_by(Forecast.created_at.desc()).limit(limit).all()


@router.get("/forecasts/{forecast_id}", response_model=ForecastResponse)
def get_forecast(forecast_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_verified_user)):
    return owned_or_404(db, Forecast, forecast_id, current_user)


@router.delete("/forecasts/{forecast_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_forecast(forecast_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_verified_user)):
    forecast = owned_or_404(db, Forecast, forecast_id, current_user)
    db.delete(forecast)
    db.commit()
    return None
