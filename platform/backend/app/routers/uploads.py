<<<<<<< HEAD
# Author: Avinash Krishna — Team AVV Elites (SIH26153)
=======
>>>>>>> 77949f2bb89fea05df3ee4faf24abd4771ef1671
"""
platform/backend/app/routers/uploads.py
SECURITY.md ref: §6 (upload validation) and §4 (rate limiting on generation-
triggering endpoints — every upload here runs inference, which is the
"AI generation request" the abuse-protection requirement names explicitly).
"""
from __future__ import annotations

import io

import pandas as pd
from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile, status
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import get_db
from app.deps import get_current_verified_user, owned_or_404
from app.middleware import log_audit_event
from app.models import Forecast, NetworkSegment, User
from app.rate_limit import limiter
from app.schemas import ForecastCreate, ForecastResponse
from app.services import ml_bridge

router = APIRouter(tags=["uploads"])

settings = get_settings()


def _validate_upload(file: UploadFile, raw_bytes: bytes) -> None:
    suffix = "." + file.filename.rsplit(".", 1)[-1].lower() if file.filename and "." in file.filename else ""
    if suffix not in settings.allowed_upload_extensions:
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail=f"Unsupported file type '{suffix}'. Allowed: {', '.join(settings.allowed_upload_extensions)}",
        )
    size_mb = len(raw_bytes) / (1024 * 1024)
    if size_mb > settings.max_upload_mb:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File is {size_mb:.1f} MB, exceeds the {settings.max_upload_mb} MB limit.",
        )
    if suffix == ".csv":
        # Sniff the first bytes rather than trusting the extension alone —
        # a defence-in-depth check against a disguised-content upload
        # (SECURITY.md §6: "reject invalid data ... enforce strict input
        # types", which starts with confirming the bytes are what the
        # filename claims before pandas ever touches them).
        head = raw_bytes[:4096].decode("utf-8", errors="replace")
        if "\x00" in head:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                 detail="File does not appear to be valid text/CSV.")


@router.post("/segments/{segment_id}/forecasts", response_model=ForecastResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit(get_settings().upload_rate_limit)
async def upload_and_forecast(
    request: Request,
    segment_id: str,
    body: ForecastCreate,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_verified_user),
):
    """Upload traffic for one host in `segment_id`, run the World Model
    pipeline, and persist the result as a Forecast scoped to the caller's
    organization. `segment_id` ownership is checked BEFORE the (expensive)
    ML inference call runs, so an IDOR attempt is rejected cheaply rather
    than after paying for a SHAP explanation nobody is allowed to see."""
    if segment_id != body.network_segment_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="segment_id path/body mismatch.")
    owned_or_404(db, NetworkSegment, segment_id, current_user)  # IDOR check, cheap, first

    raw_bytes = await file.read()
    _validate_upload(file, raw_bytes)

    try:
        df = pd.read_csv(io.BytesIO(raw_bytes), nrows=200_000)  # hard cap even within the size limit
    except Exception:
        log_audit_event("upload_rejected", user_id=current_user.id, organization_id=current_user.organization_id,
                         detail="unparseable CSV")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Could not parse this file as CSV.")

    if "src_ip" not in df.columns:
        df["src_ip"] = body.host_identifier  # single-host upload convenience: caller may omit the column entirely

    try:
        result = ml_bridge.run_inference(df, host_id=body.host_identifier)
    except ml_bridge.MLPipelineUnavailable as e:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    forecast = Forecast(
        organization_id=current_user.organization_id, network_segment_id=segment_id,
        host_identifier=body.host_identifier, predicted_stage=result["predicted_stage"],
        stage_confidence=result["stage_confidence"], cross_validated=result["cross_validated"],
        infiltration_probabilities=result["infiltration_probabilities"], explanation=result["explanation"],
        created_by=current_user.id,
    )
    db.add(forecast)
    db.commit()
    db.refresh(forecast)

    log_audit_event("forecast_created", user_id=current_user.id, organization_id=current_user.organization_id,
                     detail=f"segment={segment_id} host={body.host_identifier} stage={result['predicted_stage']}")
    return forecast


@router.post("/segments/{segment_id}/forecasts/demo-sample", response_model=ForecastResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit(get_settings().upload_rate_limit)
def create_demo_forecast(request: Request, segment_id: str, db: Session = Depends(get_db),
                          current_user: User = Depends(get_current_verified_user)):
    """No-upload convenience endpoint using the bundled synthetic sample —
    lets a fresh deployment demo end to end before a team has real traffic
    to upload. Same IDOR check and same inference path as the real upload
    endpoint above; only the data source differs."""
    owned_or_404(db, NetworkSegment, segment_id, current_user)
    df = ml_bridge.demo_traffic_dataframe()
    host_id = str(df["src_ip"].iloc[-1])

    try:
        result = ml_bridge.run_inference(df, host_id=host_id)
    except ml_bridge.MLPipelineUnavailable as e:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(e))

    forecast = Forecast(
        organization_id=current_user.organization_id, network_segment_id=segment_id,
        host_identifier=host_id, predicted_stage=result["predicted_stage"],
        stage_confidence=result["stage_confidence"], cross_validated=result["cross_validated"],
        infiltration_probabilities=result["infiltration_probabilities"], explanation=result["explanation"],
        created_by=current_user.id,
    )
    db.add(forecast)
    db.commit()
    db.refresh(forecast)
    return forecast
