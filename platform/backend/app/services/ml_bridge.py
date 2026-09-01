"""
platform/backend/app/services/ml_bridge.py

Thin bridge between the FastAPI platform and the ml_core World Model
pipeline (../../../src/*). Deliberately thin: every actual modeling decision
(architecture, feature engineering, rollout logic) lives in src/ and is
shared, unmodified, with the offline Streamlit demo — this file only loads
checkpoints once and exposes a single run_inference() call so routers never
import torch or reach into src/ directly.

Path setup: the platform is a sibling directory to src/ at the repo root
(nexusai-forecast/{src,platform}/), so we add the repo root to sys.path once
at import time rather than requiring the team to `pip install -e .` the
ml_core package for the platform to run — keeps `docker build` for
platform/backend simple (see Dockerfile) without vendoring a copy of src/.
"""
from __future__ import annotations

import pickle
import sys
from functools import lru_cache
from pathlib import Path

import numpy as np
import pandas as pd
import torch

_REPO_ROOT = Path(__file__).resolve().parents[4]  # platform/backend/app/services/ml_bridge.py -> repo root
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from src.explain.attention_viz import summarize_attention  # noqa: E402
from src.explain.shap_explainer import ShapExplainer  # noqa: E402
from src.features.windowing import FUSED_FEATURE_NAMES, build_sequences  # noqa: E402
from src.models.attck_mapper import map_trajectory_to_stage  # noqa: E402
from src.models.rollout import k_step_rollout  # noqa: E402
from src.models.state_encoder import StateEncoder  # noqa: E402
from src.models.transition_model import TransitionModel  # noqa: E402
from src.rag.copilot import explain as rag_explain, explanation_to_dict  # noqa: E402
from src.rag.knowledge_base import KnowledgeBase  # noqa: E402
from src.rag.retriever import AttckRetriever  # noqa: E402
from src.synthetic_data import generate_synthetic_dataset  # noqa: E402
from src.utils import load_config, resolve_path  # noqa: E402

from app.utils_logging import get_logger

logger = get_logger(__name__)


class MLPipelineUnavailable(RuntimeError):
    """Raised when checkpoints haven't been trained yet — routers turn this
    into a clear 503 rather than a bare 500 traceback."""


@lru_cache
def _load_pipeline():
    cfg = load_config()
    ckpt_dir = resolve_path(cfg["paths"]["checkpoint_dir"])
    if not (ckpt_dir / "state_encoder.pt").exists():
        raise MLPipelineUnavailable(
            f"No checkpoints in {ckpt_dir}. Run `python -m src.train` from the repo root first."
        )

    encoder = StateEncoder(cfg)
    encoder.load_state_dict(torch.load(ckpt_dir / "state_encoder.pt", map_location="cpu"))
    encoder.eval()

    transition = TransitionModel(cfg)
    transition.load_state_dict(torch.load(ckpt_dir / "transition_model.pt", map_location="cpu"))
    transition.eval()

    norm = np.load(ckpt_dir / "normalization.npz")

    cluster_mapper = None
    if (ckpt_dir / "cluster_mapper.pkl").exists():
        with open(ckpt_dir / "cluster_mapper.pkl", "rb") as f:
            cluster_mapper = pickle.load(f)

    kb = KnowledgeBase.load()
    retriever = AttckRetriever(kb)

    return cfg, encoder, transition, norm, cluster_mapper, retriever


def pipeline_ready() -> bool:
    try:
        _load_pipeline()
        return True
    except MLPipelineUnavailable:
        return False


def run_inference(traffic_df: pd.DataFrame, host_id: str) -> dict:
    """Runs the full pipeline for one host and returns a JSON-serializable
    dict shaped for schemas.ForecastResponse / the Forecast ORM row.
    traffic_df must contain FUSED_FEATURE_NAMES columns plus src_ip/window_start
    (i.e. already through windowing.aggregate_flows_to_windows /
    join_flow_and_packet_windows upstream, or the bundled synthetic shape).
    """
    cfg, encoder, transition, norm, cluster_mapper, retriever = _load_pipeline()
    feat_mean, feat_std = norm["mean"], norm["std"]

    missing = [c for c in FUSED_FEATURE_NAMES if c not in traffic_df.columns]
    if missing:
        raise ValueError(f"traffic data missing required feature columns: {missing}")

    df_norm = traffic_df.copy()
    df_norm[FUSED_FEATURE_NAMES] = (
        traffic_df[FUSED_FEATURE_NAMES].to_numpy(dtype=np.float32) - feat_mean
    ) / feat_std

    seq_len = cfg["windowing"]["sequence_length"]
    X_seq, _, host_ids = build_sequences(df_norm, sequence_length=seq_len, host_key="src_ip", label_col=None)
    if len(X_seq) == 0 or host_id not in host_ids:
        raise ValueError(
            f"Not enough consecutive windows for host {host_id!r} to build a "
            f"{seq_len}-window sequence (need >= {seq_len} windows of history)."
        )
    idx = host_ids.index(host_id)

    sample = torch.tensor(X_seq[idx: idx + 1], dtype=torch.float32)
    with torch.no_grad():
        state_seq = encoder.encode_sequence(sample)
        class_probs = encoder.mlp.class_probabilities(sample[:, -1, :])

    rollout_result = k_step_rollout(
        transition, state_seq, k_steps=cfg["rollout"]["k_steps"], horizon_minutes=cfg["rollout"]["horizon_minutes"]
    )

    last_raw_features = X_seq[idx, -1, :]
    latent = state_seq[0, -1, :].numpy()
    stage_result = map_trajectory_to_stage(last_raw_features, latent, cluster_mapper)

    background = X_seq[:, -1, :][: min(30, len(X_seq))]
    explainer = ShapExplainer(encoder, background, feature_names=FUSED_FEATURE_NAMES)
    pred_class = int(class_probs.argmax(dim=-1).item())
    shap_result = explainer.explain_window(last_raw_features, predicted_class_idx=pred_class, nsamples=60)

    attn_summary = summarize_attention(rollout_result.final_attention_weights, cfg["windowing"]["window_seconds"])

    infiltration_probs = {
        f"{m}_min": p for m, p in zip(cfg["rollout"]["horizon_minutes"], rollout_result.infiltration_probs)
    }
    stage_confidence = 0.9 if stage_result["cross_validated"] else (0.55 if stage_result["cross_validated"] is False else 0.75)

    explanation = rag_explain(
        predicted_stage=stage_result["final_stage"], stage_confidence=stage_confidence,
        infiltration_probs=infiltration_probs, top_shap_features=shap_result["top_features"],
        attention_summary=attn_summary, retriever=retriever, host_id=host_id,
    )

    return {
        "predicted_stage": stage_result["final_stage"],
        "stage_confidence": stage_confidence,
        "cross_validated": stage_result["cross_validated"],
        "infiltration_probabilities": infiltration_probs,
        "explanation": explanation_to_dict(explanation),
    }


def demo_traffic_dataframe() -> pd.DataFrame:
    """Bundled synthetic sample, used by the /uploads/demo-sample endpoint so
    a fresh platform deployment has something to show before a team plugs in
    real traffic — same generator the offline Streamlit app and tests use,
    so numbers are consistent across every surface."""
    return generate_synthetic_dataset(n_hosts_per_stage=2, windows_per_host=30, n_benign_hosts=3)
