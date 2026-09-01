"""
src/explain/attention_viz.py
Architecture ref: docs/architecture.md § 4.6 Explainability (attention half)

Surfaces the transition model's self-attention weights as the second,
complementary explanation channel: "which recent minutes were driving this
forecast," as opposed to SHAP's "which traffic features were driving this
classification." Both are attached to every prediction — see
src/rag/copilot.py, which turns this and shap_explainer's output into an
analyst-facing sentence instead of a raw weight matrix.
"""
from __future__ import annotations

import numpy as np


def summarize_attention(attn_weights: np.ndarray, window_seconds: float = 30.0) -> dict:
    """attn_weights: (T, T) self-attention matrix from TransitionModel.forward()
    (already averaged over heads by nn.MultiheadAttention). Returns which past
    timesteps the *final* timestep (i.e. "now") attended to most — that row of
    the matrix is what explains the current forecast.

    minutes_ago is reported as a human-readable offset (e.g. "2.5 min ago")
    because "attention on index 17" means nothing to a SOC analyst.
    """
    T = attn_weights.shape[0]
    now_row = attn_weights[-1, :]  # how much the most recent timestep attends to each past timestep
    order = np.argsort(-now_row)

    ranked = []
    for idx in order:
        steps_ago = (T - 1) - int(idx)
        minutes_ago = round(steps_ago * window_seconds / 60.0, 1)
        ranked.append({
            "window_index": int(idx),
            "minutes_ago": minutes_ago,
            "attention_weight": float(now_row[idx]),
        })

    return {
        "top_attended_windows": ranked[:5],
        "attention_entropy": float(-np.sum(now_row * np.log(now_row + 1e-9))),
        # low entropy = attention sharply focused on one or two moments
        # (a clear trigger); high entropy = diffuse, slow-building pattern —
        # both are meaningful and worth stating to the analyst explicitly.
    }


def attention_heatmap_data(attn_weights: np.ndarray) -> dict:
    """Raw (T, T) matrix plus axis labels, shaped for direct consumption by
    the Streamlit/React heatmap component — kept separate from
    summarize_attention() so callers that just want the top-5 explanation
    text don't have to ship the full matrix over the wire."""
    T = attn_weights.shape[0]
    return {
        "matrix": attn_weights.tolist(),
        "labels": [f"t-{T - 1 - i}" for i in range(T)],
    }
