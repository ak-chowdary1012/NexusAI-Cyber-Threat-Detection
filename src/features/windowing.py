# Author: Avinash Krishna — Team AVV Elites (SIH26153)
"""
src/features/windowing.py
Architecture ref: docs/architecture.md § Dataset & Methodology (windowing)

Turns per-flow and per-packet feature tables into fixed-length sequences of
window-level feature vectors — the shape the state encoder and transition
model expect. Default: 30-second windows, 50% overlap (15s stride), T=20
windows (10 minutes of context) per sequence, all read from configs/default.yaml
rather than hard-coded, so a config change alone (no code edits) changes the
model's input contract everywhere.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from src.features.flow_features import FLOW_FEATURE_NAMES
from src.features.packet_features import PACKET_FEATURE_NAMES

FUSED_FEATURE_NAMES = FLOW_FEATURE_NAMES + PACKET_FEATURE_NAMES  # 21 + 10 = 31 dims


def aggregate_flows_to_windows(flow_df: pd.DataFrame, window_seconds: float, host_key: str = "src_ip") -> pd.DataFrame:
    """Aggregate per-flow feature rows into per-(host, window) feature rows by
    taking the mean of each engineered feature — flows already summarize a
    connection, so window-level aggregation here is a second, coarser layer
    that captures multi-flow behaviour (e.g. many small flows = a scan)."""
    df = flow_df.copy()
    if "timestamp" not in df.columns:
        # synthetic/offline fallback: assign a monotonically increasing
        # synthetic timestamp so the pipeline still runs without real capture
        # times (documented fallback, not a silent fabrication of real time).
        df["timestamp"] = np.arange(len(df)) * (window_seconds / max(len(df), 1))
    df["window_start"] = (df["timestamp"].astype(float) // window_seconds) * window_seconds

    agg_cols = [c for c in FLOW_FEATURE_NAMES if c in df.columns]
    grouped = df.groupby([host_key, "window_start"])[agg_cols].mean().reset_index()
    if "label" in df.columns:
        # majority label per window — a window is "malicious" if most flows in it are
        labels = df.groupby([host_key, "window_start"])["label"].agg(
            lambda s: s.value_counts().idxmax()
        ).reset_index()
        grouped = grouped.merge(labels, on=[host_key, "window_start"])
    return grouped


def join_flow_and_packet_windows(flow_windows: pd.DataFrame, packet_windows: pd.DataFrame, host_key: str = "src_ip") -> pd.DataFrame:
    """Left-join flow-level window aggregates with packet-level window
    aggregates on (host, window_start). Packet-level coverage is often
    partial (not every flow has a matching PCAP capture) so missing packet
    features are filled with 0 rather than dropping the row — flow-level
    signal alone is still valid input, per the spec's fallback allowance."""
    merged = flow_windows.merge(
        packet_windows, left_on=[host_key, "window_start"], right_on=[host_key, "window_start"], how="left"
    )
    for col in PACKET_FEATURE_NAMES:
        if col not in merged.columns:
            merged[col] = 0.0
    merged[PACKET_FEATURE_NAMES] = merged[PACKET_FEATURE_NAMES].fillna(0.0)
    return merged


def build_sequences(
    windowed_df: pd.DataFrame,
    sequence_length: int,
    host_key: str = "src_ip",
    label_col: str | None = "label",
) -> tuple[np.ndarray, np.ndarray | None, list[str]]:
    """Slide a length-`sequence_length` window over each host's chronologically
    ordered window rows to build (N, T, F) sequences for the transition model.

    Returns:
        X: float32 array, shape (num_sequences, sequence_length, num_features)
        y: label for the *last* window in each sequence (what we're forecasting
           toward), or None if label_col isn't present (real deployment traffic
           is unlabeled — this must work in that case, not just on benchmarks)
        host_ids: the host_key value each sequence belongs to (for traceability
           back to "which machine is this forecast about")
    """
    feature_cols = [c for c in FUSED_FEATURE_NAMES if c in windowed_df.columns]
    sequences, labels, host_ids = [], [], []

    for host, group in windowed_df.groupby(host_key):
        group = group.sort_values("window_start")
        feats = group[feature_cols].to_numpy(dtype=np.float32)
        has_labels = label_col is not None and label_col in group.columns
        lbls = group[label_col].to_numpy() if has_labels else None

        if len(feats) < sequence_length:
            continue  # not enough history yet for this host — real-world
            # deployment handles this by buffering until enough windows arrive,
            # see platform/backend/app/services/ml_bridge.py

        for start in range(0, len(feats) - sequence_length + 1):
            end = start + sequence_length
            sequences.append(feats[start:end])
            host_ids.append(host)
            if has_labels:
                labels.append(lbls[end - 1])

    X = np.stack(sequences) if sequences else np.empty((0, sequence_length, len(feature_cols)), dtype=np.float32)
    y = np.array(labels) if labels else None
    return X, y, host_ids
