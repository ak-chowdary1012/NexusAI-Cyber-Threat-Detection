<<<<<<< HEAD
# Author: Avinash Krishna — Team AVV Elites (SIH26153)
=======
>>>>>>> 77949f2bb89fea05df3ee4faf24abd4771ef1671
"""
src/features/flow_features.py
Architecture ref: docs/architecture.md § Dual-Level Feature Extraction (flow-level)

Computes NetFlow/IPFIX-style aggregate features per flow. This is the layer
that catches volumetric behaviour (floods, scans-by-volume). It is deliberately
blind to fine-grained timing/sequencing — that gap is closed by
packet_features.py, per the spec's explicit requirement that flow-level alone
is insufficient.

Input contract: a pandas DataFrame with one row per network flow, containing
at minimum the columns in RAW_FLOW_COLUMNS. This matches the schema produced
by CICFlowMeter, the tool used to generate CIC-IDS2017/2018 — so this module
runs unmodified against the real dataset once downloaded (see data/README.md)
or against the bundled synthetic generator's output.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

# Columns required on the way in. CICFlowMeter/CIC-IDS names some of these
# differently (spaces, mixed case); normalize_columns() below maps common
# variants onto this canonical set so the rest of the pipeline never has to
# special-case dataset quirks.
RAW_FLOW_COLUMNS = [
    "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
    "timestamp", "flow_duration",
    "total_fwd_packets", "total_bwd_packets",
    "total_fwd_bytes", "total_bwd_bytes",
    "flag_syn", "flag_ack", "flag_fin", "flag_rst", "flag_psh", "flag_urg",
]

# Flow-level features actually fed to the state encoder. Column order here
# is fixed and MUST match state_encoder.FLOW_FEATURE_NAMES.
FLOW_FEATURE_NAMES = [
    "duration", "fwd_packets", "bwd_packets", "total_bytes",
    "bytes_per_sec", "packets_per_sec",
    "fwd_bwd_byte_ratio", "fwd_bwd_packet_ratio",
    "iat_mean", "iat_var", "iat_max",
    "syn_flag_ratio", "ack_flag_ratio", "fin_flag_ratio",
    "rst_flag_ratio", "psh_flag_ratio", "urg_flag_ratio",
    "avg_fwd_packet_size", "avg_bwd_packet_size",
    "is_tcp", "is_udp",
]

_COLUMN_ALIASES = {
    "Src IP": "src_ip", "Source IP": "src_ip",
    "Dst IP": "dst_ip", "Destination IP": "dst_ip",
    "Src Port": "src_port", "Source Port": "src_port",
    "Dst Port": "dst_port", "Destination Port": "dst_port",
    "Protocol": "protocol",
    "Timestamp": "timestamp",
    "Flow Duration": "flow_duration",
    "Tot Fwd Pkts": "total_fwd_packets", "Total Fwd Packets": "total_fwd_packets",
    "Tot Bwd Pkts": "total_bwd_packets", "Total Backward Packets": "total_bwd_packets",
    "TotLen Fwd Pkts": "total_fwd_bytes", "Total Length of Fwd Packets": "total_fwd_bytes",
    "TotLen Bwd Pkts": "total_bwd_bytes", "Total Length of Bwd Packets": "total_bwd_bytes",
    "SYN Flag Cnt": "flag_syn", "Fwd PSH Flags": "flag_psh",
    "ACK Flag Cnt": "flag_ack", "FIN Flag Cnt": "flag_fin",
    "RST Flag Cnt": "flag_rst", "URG Flag Cnt": "flag_urg",
    "Label": "label",
}


def normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Map dataset-specific column names (CICFlowMeter export conventions vary
    across CIC-IDS2017/2018 releases) onto our canonical snake_case schema."""
    df = df.rename(columns=_COLUMN_ALIASES)
    df.columns = [c.strip().lower().replace(" ", "_") for c in df.columns]
    return df


def extract_flow_features(df: pd.DataFrame) -> pd.DataFrame:
    """Compute FLOW_FEATURE_NAMES from a normalized raw-flow DataFrame.

    Every feature is derived defensively (guarded divide-by-zero) because
    real flow exports contain zero-duration flows (single-packet probes)
    that would otherwise poison rate-based features with inf/NaN.
    """
    df = normalize_columns(df)
    out = pd.DataFrame(index=df.index)

    duration = df.get("flow_duration", pd.Series(0, index=df.index)).astype(float)
    duration_safe = duration.replace(0, np.nan)

    fwd_pkts = df.get("total_fwd_packets", pd.Series(0, index=df.index)).astype(float)
    bwd_pkts = df.get("total_bwd_packets", pd.Series(0, index=df.index)).astype(float)
    fwd_bytes = df.get("total_fwd_bytes", pd.Series(0, index=df.index)).astype(float)
    bwd_bytes = df.get("total_bwd_bytes", pd.Series(0, index=df.index)).astype(float)
    total_bytes = fwd_bytes + bwd_bytes
    total_pkts = fwd_pkts + bwd_pkts

    out["duration"] = duration
    out["fwd_packets"] = fwd_pkts
    out["bwd_packets"] = bwd_pkts
    out["total_bytes"] = total_bytes
    out["bytes_per_sec"] = (total_bytes / duration_safe).fillna(0.0)
    out["packets_per_sec"] = (total_pkts / duration_safe).fillna(0.0)
    out["fwd_bwd_byte_ratio"] = (fwd_bytes / bwd_bytes.replace(0, np.nan)).fillna(fwd_bytes.clip(upper=1.0))
    out["fwd_bwd_packet_ratio"] = (fwd_pkts / bwd_pkts.replace(0, np.nan)).fillna(fwd_pkts.clip(upper=1.0))

    # Inter-arrival-time stats: use dataset-provided columns if present,
    # else approximate from duration/packet-count (documented approximation,
    # not silently wrong — see docs/architecture.md limitations section).
    if "flow_iat_mean" in df.columns:
        out["iat_mean"] = df["flow_iat_mean"].astype(float)
        out["iat_var"] = df.get("flow_iat_std", pd.Series(0, index=df.index)).astype(float) ** 2
        out["iat_max"] = df.get("flow_iat_max", pd.Series(0, index=df.index)).astype(float)
    else:
        approx_iat = (duration_safe / total_pkts.replace(0, np.nan)).fillna(0.0)
        out["iat_mean"] = approx_iat
        out["iat_var"] = 0.0
        out["iat_max"] = approx_iat

    for flag in ["syn", "ack", "fin", "rst", "psh", "urg"]:
        col = f"flag_{flag}"
        vals = df.get(col, pd.Series(0, index=df.index)).astype(float)
        out[f"{flag}_flag_ratio"] = (vals / total_pkts.replace(0, np.nan)).fillna(0.0).clip(0, 1)

    out["avg_fwd_packet_size"] = (fwd_bytes / fwd_pkts.replace(0, np.nan)).fillna(0.0)
    out["avg_bwd_packet_size"] = (bwd_bytes / bwd_pkts.replace(0, np.nan)).fillna(0.0)

    protocol = df.get("protocol", pd.Series(0, index=df.index))
    out["is_tcp"] = (protocol == 6).astype(float) if protocol.dtype != object else protocol.eq("TCP").astype(float)
    out["is_udp"] = (protocol == 17).astype(float) if protocol.dtype != object else protocol.eq("UDP").astype(float)

    out = out[FLOW_FEATURE_NAMES].replace([np.inf, -np.inf], 0.0).fillna(0.0)

    # carry through identity/label columns needed by windowing.py, without
    # treating them as model features
    for passthrough in ("src_ip", "dst_ip", "timestamp", "label"):
        if passthrough in df.columns:
            out[passthrough] = df[passthrough]
    return out
