<<<<<<< HEAD
# Author: Avinash Krishna — Team AVV Elites (SIH26153)
=======
>>>>>>> 77949f2bb89fea05df3ee4faf24abd4771ef1671
"""
src/synthetic_data.py

Generates a small, labelled, statistically-plausible synthetic traffic
dataset covering benign traffic plus one scenario per kill-chain stage. This
exists so the full pipeline — features -> state encoder -> transition model
-> rollout -> stage mapper -> explainability -> RAG copilot -> dashboard —
can be run and demoed end-to-end on a laptop in minutes, without first
downloading and preprocessing the real ~2.83M-row CIC-IDS2017/2018 or
CTU-13 corpora (see data/README.md for how to plug those in for the real
benchmark numbers the submission reports).

This is explicitly a development/demo fixture, not a claim of a validated
benchmark result — evaluate.py and docs/architecture.md are clear about
which numbers come from which dataset.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from src.features.flow_features import FLOW_FEATURE_NAMES
from src.features.packet_features import PACKET_FEATURE_NAMES

RNG_SEED = 42

# One synthetic "profile" per label: a mean + std for every fused feature,
# hand-tuned to be qualitatively consistent with the attck_mapper.py rule
# thresholds (e.g. Reconnaissance profiles get a high port_scan_score) so the
# demo's rule-based stage mapper and the labels agree — a sanity property
# worth asserting in tests/test_pipeline_end_to_end.py.
_PROFILES = {
    "Benign": dict(
        bytes_per_sec=(800, 300), packets_per_sec=(5, 2), syn_flag_ratio=(0.15, 0.05),
        fin_flag_ratio=(0.15, 0.05), fwd_bwd_byte_ratio=(1.0, 0.3), total_bytes=(4000, 1500),
        port_scan_score=(0.02, 0.02), unique_dst_ports_per_src=(1.5, 0.8), iat_var=(8.0, 3.0),
        payload_size_var=(2000, 500), retransmission_ratio=(0.02, 0.02),
    ),
    "Reconnaissance": dict(
        bytes_per_sec=(200, 100), packets_per_sec=(20, 8), syn_flag_ratio=(0.85, 0.1),
        fin_flag_ratio=(0.05, 0.03), fwd_bwd_byte_ratio=(3.0, 1.0), total_bytes=(500, 200),
        port_scan_score=(0.75, 0.15), unique_dst_ports_per_src=(28, 10), iat_var=(0.5, 0.3),
        payload_size_var=(50, 20), retransmission_ratio=(0.05, 0.03),
    ),
    "Initial Access": dict(
        bytes_per_sec=(3000, 800), packets_per_sec=(12, 4), syn_flag_ratio=(0.7, 0.1),
        fin_flag_ratio=(0.1, 0.05), fwd_bwd_byte_ratio=(3.5, 1.0), total_bytes=(6000, 2000),
        port_scan_score=(0.15, 0.05), unique_dst_ports_per_src=(2, 1), iat_var=(3.0, 1.0),
        payload_size_var=(1500, 400), retransmission_ratio=(0.08, 0.04),
    ),
    "Lateral Movement": dict(
        bytes_per_sec=(75000, 15000), packets_per_sec=(60, 15), syn_flag_ratio=(0.3, 0.05),
        fin_flag_ratio=(0.1, 0.05), fwd_bwd_byte_ratio=(1.5, 0.4), total_bytes=(500000, 100000),
        port_scan_score=(0.05, 0.03), unique_dst_ports_per_src=(2, 1), iat_var=(1.5, 0.5),
        payload_size_var=(9000, 2000), retransmission_ratio=(0.03, 0.02),
    ),
    "Command and Control": dict(
        bytes_per_sec=(400, 100), packets_per_sec=(2, 1), syn_flag_ratio=(0.2, 0.05),
        fin_flag_ratio=(0.2, 0.05), fwd_bwd_byte_ratio=(1.1, 0.2), total_bytes=(600, 100),
        port_scan_score=(0.02, 0.02), unique_dst_ports_per_src=(1, 0.3), iat_var=(0.8, 0.3),
        payload_size_var=(80, 30), retransmission_ratio=(0.01, 0.01),
    ),
    "Exfiltration": dict(
        bytes_per_sec=(90000, 20000), packets_per_sec=(70, 20), syn_flag_ratio=(0.1, 0.03),
        fin_flag_ratio=(0.05, 0.02), fwd_bwd_byte_ratio=(9.0, 2.0), total_bytes=(2_500_000, 500_000),
        port_scan_score=(0.01, 0.01), unique_dst_ports_per_src=(1, 0.5), iat_var=(2.0, 0.5),
        payload_size_var=(12000, 3000), retransmission_ratio=(0.04, 0.02),
    ),
}

ALL_FEATURES = FLOW_FEATURE_NAMES + PACKET_FEATURE_NAMES


def _sample_profile(profile: dict, n: int, rng: np.random.Generator) -> pd.DataFrame:
    row = {}
    for feature in ALL_FEATURES:
        mean, std = profile.get(feature, (0.1, 0.05))
        vals = rng.normal(mean, std, size=n)
        row[feature] = np.clip(vals, 0, None)
    return pd.DataFrame(row)


def generate_synthetic_dataset(
    n_hosts_per_stage: int = 8,
    windows_per_host: int = 40,
    n_benign_hosts: int = 20,
    seed: int = RNG_SEED,
) -> pd.DataFrame:
    """Builds a long-format DataFrame: one row per (host, window), with fused
    features plus a `label` column (stage name or "Benign") and a binary
    `is_malicious` column. Malicious hosts transition through a short
    kill-chain sequence (Benign -> Reconnaissance -> ... ) across their
    windows rather than being a single stage throughout, so the transition
    model has real state-change signal to learn from, matching how CTU-13's
    labelled multi-stage scenarios are described in docs/architecture.md.
    """
    rng = np.random.default_rng(seed)
    rows = []
    window_seconds = 30
    stage_order = ["Reconnaissance", "Initial Access", "Lateral Movement", "Command and Control", "Exfiltration"]

    host_counter = 0
    # Benign-only hosts
    for _ in range(n_benign_hosts):
        host_id = f"10.0.0.{host_counter}"
        host_counter += 1
        df = _sample_profile(_PROFILES["Benign"], windows_per_host, rng)
        df["src_ip"] = host_id
        df["window_start"] = np.arange(windows_per_host) * window_seconds
        df["label"] = "Benign"
        df["is_malicious"] = 0
        rows.append(df)

    # Attack-progression hosts: spend early windows benign, then progress
    # through the kill chain, one stage at a time, ending in exfiltration —
    # giving the transition model genuine P(S_t+1 | S_t) signal to learn.
    for stage_end in stage_order:
        end_idx = stage_order.index(stage_end)
        sequence = ["Benign"] * 3 + stage_order[: end_idx + 1]
        for _ in range(n_hosts_per_stage):
            host_id = f"10.0.1.{host_counter}"
            host_counter += 1
            per_stage_windows = max(windows_per_host // len(sequence), 3)
            host_rows = []
            for stage in sequence:
                df = _sample_profile(_PROFILES[stage], per_stage_windows, rng)
                df["label"] = stage
                df["is_malicious"] = 0 if stage == "Benign" else 1
                host_rows.append(df)
            host_df = pd.concat(host_rows, ignore_index=True)
            host_df["src_ip"] = host_id
            host_df["window_start"] = np.arange(len(host_df)) * window_seconds
            rows.append(host_df)

    full = pd.concat(rows, ignore_index=True)
    full = full[["src_ip", "window_start"] + ALL_FEATURES + ["label", "is_malicious"]]
    return full


if __name__ == "__main__":
    from src.utils import resolve_path, get_logger

    logger = get_logger(__name__)
    out_dir = resolve_path("data/synthetic")
    out_dir.mkdir(parents=True, exist_ok=True)
    df = generate_synthetic_dataset()
    out_path = out_dir / "synthetic_traffic.csv"
    df.to_csv(out_path, index=False)
    logger.info(f"Wrote {len(df)} synthetic windows across {df['src_ip'].nunique()} hosts -> {out_path}")
    logger.info(f"Label distribution:\n{df['label'].value_counts()}")
