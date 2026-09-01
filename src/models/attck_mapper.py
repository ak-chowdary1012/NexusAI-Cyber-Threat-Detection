<<<<<<< HEAD
# Author: Avinash Krishna — Team AVV Elites (SIH26153)
=======
>>>>>>> 77949f2bb89fea05df3ee4faf24abd4771ef1671
"""
src/models/attck_mapper.py
Architecture ref: docs/architecture.md § 4.5 MITRE ATT&CK Stage Mapper

Maps a predicted trajectory (the simulated states from rollout.py, plus the
raw window features that produced them) onto a kill-chain stage:
Reconnaissance, Initial Access, Lateral Movement, Command & Control,
Exfiltration.

Two independent signals are combined, by design — the docs are explicit that
this cross-validation is what turns "we mapped stages" into "we validated
the mapping":
  1. Rule-based signatures on interpretable raw features (fast, auditable,
     zero training cost, directly traceable to a specific ATT&CK technique).
  2. K-means clusters over the *learned* latent states, fit once on CTU-13's
     labelled multi-stage botnet scenarios and re-used at inference time.

agreement_rate() reports how often the two signals agree — this number
belongs in the evaluation report and the demo dashboard, not just in this
docstring.
"""
from __future__ import annotations

from dataclasses import dataclass

import numpy as np
from sklearn.cluster import KMeans

STAGES = ["Reconnaissance", "Initial Access", "Lateral Movement", "Command and Control", "Exfiltration"]

# Index into the fused feature vector (see windowing.FUSED_FEATURE_NAMES) for
# the specific engineered features each rule below reads. Kept as named
# lookups (not magic ints) so a change in feature ordering fails loudly
# instead of silently mis-mapping stages.
_FLOW_IDX = {name: i for i, name in enumerate(
    __import__("src.features.flow_features", fromlist=["FLOW_FEATURE_NAMES"]).FLOW_FEATURE_NAMES
)}
_PACKET_IDX_OFFSET = len(_FLOW_IDX)
_PACKET_IDX = {name: _PACKET_IDX_OFFSET + i for i, name in enumerate(
    __import__("src.features.packet_features", fromlist=["PACKET_FEATURE_NAMES"]).PACKET_FEATURE_NAMES
)}


def rule_based_stage(feature_window: np.ndarray) -> tuple[str, dict[str, float]]:
    """feature_window: 1D array, the last (most recent, real — not simulated)
    fused feature vector for a host. Returns (stage_label, evidence_dict) so
    the caller can show *why*, not just *what*, per the spec's explainability
    requirement.

    Thresholds are deliberately simple and documented — they are the
    auditable half of the cross-validated mapping, not a black box.
    """
    f = feature_window
    evidence = {}

    port_scan = f[_PACKET_IDX["port_scan_score"]]
    unique_ports = f[_PACKET_IDX["unique_dst_ports_per_src"]]
    evidence["port_scan_score"] = float(port_scan)
    if port_scan > 0.4 or unique_ports > 15:
        return "Reconnaissance", evidence

    syn_ratio = f[_FLOW_IDX["syn_flag_ratio"]]
    fwd_bwd_byte_ratio = f[_FLOW_IDX["fwd_bwd_byte_ratio"]]
    evidence["syn_flag_ratio"] = float(syn_ratio)
    if syn_ratio > 0.6 and fwd_bwd_byte_ratio > 2.0:
        return "Initial Access", evidence  # authentication-burst / exploit-attempt signature

    bytes_per_sec = f[_FLOW_IDX["bytes_per_sec"]]
    fin_ratio = f[_FLOW_IDX["fin_flag_ratio"]]
    evidence["internal_transfer_rate"] = float(bytes_per_sec)
    if bytes_per_sec > 50_000 and fin_ratio < 0.3:
        return "Lateral Movement", evidence  # sustained internal SMB/RDP-style spike

    iat_var = f[_FLOW_IDX["iat_var"]]
    payload_var = f[_PACKET_IDX["payload_size_var"]]
    evidence["beacon_regularity"] = float(1.0 / (1.0 + iat_var))
    if iat_var < 2.0 and payload_var < 500 and bytes_per_sec < 5_000:
        return "Command and Control", evidence  # low-volume, low-variance periodic beacon

    total_bytes = f[_FLOW_IDX["total_bytes"]]
    evidence["outbound_volume"] = float(total_bytes)
    if total_bytes > 1_000_000 and fwd_bwd_byte_ratio > 5.0:
        return "Exfiltration", evidence  # sustained large outbound transfer

    return "Reconnaissance", evidence  # conservative default: treat ambiguous
    # traffic as early-stage rather than silently returning "unknown", so the
    # dashboard always has a stage to show alongside its confidence score.


@dataclass
class ClusterStageMapper:
    """K-means over learned latent states, fit on CTU-13 labelled scenarios.
    cluster_to_stage assigns each cluster the majority ground-truth stage of
    the CTU-13 windows that fell into it at fit time."""
    kmeans: KMeans
    cluster_to_stage: dict[int, str]

    @classmethod
    def fit(cls, latent_states: np.ndarray, stage_labels: list[str], k: int = 5, seed: int = 42) -> "ClusterStageMapper":
        kmeans = KMeans(n_clusters=k, random_state=seed, n_init=10)
        cluster_ids = kmeans.fit_predict(latent_states)
        cluster_to_stage = {}
        for c in range(k):
            mask = cluster_ids == c
            if not mask.any():
                cluster_to_stage[c] = STAGES[0]
                continue
            labels_in_cluster = [stage_labels[i] for i in range(len(stage_labels)) if mask[i]]
            values, counts = np.unique(labels_in_cluster, return_counts=True)
            cluster_to_stage[c] = str(values[np.argmax(counts)])
        return cls(kmeans=kmeans, cluster_to_stage=cluster_to_stage)

    def predict(self, latent_state: np.ndarray) -> str:
        cluster_id = int(self.kmeans.predict(latent_state.reshape(1, -1))[0])
        return self.cluster_to_stage[cluster_id]


def agreement_rate(rule_labels: list[str], cluster_labels: list[str]) -> float:
    """Fraction of windows where the rule-based and cluster-based mappings
    agree. Reported in evaluate.py and surfaced on the dashboard — this
    number is what makes the ATT&CK mapping a *validated* claim."""
    if not rule_labels:
        return 0.0
    agree = sum(1 for r, c in zip(rule_labels, cluster_labels) if r == c)
    return agree / len(rule_labels)


def map_trajectory_to_stage(
    last_real_features: np.ndarray,
    latent_state: np.ndarray,
    cluster_mapper: ClusterStageMapper | None = None,
) -> dict[str, str]:
    """Single-trajectory convenience function combining both signals. Returns
    both individual predictions plus a `final_stage` (rule-based prediction
    wins on disagreement — it is the auditable, feature-grounded signal, and
    the spec prioritizes interpretability over raw accuracy for this
    component). If no fitted cluster_mapper is available (e.g. CTU-13 not yet
    downloaded), the rule-based prediction alone is returned, clearly flagged
    as unvalidated."""
    rule_stage, evidence = rule_based_stage(last_real_features)
    result = {"rule_based_stage": rule_stage, "evidence": evidence, "final_stage": rule_stage}
    if cluster_mapper is not None:
        cluster_stage = cluster_mapper.predict(latent_state)
        result["cluster_stage"] = cluster_stage
        result["cross_validated"] = cluster_stage == rule_stage
    else:
        result["cluster_stage"] = None
        result["cross_validated"] = None
    return result
