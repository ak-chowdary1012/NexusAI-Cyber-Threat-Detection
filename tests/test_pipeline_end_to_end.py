# Author: Avinash Krishna — Team AVV Elites (SIH26153)
"""
tests/test_pipeline_end_to_end.py

Exercises the full pipeline on the bundled synthetic dataset — the same
smoke test a fresh clone should be able to run to confirm the environment
is set up correctly, per the README's "no team member should need to be
asked anything" bar. Deliberately small (few epochs, small SHAP background)
so it runs in well under a minute; it is checking wiring/shape correctness,
not model quality — evaluate.py after a real train.py run is where quality
numbers are asserted.

Run with: pytest tests/ -v
"""
from __future__ import annotations

import numpy as np
import torch

from src.explain.attention_viz import summarize_attention
from src.explain.shap_explainer import ShapExplainer
from src.features.windowing import FUSED_FEATURE_NAMES, build_sequences
from src.models.attck_mapper import map_trajectory_to_stage, rule_based_stage
from src.models.rollout import k_step_rollout
from src.models.state_encoder import StateEncoder
from src.models.transition_model import TransitionModel
from src.rag.copilot import explain
from src.rag.knowledge_base import KnowledgeBase
from src.rag.retriever import AttckRetriever
from src.synthetic_data import generate_synthetic_dataset
from src.utils import load_config, set_seed


def _small_cfg():
    cfg = load_config()
    # shrink for test speed without changing the architecture being tested
    cfg["transition_model"]["epochs"] = 2
    return cfg


def test_feature_dims_match_config():
    cfg = _small_cfg()
    assert len(FUSED_FEATURE_NAMES) == cfg["state_encoder"]["mlp"]["input_dim"]
    assert len(FUSED_FEATURE_NAMES) == cfg["state_encoder"]["autoencoder"]["input_dim"]


def test_synthetic_data_has_all_stages():
    df = generate_synthetic_dataset(n_hosts_per_stage=2, windows_per_host=15, n_benign_hosts=3)
    labels = set(df["label"].unique())
    assert {"Benign", "Reconnaissance", "Initial Access", "Lateral Movement",
            "Command and Control", "Exfiltration"} <= labels


def test_state_encoder_output_shape():
    cfg = _small_cfg()
    set_seed(cfg["project"]["seed"])
    encoder = StateEncoder(cfg)
    x = torch.randn(8, cfg["state_encoder"]["mlp"]["input_dim"])
    state = encoder.encode(x)
    assert state.shape == (8, cfg["state_encoder"]["state_vector_dim"])
    assert torch.all(state.abs() <= 1.0 + 1e-4)  # Tanh-bounded


def test_transition_model_forward_shapes():
    cfg = _small_cfg()
    set_seed(cfg["project"]["seed"])
    model = TransitionModel(cfg)
    T = cfg["windowing"]["sequence_length"]
    x = torch.randn(4, T, cfg["transition_model"]["input_dim"])
    out = model(x)
    assert out["next_state"].shape == (4, cfg["transition_model"]["input_dim"])
    assert out["infiltration_prob"].shape == (4, 1)
    assert torch.all((out["infiltration_prob"] >= 0) & (out["infiltration_prob"] <= 1))
    assert out["attention_weights"].shape == (4, T, T)


def test_rollout_produces_monotone_horizon_probs():
    cfg = _small_cfg()
    set_seed(cfg["project"]["seed"])
    model = TransitionModel(cfg)
    T = cfg["windowing"]["sequence_length"]
    x = torch.randn(1, T, cfg["transition_model"]["input_dim"])
    result = k_step_rollout(model, x, k_steps=cfg["rollout"]["k_steps"], horizon_minutes=cfg["rollout"]["horizon_minutes"])
    assert len(result.infiltration_probs) == 3
    # running-max smoothing guarantees non-decreasing horizon probabilities
    assert result.infiltration_probs[0] <= result.infiltration_probs[1] <= result.infiltration_probs[2]
    assert result.simulated_states.shape[0] == max(cfg["rollout"]["k_steps"])


def test_attck_rule_mapper_returns_valid_stage():
    cfg = _small_cfg()
    from src.models.attck_mapper import STAGES
    feat = np.random.default_rng(0).normal(size=len(FUSED_FEATURE_NAMES))
    stage, evidence = rule_based_stage(feat)
    assert stage in STAGES
    assert isinstance(evidence, dict) and len(evidence) > 0


def test_rag_retriever_returns_relevant_technique_for_scan_pattern():
    kb = KnowledgeBase.load()
    retriever = AttckRetriever(kb)
    hits = retriever.retrieve("Reconnaissance port_scan_score unique_dst_ports_per_src", top_k=3)
    assert len(hits) > 0
    top_ids = [entry.id for entry, _ in hits]
    assert "T1595" in top_ids  # Active Scanning must surface for a scan-shaped query


def test_copilot_explanation_is_grounded_in_inputs():
    kb = KnowledgeBase.load()
    retriever = AttckRetriever(kb)
    shap_feats = [{"feature": "port_scan_score", "shap_value": 0.5, "raw_value": 0.9}]
    attn_summary = {"top_attended_windows": [{"minutes_ago": 1.0, "attention_weight": 0.4}], "attention_entropy": 1.2}
    exp = explain(
        predicted_stage="Reconnaissance", stage_confidence=0.9,
        infiltration_probs={"1_min": 0.3, "5_min": 0.5, "15_min": 0.6},
        top_shap_features=shap_feats, attention_summary=attn_summary,
        retriever=retriever, host_id="test-host",
    )
    assert "test-host" in exp.headline
    assert any("port_scan_score" in b for b in exp.evidence_bullets)
    assert len(exp.retrieved_techniques) > 0
    assert len(exp.recommended_actions) > 0


def test_full_pipeline_end_to_end_on_synthetic_data():
    """The integration test: raw synthetic windows -> sequences -> state
    encoding -> transition model -> rollout -> stage mapping -> SHAP -> RAG
    explanation. If this passes, a fresh clone's environment is correctly
    wired end to end."""
    cfg = _small_cfg()
    set_seed(cfg["project"]["seed"])

    df = generate_synthetic_dataset(n_hosts_per_stage=3, windows_per_host=30, n_benign_hosts=5)
    X_seq, y_labels, host_ids = build_sequences(df, sequence_length=cfg["windowing"]["sequence_length"])
    assert X_seq.shape[0] > 0, "no sequences were built — check windows_per_host vs sequence_length"
    assert X_seq.shape[2] == len(FUSED_FEATURE_NAMES)

    encoder = StateEncoder(cfg)
    transition = TransitionModel(cfg)

    sample = torch.tensor(X_seq[:1], dtype=torch.float32)
    with torch.no_grad():
        state_seq = encoder.encode_sequence(sample)
    assert state_seq.shape == (1, cfg["windowing"]["sequence_length"], cfg["state_encoder"]["state_vector_dim"])

    rollout_result = k_step_rollout(
        transition, state_seq, k_steps=cfg["rollout"]["k_steps"], horizon_minutes=cfg["rollout"]["horizon_minutes"]
    )
    attn = summarize_attention(rollout_result.final_attention_weights, window_seconds=cfg["windowing"]["window_seconds"])
    assert "top_attended_windows" in attn

    last_features = X_seq[0, -1, :]
    latent = state_seq[0, -1, :].numpy()
    stage_result = map_trajectory_to_stage(last_features, latent, cluster_mapper=None)
    assert stage_result["final_stage"] in {"Reconnaissance", "Initial Access", "Lateral Movement",
                                            "Command and Control", "Exfiltration"}

    # SHAP on a tiny background set — this is the slow part of the test, kept small deliberately
    background = X_seq[:20, -1, :]
    explainer = ShapExplainer(encoder, background, feature_names=FUSED_FEATURE_NAMES)
    with torch.no_grad():
        pred_class = int(encoder.mlp.class_probabilities(sample[:, -1, :]).argmax(dim=-1).item())
    shap_result = explainer.explain_window(last_features, predicted_class_idx=pred_class, nsamples=20)
    assert len(shap_result["top_features"]) > 0

    # RAG copilot ties it all together
    kb = KnowledgeBase.load()
    retriever = AttckRetriever(kb)
    exp = explain(
        predicted_stage=stage_result["final_stage"], stage_confidence=0.8,
        infiltration_probs={
            f"{m}_min": p for m, p in zip(cfg["rollout"]["horizon_minutes"], rollout_result.infiltration_probs)
        },
        top_shap_features=shap_result["top_features"], attention_summary=attn,
        retriever=retriever, host_id=str(host_ids[0]),
    )
    assert exp.headline
    assert len(exp.recommended_actions) > 0
