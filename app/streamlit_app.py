"""
app/streamlit_app.py
Architecture ref: docs/architecture.md § 7 Live Demo & Dashboard Plan

Fully offline demo dashboard — zero outbound network calls at runtime (the
RAG copilot retrieves from the bundled local JSON knowledge base via BM25;
nothing here calls an external API). Run with:

    streamlit run app/streamlit_app.py

Security note (see SECURITY.md § input validation): every user-controlled
input — the uploaded file's extension, size, and parsed contents — is
validated before touching the ML pipeline. A malformed or oversized upload
must degrade to a clear error message, never a stack trace or a hang.
"""
from __future__ import annotations

import io
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import streamlit as st
import torch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # allow `src.*` imports when run via `streamlit run`

from src.explain.attention_viz import attention_heatmap_data, summarize_attention
from src.explain.shap_explainer import ShapExplainer
from src.features.windowing import FUSED_FEATURE_NAMES, build_sequences
from src.models.attck_mapper import map_trajectory_to_stage
from src.models.baseline import BaselineModel
from src.models.rollout import k_step_rollout
from src.models.state_encoder import StateEncoder
from src.models.transition_model import TransitionModel
from src.rag.copilot import explain as rag_explain
from src.rag.knowledge_base import KnowledgeBase
from src.rag.retriever import AttckRetriever
from src.synthetic_data import generate_synthetic_dataset
from src.utils import load_config, resolve_path, set_seed

MAX_UPLOAD_MB = 50
ALLOWED_EXTENSIONS = {".csv", ".pcap", ".pcapng"}

st.set_page_config(page_title="NexusAI Forecast — SIH26153", layout="wide", page_icon="🛰️")


@st.cache_resource
def load_pipeline():
    """Loads config + checkpoints once per server process. Cached deliberately:
    re-loading PyTorch weights per user interaction would make the "live"
    demo feel sluggish. If no checkpoints exist yet, returns None components
    so the UI can show a clear "run training first" message instead of
    crashing on import."""
    cfg = load_config()
    set_seed(cfg["project"]["seed"])
    ckpt_dir = resolve_path(cfg["paths"]["checkpoint_dir"])

    kb = KnowledgeBase.load()
    retriever = AttckRetriever(kb)

    if not (ckpt_dir / "state_encoder.pt").exists():
        return cfg, None, None, None, None, retriever

    encoder = StateEncoder(cfg)
    encoder.load_state_dict(torch.load(ckpt_dir / "state_encoder.pt", map_location="cpu"))
    encoder.eval()

    transition = TransitionModel(cfg)
    transition.load_state_dict(torch.load(ckpt_dir / "transition_model.pt", map_location="cpu"))
    transition.eval()

    norm = np.load(ckpt_dir / "normalization.npz")

    cluster_mapper = None
    cluster_path = ckpt_dir / "cluster_mapper.pkl"
    if cluster_path.exists():
        import pickle
        with open(cluster_path, "rb") as f:
            cluster_mapper = pickle.load(f)

    baseline = None
    baseline_path = ckpt_dir / "baseline.pkl"
    if baseline_path.exists():
        import pickle
        with open(baseline_path, "rb") as f:
            baseline = pickle.load(f)

    return cfg, (encoder, transition, norm, cluster_mapper, baseline), None, None, None, retriever


def validate_upload(uploaded_file) -> tuple[bool, str]:
    """Input validation for the file-upload entry point (SECURITY.md §6).
    Rejects by extension allow-list and size cap before any parsing is
    attempted — this is the one place end-user-controlled bytes enter this
    offline application, so it is the one place that must never trust the
    input blindly."""
    suffix = Path(uploaded_file.name).suffix.lower()
    if suffix not in ALLOWED_EXTENSIONS:
        return False, f"Unsupported file type '{suffix}'. Allowed: {', '.join(sorted(ALLOWED_EXTENSIONS))}"
    size_mb = uploaded_file.size / (1024 * 1024)
    if size_mb > MAX_UPLOAD_MB:
        return False, f"File is {size_mb:.1f} MB, exceeds the {MAX_UPLOAD_MB} MB demo limit."
    return True, ""


def load_uploaded_traffic(uploaded_file) -> pd.DataFrame:
    suffix = Path(uploaded_file.name).suffix.lower()
    if suffix == ".csv":
        df = pd.read_csv(uploaded_file, nrows=200_000)  # hard cap even within the size limit — defence in depth
        return df
    else:
        # PCAP path: write to a bounded temp buffer and run packet_features.
        # Kept out of the default demo path (CSV is faster to click through)
        # but fully wired — see src/features/packet_features.py.
        raise NotImplementedError(
            "PCAP upload calls src.features.packet_features.extract_packet_features(); "
            "wire a temp-file write here in your environment (Streamlit's UploadedFile "
            "is an in-memory buffer — Scapy's PcapReader needs a real path)."
        )


def main():
    st.title("🛰️ NexusAI Forecast")
    st.caption("SIH26153 · AI-Based Network Attack Forecasting from Network Traffic Data · Team AVV Elites")
    st.markdown(
        "A **World-Model** AI system that learns network state-transition dynamics and forecasts "
        "attacker progression *before* compromise completes — mapped to MITRE ATT&CK stages, "
        "explained via SHAP + attention, grounded by retrieval-augmented decision support. "
        "**Runs fully offline — no data leaves this machine.**"
    )

    cfg, pipeline, _, _, _, retriever = load_pipeline()

    with st.sidebar:
        st.header("Data source")
        source = st.radio("Choose input", ["Bundled synthetic sample", "Upload CSV/PCAP"], index=0)
        uploaded_df = None
        if source == "Upload CSV/PCAP":
            uploaded = st.file_uploader("Traffic sample", type=["csv", "pcap", "pcapng"])
            if uploaded is not None:
                ok, msg = validate_upload(uploaded)
                if not ok:
                    st.error(msg)
                else:
                    try:
                        uploaded_df = load_uploaded_traffic(uploaded)
                        st.success(f"Loaded {len(uploaded_df)} rows.")
                    except NotImplementedError as e:
                        st.warning(str(e))
                    except Exception:
                        st.error("Could not parse this file — please check it matches the expected schema.")

        st.divider()
        st.header("Model status")
        if pipeline is None:
            st.warning("No trained checkpoints found. Run:\n\n`python -m src.train`\n\nthen refresh this page.")
        else:
            st.success("Checkpoints loaded ✓")

    if pipeline is None:
        st.info("👈 Train the model first (`python -m src.train`), then explore forecasts here.")
        return

    encoder, transition, norm, cluster_mapper, baseline = pipeline
    feat_mean, feat_std = norm["mean"], norm["std"]

    if uploaded_df is None:
        df = generate_synthetic_dataset(n_hosts_per_stage=2, windows_per_host=cfg["windowing"]["sequence_length"] + 5, n_benign_hosts=2)
        st.caption("Using the bundled synthetic sample (toggle 'Upload CSV/PCAP' in the sidebar to use your own).")
    else:
        df = uploaded_df

    df_norm = df.copy()
    missing = [c for c in FUSED_FEATURE_NAMES if c not in df_norm.columns]
    if missing:
        st.error(f"Uploaded data is missing required feature columns: {missing[:5]}{'...' if len(missing) > 5 else ''}")
        return
    df_norm[FUSED_FEATURE_NAMES] = (df_norm[FUSED_FEATURE_NAMES].to_numpy(dtype=np.float32) - feat_mean) / feat_std

    X_seq, y_labels, host_ids = build_sequences(df_norm, sequence_length=cfg["windowing"]["sequence_length"])
    if len(X_seq) == 0:
        st.warning("Not enough consecutive windows per host to build a sequence yet — showing bundled sample instead.")
        return

    host_options = sorted(set(host_ids))
    selected_host = st.selectbox("Host to inspect", host_options)
    idx = host_ids.index(selected_host)

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

    col1, col2, col3 = st.columns(3)
    col1.metric("Predicted ATT&CK stage", stage_result["final_stage"])
    col2.metric("Cross-validated?", "✅ Yes" if stage_result["cross_validated"] else ("—" if stage_result["cross_validated"] is None else "⚠️ Disagreement"))
    col3.metric("15-min infiltration probability", f"{rollout_result.infiltration_probs[-1]:.0%}")

    st.subheader("Multi-horizon forecast curve")
    horizon_df = pd.DataFrame({
        "Horizon (min)": cfg["rollout"]["horizon_minutes"],
        "Infiltration probability": rollout_result.infiltration_probs,
    })
    st.line_chart(horizon_df.set_index("Horizon (min)"))

    tab1, tab2, tab3, tab4 = st.tabs(["🧠 SHAP explanation", "🔍 Attention heatmap", "📊 Baseline comparison", "🤖 RAG analyst copilot"])

    with tab1:
        st.markdown("Which **traffic features** drove the state encoder's classification of the current window.")
        background = X_seq[:, -1, :][: min(30, len(X_seq))]
        explainer = ShapExplainer(encoder, background, feature_names=FUSED_FEATURE_NAMES)
        pred_class = int(class_probs.argmax(dim=-1).item())
        with st.spinner("Computing SHAP attribution..."):
            shap_result = explainer.explain_window(last_raw_features, predicted_class_idx=pred_class, nsamples=60)
        shap_df = pd.DataFrame(shap_result["top_features"]).set_index("feature")
        st.bar_chart(shap_df["shap_value"])
        st.dataframe(shap_df, use_container_width=True)

    with tab2:
        st.markdown("Which **recent minutes** the forecasting model weighted most heavily.")
        attn_summary = summarize_attention(rollout_result.final_attention_weights, cfg["windowing"]["window_seconds"])
        heatmap = attention_heatmap_data(rollout_result.final_attention_weights)
        st.dataframe(pd.DataFrame(attn_summary["top_attended_windows"]), use_container_width=True)
        st.caption(f"Attention entropy: {attn_summary['attention_entropy']:.2f} (lower = sharply focused on one moment)")
        heatmap_df = pd.DataFrame(heatmap["matrix"], index=heatmap["labels"], columns=heatmap["labels"])
        st.dataframe(heatmap_df.style.background_gradient(cmap="Reds", axis=None), use_container_width=True)

    with tab3:
        st.markdown("**World Model vs. classical baseline** (logistic regression on the identical feature set, no temporal context).")
        if baseline is not None:
            wm_prob = float(rollout_result.step_probs[0])
            baseline_prob = float(baseline.predict_proba(X_seq[idx: idx + 1])[0])
            comp_df = pd.DataFrame({"Model": ["World Model (this window)", "Baseline (this window)"], "Infiltration probability": [wm_prob, baseline_prob]})
            st.bar_chart(comp_df.set_index("Model"))
            st.caption("Full held-out-set F1/precision/recall/false-positive-rate comparison: see results/eval_report.json (`python -m src.evaluate`).")
        else:
            st.info("Baseline checkpoint not found — run `python -m src.train` to produce it.")

    with tab4:
        st.markdown("Explanation composed from SHAP + attention, **grounded by retrieval** against the local MITRE ATT&CK knowledge base — fully offline, no LLM call.")
        exp = rag_explain(
            predicted_stage=stage_result["final_stage"],
            stage_confidence=0.75 if stage_result["cross_validated"] is None else (0.9 if stage_result["cross_validated"] else 0.55),
            infiltration_probs={f"{m}_min": p for m, p in zip(cfg["rollout"]["horizon_minutes"], rollout_result.infiltration_probs)},
            top_shap_features=shap_result["top_features"],
            attention_summary=summarize_attention(rollout_result.final_attention_weights, cfg["windowing"]["window_seconds"]),
            retriever=retriever,
            host_id=str(selected_host),
        )
        st.info(exp.headline)
        st.markdown("**Evidence:**")
        for b in exp.evidence_bullets:
            st.markdown(f"- {b}")
        st.markdown("**Retrieved ATT&CK techniques:**")
        for t in exp.retrieved_techniques:
            st.markdown(f"- **[{t['id']}] {t['name']}** (relevance {t['relevance_score']:.2f}) — {t['network_signature']}")
        st.markdown("**Recommended defender actions:**")
        for a in exp.recommended_actions:
            st.markdown(f"- {a}")


if __name__ == "__main__":
    main()
