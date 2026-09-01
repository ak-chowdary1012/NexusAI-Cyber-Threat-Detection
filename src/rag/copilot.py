"""
src/rag/copilot.py
Architecture ref: docs/architecture.md § 4.8 RAG-Grounded Decision Support

This is where explainability (SHAP + attention) and retrieval (retriever.py)
meet to produce the actual sentence an analyst reads, directly answering the
spec's requirement for "interpretable decision support for defenders" —
not just "a number and a chart," but "here's what's happening, here's the
evidence, here's what MITRE recommends doing about it, and here's why we
retrieved that specific guidance."

Deliberately template-based, not an LLM call: the offline hackathon-required
demo must run with zero outbound network calls, so generation here is
retrieval + deterministic composition, never a hosted model. The optional,
clearly-separate platform/ layer offers a richer LLM-generated version of
this same grounded context for deployed multi-analyst use — see
platform/backend/app/services/rag_service.py — but that is an enhancement
on top of, not a replacement for, this offline path.
"""
from __future__ import annotations

from dataclasses import dataclass

from src.rag.retriever import AttckRetriever


@dataclass
class CopilotExplanation:
    headline: str
    evidence_bullets: list[str]
    retrieved_techniques: list[dict]
    recommended_actions: list[str]


def build_query(predicted_stage: str, top_shap_features: list[dict], top_attention_windows: list[dict]) -> str:
    """Turns structured model evidence into a BM25 query string. Using the
    actual driving features (not just the stage name) lets retrieval
    distinguish, e.g., a beacon-pattern C2 case from a proxy-relay C2 case —
    both map to the same project_stage but should surface different
    techniques and different mitigations."""
    feature_terms = " ".join(f["feature"] for f in top_shap_features[:5])
    return f"{predicted_stage} {feature_terms}"


def explain(
    predicted_stage: str,
    stage_confidence: float,
    infiltration_probs: dict[str, float],   # e.g. {"1_min": 0.12, "5_min": 0.41, "15_min": 0.63}
    top_shap_features: list[dict],
    attention_summary: dict,
    retriever: AttckRetriever,
    host_id: str = "unknown host",
) -> CopilotExplanation:
    """Compose the full grounded explanation for one forecast. Every claim in
    `evidence_bullets` traces back to a concrete number computed elsewhere in
    the pipeline (SHAP value, attention weight, or retrieved technique) —
    nothing here is generated free-form."""
    query = build_query(predicted_stage, top_shap_features, attention_summary.get("top_attended_windows", []))
    hits = retriever.retrieve_for_stage(predicted_stage, query, top_k=3)

    horizon, prob = max(infiltration_probs.items(), key=lambda kv: kv[1])
    headline = (
        f"{host_id}: trending toward {predicted_stage} "
        f"({int(stage_confidence * 100)}% mapping confidence). "
        f"Infiltration probability reaches {prob:.0%} within the {horizon.replace('_', ' ')} horizon."
    )

    evidence_bullets = []
    for feat in top_shap_features[:3]:
        direction = "increased" if feat["shap_value"] > 0 else "decreased"
        evidence_bullets.append(
            f"Feature '{feat['feature']}' (value={feat['raw_value']:.3g}) {direction} the classification "
            f"score by {abs(feat['shap_value']):.3f} — the largest single driver in this window."
            if feat is top_shap_features[0] else
            f"'{feat['feature']}' (value={feat['raw_value']:.3g}) contributed {feat['shap_value']:+.3f}."
        )
    for w in attention_summary.get("top_attended_windows", [])[:2]:
        evidence_bullets.append(
            f"The forecasting model weighted the traffic from {w['minutes_ago']} min ago most heavily "
            f"(attention={w['attention_weight']:.2f}) when producing this forecast."
        )

    retrieved_techniques = [
        {
            "id": entry.id,
            "name": entry.name,
            "relevance_score": round(score, 3),
            "why_retrieved": f"Matches predicted stage '{predicted_stage}' and the observed feature pattern.",
            "network_signature": entry.network_signature,
        }
        for entry, score in hits
    ]

    recommended_actions = [f"[{e.id}] {e.mitigation}" for e, _ in hits]
    if not recommended_actions:
        recommended_actions = ["No specific technique matched with confidence — escalate for manual triage."]

    return CopilotExplanation(
        headline=headline,
        evidence_bullets=evidence_bullets,
        retrieved_techniques=retrieved_techniques,
        recommended_actions=recommended_actions,
    )


def explanation_to_dict(exp: CopilotExplanation) -> dict:
    """Serialization used by both the Streamlit demo and the platform API —
    single source of truth for the response shape so the two front ends
    never drift apart."""
    return {
        "headline": exp.headline,
        "evidence_bullets": exp.evidence_bullets,
        "retrieved_techniques": exp.retrieved_techniques,
        "recommended_actions": exp.recommended_actions,
    }
