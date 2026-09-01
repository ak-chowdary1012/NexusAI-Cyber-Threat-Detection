# NexusAI Forecast — Architecture

**SIH26153** · AI-based Network Attack Forecasting from Network Traffic Data · Team AVV Elites
<<<<<<< HEAD
Author: Avinash Krishna
=======
>>>>>>> 77949f2bb89fea05df3ee4faf24abd4771ef1671

## 1. Problem framing

Static intrusion classification answers "was this traffic malicious?" after the fact. A **World Model**, in the Ha & Schmidhuber sense, answers a different question: *given how this network has been behaving, what is it likely to do next?* This system learns network-state dynamics from traffic telemetry and simulates forward in its own learned latent space to forecast the probability and kill-chain stage of attacker progression **before compromise completes** — the explicit ask in the problem statement.

## 2. Pipeline

```
Traffic → Feature Extraction (dual-level) → State Encoder → Transition Model → K-Step Rollout
                                                                                       │
                                                              ┌────────────────────────┼────────────────┐
                                                              ▼                        ▼                ▼
                                                    ATT&CK Stage Mapper      SHAP + Attention    RAG-Grounded
                                                    (cross-validated)         Explainability      Copilot
```

**Feature extraction** (`src/features/`) is dual-level by design: flow-level aggregates (NetFlow/IPFIX-style — volumetric behaviour, floods, scans-by-volume) *and* packet-level features from raw PCAP via Scapy (TTL variance, TCP window behaviour, fragmentation, retransmissions, port-scan signatures) — catching the slow, low-volume reconnaissance that flow-level alone misses. Windowed at 30s with 50% overlap into 20-window (10-minute) sequences.

**State encoder** (`src/models/state_encoder.py`) repositions a validated detection engine — an MLP classifier over known attack families plus a deep autoencoder for reconstruction-error novelty detection — as a *representation* layer, not the final answer. Class probabilities, anomaly score, and the autoencoder's latent are fused into a compact state vector S_t. This is the only point where raw features are touched; everything downstream operates on S_t.

**Transition model** (`src/models/transition_model.py`) is the World Model core: a 2-layer Bidirectional LSTM (hidden=128, →256 after concatenation) followed by 4-head self-attention over the state sequence, learning P(S_t+1 | S_t). The attention weights double as the temporal-explainability signal — deliberately reused rather than bolted on separately, so the explanation can never tell a different story than what actually drove the prediction.

**K-step rollout** (`src/models/rollout.py`) autoregressively feeds the transition model's own predicted next-state back in as input, simulating forward K ∈ {2, 10, 30} steps (1/5/15-minute horizons) to produce a monotone infiltration-probability curve — the actual "forecast," not just a single-window classification.

**ATT&CK stage mapper** (`src/models/attck_mapper.py`) combines two independent signals: interpretable rule-based signatures on raw features (fast, auditable, zero training cost) and k-means clusters over the *learned* latent states (fit on CTU-13's labelled multi-stage scenarios). Their agreement rate is reported in `results/eval_report.json` — this is what makes the mapping a validated claim rather than an assertion.

**Explainability** (`src/explain/`) is two channels, always computed together: SHAP attribution (which *traffic features* drove the classification) and attention summarization (which *recent minutes* drove the forecast).

**RAG-grounded decision support** (`src/rag/`, new addition beyond the minimum spec) is where explainability becomes actionable. A local knowledge base of MITRE ATT&CK techniques is retrieved via BM25 — lexical, not neural-embedding, search, chosen specifically because it requires no model download and keeps the system's "fully offline, zero outbound calls" property intact, while remaining a strong, standard choice for keyword-dense technical text like ATT&CK technique names. Retrieval is constrained to the predicted stage, then ranked by relevance to the specific driving features, so a beacon-pattern C2 case and a proxy-relay C2 case (same stage, different evidence) surface different techniques. The resulting explanation is composed deterministically from retrieved evidence — every claim traces to a SHAP value, an attention weight, or a retrieved technique ID; nothing is free-form generated in the offline path.

**Baseline** (`src/models/baseline.py`): logistic regression on the identical feature set, flattened to the most recent window only (no temporal context) — isolates exactly what the transition model's sequence modelling contributes.

## 3. Two deployment surfaces, one pipeline

The problem statement specifies a fully offline, single-analyst tool (`app/streamlit_app.py` — zero outbound network calls, PCAP/CSV upload, runs on a laptop). To also demonstrate genuine deployment readiness — explicitly part of this project's own viability argument ("piloted on one network segment before wider SOC rollout") — `platform/` adds a secure, multi-analyst web platform (FastAPI + Postgres, JWT auth, per-organization data isolation, rate limiting, audit logging; full design in `SECURITY.md`) that imports and calls the *same* `src/` pipeline rather than reimplementing it. The two surfaces can never report different numbers because there is only one implementation.

## 4. Validation strategy

- **Generalisation check**: one attack family withheld entirely from training, evaluated separately (`configs/default.yaml: transition_model.held_out_attack_family`).
- **Baseline comparison**: World Model vs. logistic regression, same features, on the same held-out split — F1/precision/recall/false-positive-rate side by side.
- **ATT&CK mapping agreement rate**: rule-based vs. cluster-based stage prediction, measured, not assumed.
- **End-to-end test suite** (`tests/`, `platform/backend/tests/`): 9 pipeline tests + 26 platform tests (including explicit cross-organization IDOR regression tests) — all passing against the real trained pipeline, not mocks.

## 5. Known limitations

- Bundled synthetic data (`src/synthetic_data.py`) is a wiring/demo fixture with cleanly separated profiles, not a benchmark — real numbers require CIC-IDS2017/2018 and CTU-13 (see `data/README.md`).
- The RAG knowledge base is a curated, hand-verified seed set (~20 techniques across the 5 tracked stages), not the full ATT&CK corpus; `src/rag/knowledge_base.py::sync_from_stix()` is the documented path to full coverage.
- Rule-based ATT&CK thresholds (`attck_mapper.py`) are simple and auditable by design, tuned for clarity over the training data available in a hackathon timeframe — the cross-validation against learned clusters is the intended check on their limits, not a claim they're optimal.
