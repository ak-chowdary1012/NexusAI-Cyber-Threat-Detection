# Demo Script (target: 2:00)

Shot list for the required demo video. Timings are guidance, not a hard
script — practice once with a screen recorder before the real take.

| Time | Screen | Say |
|---|---|---|
| 0:00–0:15 | Title slide / terminal | "NexusAI Forecast — SIH26153. Most intrusion detection tells you what already happened. We built a World Model that forecasts what happens *next* — before compromise completes." |
| 0:15–0:35 | Terminal: `python -m src.train` running, then `streamlit run app/streamlit_app.py` | "It's a World Model: it learns how network state evolves, then simulates forward in that learned space. Fully offline — no cloud calls, nothing leaves the machine. Here it's training in under a minute on a sample dataset." |
| 0:35–1:00 | Streamlit dashboard, host selected, forecast curve visible | "Here's a host trending toward compromise. The curve shows infiltration probability at 1, 5, and 15 minutes out — not just 'malicious or not,' but *how fast this is moving*. It's already mapped to a MITRE ATT&CK stage — Reconnaissance here — cross-validated two independent ways so this isn't just an assertion." |
| 1:00–1:20 | SHAP tab, then Attention tab | "Every forecast is explained two ways: SHAP shows which traffic features drove it — port-scan score, unique destination ports — and attention shows which recent minutes the model weighted most heavily." |
| 1:20–1:45 | RAG Copilot tab | "And this is retrieval-augmented decision support: it retrieves the matching MITRE ATT&CK techniques from a local knowledge base and hands the analyst concrete, cited mitigations — not a black box, not a hallucination, every line traces back to real evidence." |
| 1:45–2:00 | Quick cut: secure platform login screen → dashboard | "We didn't stop at the hackathon spec — we also built a secure, multi-analyst deployment on top: authentication, per-organization data isolation, rate limiting, full audit logging. Same pipeline, production-ready. Thank you." |

## B-roll / cutaway shots if you have extra time
- `results/eval_report.json` on screen (World Model vs. baseline numbers)
- `pytest tests/ -v` passing (ml_core) and `pytest platform/backend/tests/ -v` passing (26/26, including IDOR tests)
- The architecture diagram from `ARCHITECTURE.md`

## Recording notes
- Record the terminal and Streamlit app at 1080p minimum; zoom in during
  the SHAP/attention/copilot tabs so text is legible on a phone screen.
- Pre-train the model before recording (`python -m src.train`) so you don't
  burn video time waiting — cut to a sped-up clip of it running instead, as
  suggested at 0:15.
- If recording the secure platform for the final 15 seconds, pre-seed one
  organization/segment/forecast beforehand so the dashboard isn't empty on camera.
