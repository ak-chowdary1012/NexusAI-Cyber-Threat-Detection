# data/

<<<<<<< HEAD
*NexusAI Forecast — Team AVV Elites · Author: Avinash Krishna*

=======
>>>>>>> 77949f2bb89fea05df3ee4faf24abd4771ef1671
This directory is git-ignored except for `.gitkeep` placeholders — the real
datasets are multi-gigabyte and don't belong in version control.

## Using the bundled synthetic sample (default, no download needed)

```bash
python -m src.synthetic_data
```

Writes `data/synthetic/synthetic_traffic.csv` — a small, labelled dataset
with realistic-shaped feature distributions per kill-chain stage. Every
script in this repo (`train.py`, `evaluate.py`, `app/streamlit_app.py`)
falls back to generating this automatically if no `--data-path` is given, so
the whole pipeline runs out of the box.

**This is a development/demo fixture, not a benchmark result.** The metrics
it produces (see `results/eval_report.json`) show the *pipeline is wired up
correctly*, not that the model performs well on real traffic — the profiles
are cleanly separated by construction. Report real numbers from the datasets
below.

## Using the real datasets

Per the problem statement's dataset guidance, place preprocessed exports under:

```
data/raw/           # original downloads (PCAP / CSV, as distributed)
data/processed/     # after running your preprocessing into the schema
                     # src/features/flow_features.py and packet_features.py expect
```

Recommended sources:
- **CIC-IDS2017 / CIC-IDS2018** — Canadian Institute for Cybersecurity. Flow-level exports are CICFlowMeter CSVs; `src/features/flow_features.py::normalize_columns()` already maps CICFlowMeter's column-naming conventions (both the 2017 and 2018 export variants) onto this project's schema.
- **CTU-13** — multi-stage labelled botnet scenarios; used here specifically to fit `ClusterStageMapper` (`src/models/attck_mapper.py`) against real kill-chain-labelled traffic, and for the generalisation check in `train.py`.
- **UNSW-NB15, CICIoT2023, LANL Authentication Dataset, DARPA Intrusion Detection datasets** — named as additional options in the official problem statement; not used in this reference implementation, but `src/features/flow_features.py::normalize_columns()` is the one place to extend if you add one (map its column names onto the canonical schema there).
- **MITRE ATT&CK / CAPEC / CVE / NVD** — used to build the RAG knowledge base (`src/rag/`); see `src/rag/knowledge_base.py::sync_from_stix()` to regenerate a full-coverage knowledge base from the official STIX corpus.

Then run:
```bash
python -m src.train --data-path data/processed/your_export.csv
python -m src.evaluate --data-path data/processed/your_export.csv
```

## Dataset contact (per the official problem statement)

- Check nciipc.gov.in
- helpdesk1@nciipc.gov.in
