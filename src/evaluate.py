<<<<<<< HEAD
# Author: Avinash Krishna — Team AVV Elites (SIH26153)
=======
>>>>>>> 77949f2bb89fea05df3ee4faf24abd4771ef1671
"""
src/evaluate.py
Entry point: `python -m src.evaluate [--config configs/default.yaml] [--data-path PATH]`

Loads the checkpoints written by train.py and reports exactly the numbers
the spec and docs/architecture.md promise:
  - F1 / precision / recall / false-positive-rate, World Model vs baseline,
    side by side (§4.7 requirement)
  - Held-out attack-family performance (generalisation check, §4.3)
  - ATT&CK rule-based vs cluster-based agreement rate (§4.5 requirement)

Writes results/eval_report.json so docs/demo_script.md and the dashboard can
both read the same numbers instead of restating them by hand.
"""
from __future__ import annotations

import argparse
import json
import pickle

import numpy as np
import pandas as pd
import torch
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score

from src.features.windowing import FUSED_FEATURE_NAMES, build_sequences
from src.models.attck_mapper import agreement_rate, map_trajectory_to_stage
from src.models.state_encoder import StateEncoder
from src.models.transition_model import TransitionModel
from src.synthetic_data import generate_synthetic_dataset
from src.utils import get_logger, load_config, resolve_path, set_seed

logger = get_logger(__name__)


def binary_metrics(y_true: np.ndarray, y_prob: np.ndarray, threshold: float = 0.5) -> dict[str, float]:
    y_pred = (y_prob >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    return {
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "false_positive_rate": float(fp / max(fp + tn, 1)),
        "n_samples": int(len(y_true)),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="configs/default.yaml")
    parser.add_argument("--data-path", default=None)
    args = parser.parse_args()

    cfg = load_config(args.config)
    set_seed(cfg["project"]["seed"])
    device = torch.device("cpu")  # evaluation is cheap enough to always run on CPU, keeps CI simple

    ckpt_dir = resolve_path(cfg["paths"]["checkpoint_dir"])
    if not (ckpt_dir / "state_encoder.pt").exists():
        raise FileNotFoundError(f"No checkpoints in {ckpt_dir} — run `python -m src.train` first.")

    df = pd.read_csv(args.data_path) if args.data_path else generate_synthetic_dataset(seed=cfg["project"]["seed"] + 1)
    # NOTE: a different seed than train.py's synthetic call above so the demo
    # evaluation isn't silently scored on its own training data.

    norm = np.load(ckpt_dir / "normalization.npz")
    feat_mean, feat_std = norm["mean"], norm["std"]
    df_norm = df.copy()
    df_norm[FUSED_FEATURE_NAMES] = (df[FUSED_FEATURE_NAMES].to_numpy(dtype=np.float32) - feat_mean) / feat_std

    encoder = StateEncoder(cfg).to(device)
    encoder.load_state_dict(torch.load(ckpt_dir / "state_encoder.pt", map_location=device))
    encoder.eval()

    transition = TransitionModel(cfg).to(device)
    transition.load_state_dict(torch.load(ckpt_dir / "transition_model.pt", map_location=device))
    transition.eval()

    seq_len = cfg["windowing"]["sequence_length"]
    X_seq, y_seq_label, host_ids = build_sequences(df_norm, sequence_length=seq_len, host_key="src_ip", label_col="label")
    y_binary = (pd.Series(y_seq_label) != "Benign").astype(int).to_numpy()

    with torch.no_grad():
        state_seq = encoder.encode_sequence(torch.tensor(X_seq, dtype=torch.float32)).numpy()
        world_model_probs = transition(torch.tensor(state_seq, dtype=torch.float32))["infiltration_prob"].numpy().ravel()

    world_model_metrics = binary_metrics(y_binary, world_model_probs)
    logger.info(f"World Model metrics: {world_model_metrics}")

    baseline_metrics = None
    if (ckpt_dir / "baseline.pkl").exists():
        with open(ckpt_dir / "baseline.pkl", "rb") as f:
            baseline = pickle.load(f)
        baseline_probs = baseline.predict_proba(X_seq)
        baseline_metrics = binary_metrics(y_binary, baseline_probs)
        logger.info(f"Baseline (logistic regression) metrics: {baseline_metrics}")

    held_out = cfg["transition_model"]["held_out_attack_family"]
    held_out_mask = pd.Series(y_seq_label) == held_out
    generalisation = None
    if held_out_mask.any():
        generalisation = binary_metrics(y_binary[held_out_mask.to_numpy()], world_model_probs[held_out_mask.to_numpy()])
        logger.info(f"Generalisation check on withheld '{held_out}' family: {generalisation}")
    else:
        logger.warning(f"No '{held_out}' rows found in this evaluation set — generalisation check skipped.")

    # --- ATT&CK stage-mapping agreement rate ---
    cluster_mapper = None
    if (ckpt_dir / "cluster_mapper.pkl").exists():
        with open(ckpt_dir / "cluster_mapper.pkl", "rb") as f:
            cluster_mapper = pickle.load(f)

    rule_labels, cluster_labels = [], []
    malicious_idx = np.where(y_binary == 1)[0]
    for i in malicious_idx[: min(500, len(malicious_idx))]:  # cap for demo runtime
        last_features = X_seq[i, -1, :]
        latent = state_seq[i, -1, :]
        result = map_trajectory_to_stage(last_features, latent, cluster_mapper)
        rule_labels.append(result["rule_based_stage"])
        cluster_labels.append(result["cluster_stage"] or result["rule_based_stage"])
    attck_agreement = agreement_rate(rule_labels, cluster_labels) if rule_labels else None
    logger.info(f"ATT&CK rule-based vs cluster-based agreement rate: {attck_agreement}")

    report = {
        "world_model": world_model_metrics,
        "baseline": baseline_metrics,
        "generalisation_check": {"held_out_family": held_out, "metrics": generalisation},
        "attck_stage_agreement_rate": attck_agreement,
        "improvement_over_baseline_f1": (
            round(world_model_metrics["f1"] - baseline_metrics["f1"], 4) if baseline_metrics else None
        ),
    }

    results_dir = resolve_path("results")
    results_dir.mkdir(exist_ok=True)
    with open(results_dir / "eval_report.json", "w") as f:
        json.dump(report, f, indent=2)
    logger.info(f"Wrote {results_dir / 'eval_report.json'}")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
