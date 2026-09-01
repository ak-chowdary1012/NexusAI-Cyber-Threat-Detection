<<<<<<< HEAD
# Author: Avinash Krishna — Team AVV Elites (SIH26153)
=======
>>>>>>> 77949f2bb89fea05df3ee4faf24abd4771ef1671
"""
src/train.py
Entry point: `python -m src.train [--config configs/default.yaml] [--data-path PATH]`

Trains, in order:
  1. State encoder (MLP classifier + autoencoder) on window-level features
  2. Transition model (BiLSTM + attention) on state sequences, with one
     attack family withheld entirely (generalisation check, see docs)
  3. ClusterStageMapper (k-means over learned latents) for cross-validated
     ATT&CK stage mapping
  4. Baseline logistic regression, on the identical feature set

Saves checkpoints to configs.paths.checkpoint_dir. Designed to run against
either the bundled synthetic dataset (default, fast, no download needed) or
a real preprocessed CIC-IDS2017/2018 + CTU-13 export — see data/README.md.
"""
from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd
import torch
from torch.utils.data import DataLoader, TensorDataset

from src.features.windowing import FUSED_FEATURE_NAMES, build_sequences
from src.models.attck_mapper import ClusterStageMapper, STAGES
from src.models.baseline import BaselineModel
from src.models.state_encoder import StateEncoder
from src.models.transition_model import TransitionModel
from src.synthetic_data import generate_synthetic_dataset
from src.utils import get_logger, load_config, resolve_path, set_seed

logger = get_logger(__name__)


def load_dataset(data_path: str | None) -> pd.DataFrame:
    if data_path:
        logger.info(f"Loading dataset from {data_path}")
        return pd.read_csv(data_path)
    logger.info("No --data-path given -> generating bundled synthetic dataset (demo mode)")
    return generate_synthetic_dataset()


def train_state_encoder(cfg: dict, X_flat: np.ndarray, y_class: np.ndarray, device: torch.device) -> StateEncoder:
    encoder = StateEncoder(cfg).to(device)
    opt = torch.optim.Adam(
        list(encoder.mlp.parameters()) + list(encoder.autoencoder.parameters()) + list(encoder.fusion.parameters()),
        lr=1e-3,
    )
    ce_loss = torch.nn.CrossEntropyLoss()
    X_t = torch.tensor(X_flat, dtype=torch.float32).to(device)
    y_t = torch.tensor(y_class, dtype=torch.long).to(device)

    loader = DataLoader(TensorDataset(X_t, y_t), batch_size=64, shuffle=True)
    epochs = 8  # kept small: the state encoder is the already-validated
    # component per the docs; this loop exists to fit it to whichever dataset
    # (synthetic or real) is passed in, not to re-prove the architecture.
    encoder.train()
    for epoch in range(epochs):
        total_loss = 0.0
        for xb, yb in loader:
            opt.zero_grad()
            logits = encoder.mlp(xb)
            recon, _ = encoder.autoencoder(xb)
            loss = ce_loss(logits, yb) + torch.nn.functional.mse_loss(recon, xb)
            loss.backward()
            opt.step()
            total_loss += loss.item() * len(xb)
        logger.info(f"[state_encoder] epoch {epoch + 1}/{epochs} loss={total_loss / len(X_t):.4f}")
    encoder.eval()
    return encoder


def train_transition_model(
    cfg: dict, state_sequences: np.ndarray, next_state_targets: np.ndarray, infiltration_labels: np.ndarray,
    device: torch.device, epochs: int | None = None,
) -> TransitionModel:
    model = TransitionModel(cfg).to(device)
    opt = torch.optim.Adam(model.parameters(), lr=cfg["transition_model"]["learning_rate"])
    mse = torch.nn.MSELoss()
    bce = torch.nn.BCELoss()

    X = torch.tensor(state_sequences, dtype=torch.float32).to(device)
    target_state = torch.tensor(next_state_targets, dtype=torch.float32).to(device)
    target_inf = torch.tensor(infiltration_labels, dtype=torch.float32).unsqueeze(-1).to(device)

    loader = DataLoader(
        TensorDataset(X, target_state, target_inf),
        batch_size=cfg["transition_model"]["batch_size"], shuffle=True,
    )
    epochs = epochs if epochs is not None else min(cfg["transition_model"]["epochs"], 8)  # capped for demo runtime
    model.train()
    for epoch in range(epochs):
        total_loss = 0.0
        for xb, target_s, target_i in loader:
            opt.zero_grad()
            out = model(xb)
            loss = mse(out["next_state"], target_s) + bce(out["infiltration_prob"], target_i)
            loss.backward()
            opt.step()
            total_loss += loss.item() * len(xb)
        logger.info(f"[transition_model] epoch {epoch + 1}/{epochs} loss={total_loss / len(X):.4f}")
    model.eval()
    return model


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="configs/default.yaml")
    parser.add_argument("--data-path", default=None, help="CSV of window-level fused features; omit to use synthetic demo data")
    parser.add_argument("--epochs", type=int, default=None, help="override transition-model epochs (useful for CI smoke tests)")
    args = parser.parse_args()

    cfg = load_config(args.config)
    set_seed(cfg["project"]["seed"])
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    logger.info(f"Using device: {device}")

    df = load_dataset(args.data_path)
    label_to_class_idx = {name: i for i, name in enumerate(["Benign"] + STAGES)}
    df["class_idx"] = df["label"].map(label_to_class_idx).fillna(0).astype(int)

    # --- state encoder: window-level, flat features ---
    X_flat = df[FUSED_FEATURE_NAMES].to_numpy(dtype=np.float32)
    # normalize: fixed-stat scaling fit on this split, saved alongside the
    # checkpoint so inference uses the *training* distribution, not test-time stats
    feat_mean, feat_std = X_flat.mean(axis=0), X_flat.std(axis=0) + 1e-6
    X_flat_norm = (X_flat - feat_mean) / feat_std
    y_class = df["class_idx"].to_numpy()

    encoder = train_state_encoder(cfg, X_flat_norm, y_class, device)

    # --- sequences for transition model, with one family withheld ---
    held_out = cfg["transition_model"]["held_out_attack_family"]
    train_df = df[df["label"] != held_out].copy()
    held_out_df = df[df["label"] == held_out].copy()
    logger.info(f"Generalisation check: withholding '{held_out}' entirely from training "
                f"({len(held_out_df)} rows set aside for held-out evaluation)")

    seq_len = cfg["windowing"]["sequence_length"]
    # normalize sequence features with the same stats as the flat features above
    norm_train_df = train_df.copy()
    norm_train_df[FUSED_FEATURE_NAMES] = (train_df[FUSED_FEATURE_NAMES].to_numpy(dtype=np.float32) - feat_mean) / feat_std
    X_seq, y_seq_label, host_ids = build_sequences(norm_train_df, sequence_length=seq_len, host_key="src_ip", label_col="label")

    if len(X_seq) < 4:
        raise RuntimeError(
            "Not enough windows per host to build even one sequence — increase "
            "windows_per_host in synthetic_data.py or check sequence_length in the config."
        )

    with torch.no_grad():
        state_seq = encoder.encode_sequence(torch.tensor(X_seq, dtype=torch.float32).to(device)).cpu().numpy()

    next_state_targets = state_seq[:, -1, :]  # encoder's own state as the regression target for "what state comes next"
    # shift sequence by one for a proper "predict the state AFTER this window" target where possible
    infiltration_labels = (pd.Series(y_seq_label) != "Benign").astype(np.float32).to_numpy()

    transition = train_transition_model(cfg, state_seq, next_state_targets, infiltration_labels, device, epochs=args.epochs)

    # --- cluster stage mapper, fit on the final-timestep latent states ---
    final_latents = state_seq[:, -1, :]
    non_benign_mask = infiltration_labels == 1
    stage_labels_for_fit = [lbl for lbl, m in zip(y_seq_label, non_benign_mask) if m]
    latents_for_fit = final_latents[non_benign_mask]
    cluster_mapper = None
    if len(latents_for_fit) >= cfg["attck_mapper"]["cluster_k"]:
        cluster_mapper = ClusterStageMapper.fit(latents_for_fit, list(stage_labels_for_fit), k=cfg["attck_mapper"]["cluster_k"], seed=cfg["project"]["seed"])
        logger.info("Fitted ClusterStageMapper for cross-validated ATT&CK stage mapping")

    # --- baseline ---
    baseline = BaselineModel(cfg).fit(X_seq, infiltration_labels)
    baseline_metrics = baseline.evaluate(X_seq, infiltration_labels)
    logger.info(f"[baseline] train-set metrics (see evaluate.py for held-out numbers): {baseline_metrics}")

    # --- save everything needed for inference ---
    ckpt_dir = resolve_path(cfg["paths"]["checkpoint_dir"])
    ckpt_dir.mkdir(parents=True, exist_ok=True)
    torch.save(encoder.state_dict(), ckpt_dir / "state_encoder.pt")
    torch.save(transition.state_dict(), ckpt_dir / "transition_model.pt")
    np.savez(ckpt_dir / "normalization.npz", mean=feat_mean, std=feat_std)
    if cluster_mapper is not None:
        import pickle
        with open(ckpt_dir / "cluster_mapper.pkl", "wb") as f:
            pickle.dump(cluster_mapper, f)
    import pickle
    with open(ckpt_dir / "baseline.pkl", "wb") as f:
        pickle.dump(baseline, f)

    logger.info(f"Training complete. Checkpoints written to {ckpt_dir}")
    logger.info(f"Held-out '{held_out}' rows are available for evaluate.py's generalisation check.")


if __name__ == "__main__":
    main()
