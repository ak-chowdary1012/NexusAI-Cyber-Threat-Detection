# Author: Avinash Krishna — Team AVV Elites (SIH26153)
"""
src/models/state_encoder.py
Architecture ref: docs/architecture.md § 4.2 State Encoder

Repositions the prior validated detection engine (MLP classifier + deep
autoencoder) as the *state-representation* layer of the World Model, rather
than the final answer. Per window:
  - the MLP produces class probabilities over known attack families
  - the autoencoder produces a reconstruction-error anomaly score (catches
    attack types the MLP was never trained on)
  - both are fused with the raw engineered features into a compact latent
    state vector S_t (see StateEncoder.encode)

S_t is what feeds the transition model in transition_model.py — everything
downstream operates on this vector, never on raw features again.
"""
from __future__ import annotations

import torch
import torch.nn as nn
import torch.nn.functional as F


class MLPClassifier(nn.Module):
    """Known attack-family classifier. Architecture is a plain feed-forward
    net over window-level fused features — deliberately simple, because in
    a World Model the MLP's job is fast, reliable per-window classification,
    not the temporal reasoning (that's the transition model's job)."""

    def __init__(self, input_dim: int, hidden_dims: list[int], num_classes: int, dropout: float = 0.3):
        super().__init__()
        layers = []
        prev = input_dim
        for h in hidden_dims:
            layers += [nn.Linear(prev, h), nn.BatchNorm1d(h), nn.ReLU(), nn.Dropout(dropout)]
            prev = h
        self.backbone = nn.Sequential(*layers)
        self.classifier_head = nn.Linear(prev, num_classes)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """Returns raw logits, shape (batch, num_classes)."""
        return self.classifier_head(self.backbone(x))

    def class_probabilities(self, x: torch.Tensor) -> torch.Tensor:
        return F.softmax(self.forward(x), dim=-1)


class DeepAutoencoder(nn.Module):
    """Reconstruction-error novelty detector. Trained on benign-dominant
    traffic; a window that reconstructs poorly is behaving unlike anything
    the model has seen — the mechanism that catches unseen attack types the
    MLP's fixed class list cannot name."""

    def __init__(self, input_dim: int, hidden_dims: list[int], latent_dim: int, dropout: float = 0.1):
        super().__init__()
        enc_layers, prev = [], input_dim
        for h in hidden_dims:
            enc_layers += [nn.Linear(prev, h), nn.ReLU(), nn.Dropout(dropout)]
            prev = h
        enc_layers.append(nn.Linear(prev, latent_dim))
        self.encoder = nn.Sequential(*enc_layers)

        dec_layers, prev = [], latent_dim
        for h in reversed(hidden_dims):
            dec_layers += [nn.Linear(prev, h), nn.ReLU(), nn.Dropout(dropout)]
            prev = h
        dec_layers.append(nn.Linear(prev, input_dim))
        self.decoder = nn.Sequential(*dec_layers)

    def forward(self, x: torch.Tensor) -> tuple[torch.Tensor, torch.Tensor]:
        """Returns (reconstruction, latent)."""
        latent = self.encoder(x)
        recon = self.decoder(latent)
        return recon, latent

    def anomaly_score(self, x: torch.Tensor) -> torch.Tensor:
        """Per-sample reconstruction error (MSE), shape (batch,). Higher = more anomalous."""
        recon, _ = self.forward(x)
        return F.mse_loss(recon, x, reduction="none").mean(dim=-1)


class StateEncoder(nn.Module):
    """Wraps MLPClassifier + DeepAutoencoder and fuses their outputs with the
    raw engineered features into the state vector S_t consumed by the
    transition model. This is the only class other modules should import."""

    def __init__(self, cfg: dict):
        super().__init__()
        mlp_cfg = cfg["state_encoder"]["mlp"]
        ae_cfg = cfg["state_encoder"]["autoencoder"]
        self.state_vector_dim = cfg["state_encoder"]["state_vector_dim"]

        self.mlp = MLPClassifier(
            input_dim=mlp_cfg["input_dim"],
            hidden_dims=mlp_cfg["hidden_dims"],
            num_classes=mlp_cfg["num_classes"],
            dropout=mlp_cfg["dropout"],
        )
        self.autoencoder = DeepAutoencoder(
            input_dim=ae_cfg["input_dim"],
            hidden_dims=ae_cfg["hidden_dims"],
            latent_dim=ae_cfg["latent_dim"],
            dropout=ae_cfg["dropout"],
        )
        # fuse [class_probs (num_classes) + anomaly_score (1) + ae_latent (latent_dim)] -> state_vector_dim
        fusion_in = mlp_cfg["num_classes"] + 1 + ae_cfg["latent_dim"]
        self.fusion = nn.Sequential(
            nn.Linear(fusion_in, self.state_vector_dim),
            nn.LayerNorm(self.state_vector_dim),
            nn.Tanh(),  # bounded state vector — keeps the transition model's
            # input scale stable across a long rollout (see rollout.py)
        )

    def encode(self, x: torch.Tensor) -> torch.Tensor:
        """x: (batch, input_dim) raw fused window features -> (batch, state_vector_dim)."""
        class_probs = self.mlp.class_probabilities(x)
        recon, latent = self.autoencoder(x)
        anomaly = F.mse_loss(recon, x, reduction="none").mean(dim=-1, keepdim=True)
        fused = torch.cat([class_probs, anomaly, latent], dim=-1)
        return self.fusion(fused)

    def encode_sequence(self, x_seq: torch.Tensor) -> torch.Tensor:
        """x_seq: (batch, T, input_dim) -> (batch, T, state_vector_dim). Applies
        encode() at every timestep independently (the encoder has no memory —
        temporal reasoning is exclusively the transition model's job, keeping
        the two components' responsibilities cleanly separated)."""
        batch, T, F_dim = x_seq.shape
        flat = x_seq.reshape(batch * T, F_dim)
        encoded = self.encode(flat)
        return encoded.reshape(batch, T, self.state_vector_dim)
