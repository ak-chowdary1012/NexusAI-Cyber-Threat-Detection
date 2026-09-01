<<<<<<< HEAD
# Author: Avinash Krishna — Team AVV Elites (SIH26153)
=======
>>>>>>> 77949f2bb89fea05df3ee4faf24abd4771ef1671
"""
src/models/transition_model.py
Architecture ref: docs/architecture.md § 4.3 Transition Model — the World Model Core

This is the component that makes the system a World Model rather than a
classifier: it learns P(S_t+1 | S_t) over sequences of latent states produced
by the state encoder. A Bidirectional LSTM (2 layers, hidden=128 -> 256-dim
after concatenation) is followed by 4-head self-attention over the sequence.
The attention weights double as an explainability signal (see
src/explain/attention_viz.py) — this dual purpose is intentional, not a
side effect: the spec requires explainability attached to every forecast,
and re-using the mechanism that already improves accuracy avoids bolting on
a separate, disconnected "explanation" model that could tell a different
story than what actually drove the prediction.

A BiLSTM was chosen over a full Transformer encoder because, per
docs/architecture.md, a well-tuned BiLSTM is more reliably trainable inside
a 36-hour build window; the config is structured so swapping in a Transformer
encoder later only touches this one file.
"""
from __future__ import annotations

import torch
import torch.nn as nn


class MultiHeadSelfAttention(nn.Module):
    """Standard scaled dot-product multi-head self-attention, applied over the
    BiLSTM's output sequence. Returns both the attended representation and the
    raw attention weights (needed downstream for explainability)."""

    def __init__(self, embed_dim: int, num_heads: int, dropout: float = 0.0):
        super().__init__()
        self.mha = nn.MultiheadAttention(
            embed_dim=embed_dim, num_heads=num_heads, dropout=dropout, batch_first=True
        )

    def forward(self, x: torch.Tensor) -> tuple[torch.Tensor, torch.Tensor]:
        """x: (batch, T, embed_dim) -> (attended: (batch, T, embed_dim),
        attn_weights: (batch, T, T) averaged over heads by nn.MultiheadAttention)."""
        attended, attn_weights = self.mha(x, x, x, need_weights=True, average_attn_weights=True)
        return attended, attn_weights


class TransitionModel(nn.Module):
    """Learns state-transition dynamics over a sequence of latent states.

    forward() returns the predicted next-state distribution parameters (here,
    a point estimate of S_{t+1} plus an infiltration-probability head) along
    with attention weights for explainability. rollout() (below) chains
    forward() K times to simulate multiple steps into the future — see
    src/models/rollout.py for the forecast-horizon logic built on top of it.
    """

    def __init__(self, cfg: dict):
        super().__init__()
        tm_cfg = cfg["transition_model"]
        self.input_dim = tm_cfg["input_dim"]
        self.hidden_size = tm_cfg["hidden_size"]
        self.bidirectional = tm_cfg["bidirectional"]
        direction_mult = 2 if self.bidirectional else 1
        self.output_dim = self.hidden_size * direction_mult  # 256 with defaults

        self.lstm = nn.LSTM(
            input_size=self.input_dim,
            hidden_size=self.hidden_size,
            num_layers=tm_cfg["num_layers"],
            bidirectional=self.bidirectional,
            dropout=tm_cfg["dropout"] if tm_cfg["num_layers"] > 1 else 0.0,
            batch_first=True,
        )
        self.attention = MultiHeadSelfAttention(
            embed_dim=self.output_dim, num_heads=tm_cfg["attention_heads"], dropout=tm_cfg["dropout"]
        )
        self.layer_norm = nn.LayerNorm(self.output_dim)

        # Next-state prediction head: projects back to the state encoder's
        # dimensionality so rollout() can feed a predicted state back in as
        # the next timestep's input (the "simulate the future" step).
        self.next_state_head = nn.Sequential(
            nn.Linear(self.output_dim, self.output_dim // 2),
            nn.ReLU(),
            nn.Linear(self.output_dim // 2, self.input_dim),
            nn.Tanh(),  # matches the state encoder's bounded output range
        )
        # Infiltration-probability head: P(this trajectory is progressing
        # toward compromise), the number the rollout curve is built from.
        self.infiltration_head = nn.Sequential(
            nn.Linear(self.output_dim, 64),
            nn.ReLU(),
            nn.Dropout(tm_cfg["dropout"]),
            nn.Linear(64, 1),
            nn.Sigmoid(),
        )

    def forward(self, state_seq: torch.Tensor) -> dict[str, torch.Tensor]:
        """state_seq: (batch, T, input_dim) — a sequence of S_t from the state encoder.

        Returns a dict with:
          next_state: (batch, input_dim) predicted S_{t+1}
          infiltration_prob: (batch, 1) P(progressing toward compromise)
          attention_weights: (batch, T, T) for explainability
          context: (batch, output_dim) the pooled representation used by both heads
        """
        lstm_out, _ = self.lstm(state_seq)                    # (batch, T, output_dim)
        attended, attn_weights = self.attention(lstm_out)      # (batch, T, output_dim), (batch, T, T)
        context = self.layer_norm(attended[:, -1, :] + lstm_out[:, -1, :])  # residual, last timestep

        return {
            "next_state": self.next_state_head(context),
            "infiltration_prob": self.infiltration_head(context),
            "attention_weights": attn_weights,
            "context": context,
        }
