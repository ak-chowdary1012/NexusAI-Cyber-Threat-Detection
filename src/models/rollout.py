# Author: Avinash Krishna — Team AVV Elites (SIH26153)
"""
src/models/rollout.py
Architecture ref: docs/architecture.md § 4.4 K-Step Rollout — Infiltration Prediction Engine

Forward-simulates the trained TransitionModel K steps from the current state,
producing a time-series infiltration-probability curve across three forecast
horizons. With 30-second windows, K = [2, 10, 30] maps to [1, 5, 15] minutes —
this mapping lives in configs/default.yaml (rollout.k_steps /
rollout.horizon_minutes) and is read from there, never hard-coded, so the
demo, the dashboard, and the evaluation script can never drift out of sync
with each other.

This is the module that turns "a trained sequence model" into an actual
World Model in the Ha & Schmidhuber sense: something that can be asked "if
nothing intervenes, what happens next?" and answer by simulating forward in
its own learned latent space, not just scoring the traffic already observed.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np
import torch

from src.models.transition_model import TransitionModel


@dataclass
class RolloutResult:
    """Everything the dashboard/API needs to render one forecast."""
    horizon_minutes: list[int]
    infiltration_probs: list[float]           # one probability per horizon, monotone-checked below
    step_probs: list[float]                   # probability at *every* simulated step (for the curve plot)
    final_attention_weights: np.ndarray        # attention over the real (non-simulated) input sequence — explainability grounds itself in *observed* traffic, not imagined future steps
    simulated_states: np.ndarray = field(repr=False)  # (K_max, state_dim) — for downstream stage mapping


@torch.no_grad()
def k_step_rollout(
    model: TransitionModel,
    initial_sequence: torch.Tensor,
    k_steps: list[int],
    horizon_minutes: list[int],
) -> RolloutResult:
    """Simulate forward from `initial_sequence` for max(k_steps) steps.

    At each step, the model predicts next_state; that predicted state is
    appended to the sequence (sliding the window forward by one) and fed back
    in for the next step — an autoregressive rollout in latent space. The
    infiltration probability is read off at each of the requested k_steps.

    initial_sequence: (1, T, state_dim) — batch size 1 by design: a rollout
    is inherently a single trajectory simulation, batching would mix
    unrelated hosts' futures together.
    """
    assert initial_sequence.shape[0] == 1, "k_step_rollout simulates one host trajectory at a time"
    model.eval()

    max_k = max(k_steps)
    seq = initial_sequence.clone()
    step_probs: list[float] = []
    simulated_states = []
    final_attention = None

    for step in range(1, max_k + 1):
        out = model(seq)
        prob = float(out["infiltration_prob"].item())
        step_probs.append(prob)
        next_state = out["next_state"]                     # (1, state_dim)
        simulated_states.append(next_state.squeeze(0).cpu().numpy())

        if step == 1:
            # attention over the *real* observed window — this is what we
            # surface to the analyst, per the explainability docstring above
            final_attention = out["attention_weights"].squeeze(0).cpu().numpy()

        # slide the window: drop oldest timestep, append the simulated one
        seq = torch.cat([seq[:, 1:, :], next_state.unsqueeze(1)], dim=1)

    infiltration_probs = [step_probs[k - 1] for k in k_steps]
    # monotone smoothing for the reported horizon numbers only (the full
    # step_probs curve is left un-smoothed so the dashboard can show real
    # model variance) — a forecast that says "5-min risk lower than 1-min
    # risk" is confusing to an analyst, so we report the running max.
    running_max = []
    current_max = 0.0
    for p in infiltration_probs:
        current_max = max(current_max, p)
        running_max.append(current_max)

    return RolloutResult(
        horizon_minutes=horizon_minutes,
        infiltration_probs=running_max,
        step_probs=step_probs,
        final_attention_weights=final_attention,
        simulated_states=np.stack(simulated_states),
    )


def rollout_from_config(model: TransitionModel, initial_sequence: torch.Tensor, cfg: dict) -> RolloutResult:
    """Convenience wrapper reading k_steps/horizon_minutes straight from config."""
    r_cfg = cfg["rollout"]
    return k_step_rollout(
        model=model,
        initial_sequence=initial_sequence,
        k_steps=r_cfg["k_steps"],
        horizon_minutes=r_cfg["horizon_minutes"],
    )
