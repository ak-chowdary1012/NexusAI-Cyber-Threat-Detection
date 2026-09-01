# Author: Avinash Krishna — Team AVV Elites (SIH26153)
"""
src/models/baseline.py
Architecture ref: docs/architecture.md § 4.7 Baseline Benchmark

Logistic regression on the *identical* feature set used by the World Model,
flattened to the most recent window only (no sequence, no temporal context).
This isolates exactly what the transition model's temporal modelling
contributes — the spec explicitly requires a benchmark against a classical
baseline to demonstrate measurable improvement, and this is that benchmark,
not a decorative comparison.
"""
from __future__ import annotations

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import f1_score, precision_score, recall_score, confusion_matrix


class BaselineModel:
    def __init__(self, cfg: dict):
        b_cfg = cfg["baseline"]
        self.model = LogisticRegression(
            class_weight=b_cfg["class_weight"],
            max_iter=b_cfg["max_iter"],
            random_state=cfg["project"]["seed"],
        )
        self._fitted = False

    @staticmethod
    def flatten_last_window(X_seq: np.ndarray) -> np.ndarray:
        """X_seq: (N, T, F) sequences as built by windowing.build_sequences.
        Returns (N, F) — only the most recent window, no temporal context,
        by design: this is what makes it a fair "no sequence modelling" baseline."""
        return X_seq[:, -1, :]

    def fit(self, X_seq: np.ndarray, y_binary: np.ndarray) -> "BaselineModel":
        X_flat = self.flatten_last_window(X_seq)
        self.model.fit(X_flat, y_binary)
        self._fitted = True
        return self

    def predict_proba(self, X_seq: np.ndarray) -> np.ndarray:
        assert self._fitted, "call fit() before predict_proba()"
        X_flat = self.flatten_last_window(X_seq)
        return self.model.predict_proba(X_flat)[:, 1]

    def evaluate(self, X_seq: np.ndarray, y_binary: np.ndarray, threshold: float = 0.5) -> dict[str, float]:
        probs = self.predict_proba(X_seq)
        preds = (probs >= threshold).astype(int)
        tn, fp, fn, tp = confusion_matrix(y_binary, preds, labels=[0, 1]).ravel()
        return {
            "f1": f1_score(y_binary, preds, zero_division=0),
            "precision": precision_score(y_binary, preds, zero_division=0),
            "recall": recall_score(y_binary, preds, zero_division=0),
            "false_positive_rate": fp / max(fp + tn, 1),
        }
