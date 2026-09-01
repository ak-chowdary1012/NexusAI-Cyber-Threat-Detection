"""
src/explain/shap_explainer.py
Architecture ref: docs/architecture.md § 4.6 Explainability (SHAP half)

SHAP values explain *why* the state encoder's MLP classified a window the
way it did, in terms of the original engineered features (not the opaque
fused state vector) — an analyst can act on "SYN flag ratio was the top
driver," not on "latent dimension 7 was high." This is the feature-attribution
half of the explainability requirement; the attention half lives in
attention_viz.py and explains the *transition model's* forecast instead of
the encoder's classification. The spec requires both attached to every
output, so both are always computed together — see rag/copilot.py, which
consumes both to write the analyst-facing explanation.
"""
from __future__ import annotations

import numpy as np
import shap
import torch

from src.models.state_encoder import StateEncoder


class ShapExplainer:
    def __init__(self, state_encoder: StateEncoder, background_data: np.ndarray, feature_names: list[str]):
        """background_data: (n_background, input_dim) representative sample of
        window feature vectors (typically a random subset of the training set)
        used as SHAP's reference distribution. feature_names must match
        windowing.FUSED_FEATURE_NAMES order exactly."""
        self.state_encoder = state_encoder
        self.feature_names = feature_names
        state_encoder.eval()

        def predict_fn(x_numpy: np.ndarray) -> np.ndarray:
            with torch.no_grad():
                x_t = torch.tensor(x_numpy, dtype=torch.float32)
                return state_encoder.mlp.class_probabilities(x_t).numpy()

        background = shap.kmeans(background_data, min(10, len(background_data)))
        self.explainer = shap.KernelExplainer(predict_fn, background)

    def explain_window(self, feature_vector: np.ndarray, predicted_class_idx: int, nsamples: int = 100) -> dict:
        """Returns the top contributing features (by |SHAP value|) for the
        predicted class, ready to render as a bar chart or feed to the RAG
        copilot as grounding evidence."""
        shap_values = self.explainer.shap_values(
            feature_vector.reshape(1, -1), nsamples=nsamples, silent=True
        )
        # shap>=0.44 KernelExplainer returns array shaped (1, n_features, n_classes)
        # for multi-output models; normalize both shapes defensively.
        values = np.asarray(shap_values)
        if values.ndim == 3:
            per_class = values[0, :, predicted_class_idx]
        else:
            per_class = np.asarray(values)[predicted_class_idx][0]

        order = np.argsort(-np.abs(per_class))
        top = [
            {"feature": self.feature_names[i], "shap_value": float(per_class[i]), "raw_value": float(feature_vector[i])}
            for i in order[:15]
        ]
        return {"predicted_class_idx": predicted_class_idx, "top_features": top}
