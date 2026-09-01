<<<<<<< HEAD
# Author: Avinash Krishna — Team AVV Elites (SIH26153)
=======
>>>>>>> 77949f2bb89fea05df3ee4faf24abd4771ef1671
"""
src/utils.py

Shared helpers used across the pipeline: config loading, deterministic
seeding, and a consistent logging format. Every training/eval entry point
calls set_seed() first so runs are reproducible, per the code-quality bar
in docs/architecture.md.
"""
from __future__ import annotations

import logging
import os
import random
from pathlib import Path
from typing import Any

import numpy as np
import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def load_config(config_path: str | Path = "configs/default.yaml") -> dict[str, Any]:
    """Load the YAML config as a plain dict. Paths inside are left relative;
    resolve_path() below turns them into absolute paths against PROJECT_ROOT."""
    path = Path(config_path)
    if not path.is_absolute():
        path = PROJECT_ROOT / path
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def resolve_path(relative: str | Path) -> Path:
    """Resolve a path from the config against the project root, creating
    parent directories if they don't exist (safe for output paths)."""
    p = PROJECT_ROOT / relative
    return p


def set_seed(seed: int = 42) -> None:
    """Seed every source of randomness we touch. Deep-learning code additionally
    seeds torch when it's the active backend (see models/*.py)."""
    random.seed(seed)
    np.random.seed(seed)
    os.environ["PYTHONHASHSEED"] = str(seed)
    try:
        import torch

        torch.manual_seed(seed)
        torch.cuda.manual_seed_all(seed)
        # Deterministic algorithms where available; falls back silently on
        # platforms/ops that don't support it rather than crashing a demo run.
        torch.use_deterministic_algorithms(True, warn_only=True)
    except ImportError:
        pass


def get_logger(name: str, level: int = logging.INFO) -> logging.Logger:
    """Consistent logger: timestamp, module, level, message. Used by every
    module instead of print() so a real run produces a readable, greppable log."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(
            logging.Formatter(
                fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )
        logger.addHandler(handler)
        logger.setLevel(level)
        logger.propagate = False
    return logger
