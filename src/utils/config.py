"""Project paths and YAML config loading. All roots resolve from here."""
from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "data"
RAW = DATA / "raw"
PROCESSED = DATA / "processed"
UPLOADS = DATA / "uploads"
MODELS = ROOT / "models"
REPORTS = ROOT / "reports"
CONFIGS = ROOT / "src" / "training" / "configs"
MITRE_YAML = DATA / "mitre_mapping.yaml"


def load_yaml(path: Path) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


@lru_cache(maxsize=None)
def world_model_config() -> dict[str, Any]:
    return load_yaml(CONFIGS / "world_model.yaml")


def env(name: str, default: str | None = None) -> str | None:
    return os.environ.get(name, default)
