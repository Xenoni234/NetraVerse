"""Attack label -> MITRE ATT&CK stage, driven by data/mitre_mapping.yaml."""
from __future__ import annotations

from functools import lru_cache

from src.utils.config import MITRE_YAML, load_yaml

N_STAGES = 7
BENIGN = 0


@lru_cache(maxsize=1)
def _table() -> dict:
    return load_yaml(MITRE_YAML)


def stage_names() -> list[str]:
    st = _table()["stages"]
    return [st[i]["name"] for i in range(N_STAGES)]


def stage_info(stage_id: int) -> dict:
    s = _table()["stages"][int(stage_id)]
    return {"id": int(stage_id), "name": s["name"], "tactic_id": s["tactic_id"], "tactic": s["tactic"]}


def is_benign(label: str | None) -> bool:
    if label is None:
        return True
    lab = str(label).strip().lower()
    if lab.startswith("flow="):  # CTU-13 free-text labels
        return "botnet" not in lab
    return lab in _table()["benign_labels"]


@lru_cache(maxsize=4096)
def label_to_stage(label: str | None) -> int:
    """Map a raw dataset label to a stage id (0 = benign)."""
    if is_benign(label):
        return BENIGN
    lab = str(label).strip().lower()
    for rule in _table()["rules"]:
        if rule["match"] in lab:
            return int(rule["stage"])
    return int(_table()["default_attack_stage"])
