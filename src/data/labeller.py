"""Labelling: binary attack, canonical family, ATT&CK stage, distance-to-attack.

Implements the labelling schema in CLAUDE.md section 6.

``binary_label``        0 (benign) / 1 (attack), from the source ``Label`` column
``attack_family``       canonical family, via ``mitre.stage_mapping``
``attt_stage``          0..5 ATT&CK stage, or ``STAGE_MASKED`` (-1)
``distance_to_attack``  flows/windows until the next attack; 0 inside an attack,
                        ``NO_FUTURE_ATTACK`` (-1) when none follows

Invariants
----------
* Labels are computed on the raw, unshuffled, time-ordered frame.
* ``distance_to_attack`` never crosses a ``campaign_id`` boundary.
* No row is ever relabelled to balance classes — that is the loss's job.

.. note::
   For the flow-level LR baseline only ``binary_label`` is used.
   ``distance_to_attack`` is defined here in flow-index units; once windowing
   lands it is redefined in **windows**, which is what CLAUDE.md section 6
   specifies. The function takes a ``unit`` argument so the change is explicit
   rather than silent.
"""

from __future__ import annotations

import logging
from typing import Final, Mapping

import numpy as np
import pandas as pd

from src.mitre import stage_mapping

log = logging.getLogger(__name__)

#: Column names this module writes.
BINARY_LABEL: Final[str] = "binary_label"
FAMILY_LABEL: Final[str] = "attack_family"
STAGE_LABEL: Final[str] = "attt_stage"
DISTANCE_LABEL: Final[str] = "distance_to_attack"

#: Sentinel stored in ``distance_to_attack`` when no attack follows.
NO_FUTURE_ATTACK: Final[int] = -1


def label_frame(
    frame: pd.DataFrame,
    *,
    dataset: str = "cicids2018",
    label_col: str = "label_raw",
    campaign_col: str = "campaign_id",
    add_distance: bool = True,
    strict: bool = False,
    verbose: bool = True,
) -> pd.DataFrame:
    """Attach all label columns to a unified flow frame.

    Args:
        frame: Time-ordered unified flow records.
        dataset: Source dataset, selects the raw-label vocabulary.
        label_col: Column holding the source label text.
        campaign_col: Campaign key; distances never cross it.
        add_distance: Compute ``distance_to_attack`` (needs time ordering).
        strict: Raise on an unmapped raw label instead of warning.
        verbose: Print a label summary.

    Returns:
        A copy of ``frame`` with the four label columns added.
    """
    if label_col not in frame.columns:
        raise KeyError(f"{label_col!r} not in frame; columns: {sorted(frame.columns)[:20]}")

    out = frame.copy()
    raw = out[label_col].astype("string").str.strip()

    out[FAMILY_LABEL] = normalise_attack_family(raw, dataset=dataset, strict=strict)
    out[BINARY_LABEL] = label_binary(out[FAMILY_LABEL]).astype("int8")
    out[STAGE_LABEL] = stage_mapping.map_families(out[FAMILY_LABEL]).astype("int64")

    # Attack families with no valid stage keep binary_label=1 but carry the
    # masking sentinel, so the stage head can ignore them. CLAUDE.md 10-E.
    masked = out[FAMILY_LABEL].map(
        lambda f: stage_mapping.FAMILY_TO_STAGE.get(f) == stage_mapping.STAGE_MASKED
    )
    out.loc[masked, STAGE_LABEL] = stage_mapping.STAGE_MASKED

    if add_distance:
        out[DISTANCE_LABEL] = compute_distance_to_attack(out, campaign_col=campaign_col)

    if verbose:
        summary = label_summary(out)
        print(
            f"  [labeller] {summary['n_rows']:,} rows | "
            f"attack rate {summary['attack_rate']:.2%} | "
            f"{summary['n_families']} families"
        )
        for family, count in summary["family_counts"].items():
            stage = stage_mapping.FAMILY_TO_STAGE.get(family, stage_mapping.UNKNOWN_STAGE)
            print(
                f"           {family:<20} {count:>10,}  "
                f"-> {stage_mapping.stage_name(stage)}"
            )

    return out


def normalise_attack_family(
    raw_labels: pd.Series, *, dataset: str = "cicids2018", strict: bool = False
) -> pd.Series:
    """Normalise source label text into a canonical attack-family string.

    Benign rows map to ``"BENIGN"``. Unknown labels map to ``"UNKNOWN"`` and are
    logged once — never silently absorbed into benign, which would delete
    attacks from the training set.
    """
    cleaned = raw_labels.astype("string").str.strip()

    if dataset == "cicids2018":
        mapped = cleaned.map(stage_mapping.CICIDS2018_LABEL_TO_FAMILY)
    elif dataset == "cicids2017":
        # 2017 needs the web-attack prefix rule (en-dash in source), so map via
        # the function rather than a plain dict.
        mapped = cleaned.map(
            lambda v: stage_mapping.cicids2017_family(v) if v is not None else None
        )
        mapped = mapped.replace("UNKNOWN", pd.NA)
    elif dataset == "ctu13":
        mapped = cleaned.map(
            lambda v: stage_mapping.ctu13_family(v) if v is not None else None
        )
    elif dataset == "unsw_nb15":
        mapped = cleaned.map(
            lambda v: stage_mapping.unsw_nb15_family(v) if v is not None else None
        )
    else:
        raise NotImplementedError(f"No label vocabulary for {dataset!r} yet")

    unknown = cleaned[mapped.isna()].dropna().unique().tolist()
    if unknown:
        if strict:
            raise KeyError(
                f"Unmapped {dataset} labels: {sorted(unknown)}. "
                f"Add them to stage_mapping."
            )
        log.warning("Unmapped %s labels -> 'UNKNOWN': %s", dataset, sorted(unknown))
        mapped = mapped.fillna("UNKNOWN")

    return mapped.astype("string")


def label_binary(family: pd.Series) -> pd.Series:
    """0 for ``BENIGN``, 1 for everything else.

    ``UNKNOWN`` counts as an attack: an unmapped label is far more likely to be
    a new attack family than mislabelled benign traffic, and treating it as
    benign would hide it.
    """
    return (family.astype("string") != "BENIGN").astype("int8")


def compute_distance_to_attack(
    frame: pd.DataFrame,
    *,
    campaign_col: str = "campaign_id",
    binary_col: str = BINARY_LABEL,
    unit: str = "rows",
) -> pd.Series:
    """Steps from each row to the next attack row within the same campaign.

    ``0`` inside an attack, ``k`` when the next attack is ``k`` steps later,
    :data:`NO_FUTURE_ATTACK` when no attack follows in that campaign.

    Args:
        frame: Time-ordered frame carrying ``binary_col`` and ``campaign_col``.
        campaign_col: Grouping key; distance never crosses it.
        binary_col: The 0/1 attack column.
        unit: ``"rows"`` (flow-level, current) or ``"windows"`` (after windowing
            lands). Present so the redefinition is explicit — see the module note.

    Returns:
        Int64 series aligned to ``frame.index``.
    """
    if unit not in {"rows", "windows"}:
        raise ValueError(f"unit must be 'rows' or 'windows', got {unit!r}")

    out = pd.Series(NO_FUTURE_ATTACK, index=frame.index, dtype="int64")
    group_key = frame[campaign_col] if campaign_col in frame.columns else pd.Series(
        "all", index=frame.index
    )

    for _, idx in frame.groupby(group_key, sort=False).groups.items():
        labels = np.asarray(idx)
        is_attack = frame.loc[labels, binary_col].to_numpy().astype(bool)
        n = len(is_attack)
        if n == 0:
            continue

        # Vectorised forward-looking scan. `attack_at` holds the positions of
        # attack rows; searchsorted finds, for every position, the first attack
        # at or after it. A row that is itself an attack finds itself -> 0.
        attack_at = np.flatnonzero(is_attack)
        if attack_at.size == 0:
            continue
        positions = np.arange(n)
        nxt = np.searchsorted(attack_at, positions, side="left")
        has_future = nxt < attack_at.size
        distance = np.full(n, NO_FUTURE_ATTACK, dtype="int64")
        distance[has_future] = attack_at[nxt[has_future]] - positions[has_future]
        out.loc[labels] = distance

    return out


def class_weights(labels: pd.Series | np.ndarray, *, n_classes: int | None = None) -> np.ndarray:
    """Inverse-frequency class weights, normalised to mean 1.

    Fit on the TRAIN split only, then frozen.
    """
    values = np.asarray(labels)
    values = values[values >= 0]  # drop masked stages
    n_classes = n_classes or int(values.max()) + 1
    counts = np.bincount(values.astype(int), minlength=n_classes).astype("float64")
    counts[counts == 0] = np.nan
    weights = np.nanmean(counts) / counts
    return np.nan_to_num(weights, nan=0.0)


def label_summary(frame: pd.DataFrame) -> Mapping[str, object]:
    """Label statistics for logging and notebooks."""
    families = frame[FAMILY_LABEL].value_counts()
    return {
        "n_rows": int(len(frame)),
        "attack_rate": float(frame[BINARY_LABEL].mean()) if len(frame) else 0.0,
        "n_attacks": int(frame[BINARY_LABEL].sum()),
        "n_families": int(families.size),
        "family_counts": {str(k): int(v) for k, v in families.items()},
        "stage_counts": {
            stage_mapping.stage_name(int(k)): int(v)
            for k, v in frame[STAGE_LABEL].value_counts().items()
        },
    }


__all__ = [
    "BINARY_LABEL",
    "FAMILY_LABEL",
    "STAGE_LABEL",
    "DISTANCE_LABEL",
    "NO_FUTURE_ATTACK",
    "label_frame",
    "normalise_attack_family",
    "label_binary",
    "compute_distance_to_attack",
    "class_weights",
    "label_summary",
]
