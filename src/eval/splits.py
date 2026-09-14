"""The LOCKED split policy — chronological, campaign-atomic, one held-out family.

Implements DESIGN.md section 5. This module exists as its own file because the
split policy is where intrusion-detection papers most often go quietly wrong,
and a single ``train_test_split(shuffle=True)`` anywhere else in the codebase
would invalidate every number we report.

The four rules
--------------
1. **Chronological.** Within a campaign, split by wall-clock time. A random
   split lets the model see the future of the very attack it is being tested on,
   producing spectacular and meaningless scores.
2. **Campaigns stay together.** A capture day / CTU scenario lands entirely in
   one split. Otherwise the model memorises that campaign's host set rather than
   learning attack dynamics.
3. **One attack family held out.** Default ``Infiltration``: absent from train
   and val, present in test. This is the only honest measure of whether the
   model generalises to an attack it has never seen — which is the case that
   matters in deployment.
4. **Gap buffer.** Drop ``L + max(K) = 14`` windows at every boundary, so no
   test sample's history overlaps a training sample. Overlapping windows are the
   subtlest leak in this pipeline, because nothing about it looks wrong.

Anything fit on data — the scaler, class weights, the decision threshold, the
trajectory library — is fit on **train only** and frozen.

TODO
----
* [ ] Implement ``chronological_split`` honouring all four rules.
* [ ] Implement ``assert_no_leakage`` — the test the whole module exists for.
* [ ] Implement ``holdout_family_mask``.
* [ ] Implement ``split_summary`` (rows, attack rate, date range, campaigns per
      split) — print it at the start of every run so a bad split is visible.
* [ ] Handle the degenerate case where a campaign is shorter than the gap buffer.
* [ ] Decide: should the held-out family also be removed from the *pre-attack*
      labels in train? Leaving it in leaks a hint about its timing. Probably yes
      — record the decision in DESIGN.md.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Mapping, Sequence

import pandas as pd

#: Split names used throughout the project.
SPLIT_NAMES: Final[tuple[str, ...]] = ("train", "val", "test")

#: LOCKED default fractions.
TRAIN_FRAC: Final[float] = 0.70
VAL_FRAC: Final[float] = 0.15
TEST_FRAC: Final[float] = 0.15

#: LOCKED default held-out attack family.
DEFAULT_HELD_OUT_FAMILY: Final[str] = "Infiltration"

#: LOCKED gap buffer: L + max(K).
DEFAULT_GAP_WINDOWS: Final[int] = 14


@dataclass(frozen=True)
class SplitConfig:
    """Split policy parameters. Defaults are the LOCKED values."""

    train_frac: float = TRAIN_FRAC
    val_frac: float = VAL_FRAC
    test_frac: float = TEST_FRAC
    keep_campaigns_together: bool = True
    held_out_family: str | None = DEFAULT_HELD_OUT_FAMILY
    gap_windows: int = DEFAULT_GAP_WINDOWS
    time_col: str = "window_start"
    campaign_col: str = "campaign_id"
    family_col: str = "attack_family"
    random_state: int = 1337  # only for assigning whole campaigns, never rows


def chronological_split(
    windows: pd.DataFrame, config: SplitConfig | None = None
) -> dict[str, pd.DataFrame]:
    """Split labelled windows into train / val / test per the LOCKED policy.

    Args:
        windows: Labelled windows carrying ``window_start``, ``campaign_id`` and
            ``attack_family``.
        config: Split parameters.

    Returns:
        Mapping of split name to frame. The held-out family appears only in
        ``test``.

    Raises:
        ValueError: if the fractions do not sum to 1, or a campaign is too short
            to survive the gap buffer.
    """
    raise NotImplementedError("TODO: per-campaign time split, gap buffer, family holdout")


def assign_campaigns(
    windows: pd.DataFrame, config: SplitConfig | None = None
) -> Mapping[str, str]:
    """Assign whole campaigns to splits when ``keep_campaigns_together`` is set.

    Balances attack rate across splits rather than assigning at random — with
    only a handful of campaigns, a random assignment can easily hand all of one
    attack type to test.
    """
    raise NotImplementedError("TODO: greedy balanced assignment by attack rate")


def holdout_family_mask(
    windows: pd.DataFrame, family: str = DEFAULT_HELD_OUT_FAMILY, *, family_col: str = "attack_family"
) -> pd.Series:
    """Boolean mask of rows belonging to the held-out family.

    Must also cover the *pre-attack* windows leading into that family — see the
    open decision in the module TODO.
    """
    raise NotImplementedError("TODO: family match, plus the pre-attack lead-in windows")


def apply_gap_buffer(
    frame: pd.DataFrame, *, gap_windows: int = DEFAULT_GAP_WINDOWS, time_col: str = "window_start"
) -> pd.DataFrame:
    """Drop the first ``gap_windows`` rows of a split so histories cannot overlap."""
    raise NotImplementedError("TODO: drop the leading gap per (campaign, entity) group")


def assert_no_leakage(splits: Mapping[str, pd.DataFrame], config: SplitConfig | None = None) -> None:
    """Assert the split is honest. The reason this module exists.

    Checks:
      * no ``(entity_id, window_start)`` appears in two splits
      * every train window precedes every test window within a campaign
      * no campaign spans two splits when ``keep_campaigns_together``
      * the held-out family is absent from train and val
      * the gap buffer is large enough that no histories overlap

    Raises:
        AssertionError: with a message naming the specific rule violated.
    """
    raise NotImplementedError("TODO: the five leakage checks, each with a clear message")


def split_summary(splits: Mapping[str, pd.DataFrame]) -> pd.DataFrame:
    """Per-split row counts, attack rate, date range and campaign list.

    Print this at the start of every run: a broken split is obvious in this
    table and invisible everywhere else.
    """
    raise NotImplementedError("TODO: aggregate per split into a small frame")


def stratified_campaign_report(
    windows: pd.DataFrame, *, family_col: str = "attack_family"
) -> pd.DataFrame:
    """Attack-family counts per campaign, to sanity-check the holdout choice.

    Run this before locking ``held_out_family`` — holding out a family that
    appears in only one campaign tests the campaign, not the family.
    """
    raise NotImplementedError("TODO: crosstab of campaign x family")


__all__ = [
    "SPLIT_NAMES",
    "TRAIN_FRAC",
    "VAL_FRAC",
    "TEST_FRAC",
    "DEFAULT_HELD_OUT_FAMILY",
    "DEFAULT_GAP_WINDOWS",
    "SplitConfig",
    "chronological_split",
    "assign_campaigns",
    "holdout_family_mask",
    "apply_gap_buffer",
    "assert_no_leakage",
    "split_summary",
    "stratified_campaign_report",
]
