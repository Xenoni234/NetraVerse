"""The split policy — chronological, campaign-aware, never shuffled.

Implements CLAUDE.md section 7. This is its own module because the split is
where intrusion-detection results most often go quietly wrong: a single
``train_test_split(shuffle=True)`` anywhere would invalidate every number we
report, and would do so by making the numbers *better*, so nobody goes looking.

The rules
---------
1. **Chronological.** Sort by time, cut by time. Never randomly.
2. **Campaigns kept together.** A campaign (capture day) is not shuffled into
   another campaign's timeline; each is split along its own clock.
3. **Attack episodes are not cut in half.** If a boundary lands inside a
   contiguous attack episode, it is pushed to the episode edge.
4. **60 / 20 / 20.**

.. note::
   **Reading of "campaigns kept together"** (worth confirming): taken literally —
   one whole campaign per split — three capture days would put *one day in each
   split*, and since each CIC-IDS2018 day contains a different attack family,
   the test split would contain only one attack type and no baseline would be
   meaningful.

   Implemented instead as: each campaign is split **along its own timeline**
   (earliest 60% train, next 20% val, latest 20% test), with rule 3 preventing an
   episode being severed. Every split then sees every attack family, and no
   training row is chronologically after a test row *within a campaign*. Set
   ``whole_campaign=True`` for the literal reading.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Mapping, Sequence

import numpy as np
import pandas as pd

SPLIT_NAMES: Final[tuple[str, ...]] = ("train", "val", "test")

TRAIN_FRAC: Final[float] = 0.60
VAL_FRAC: Final[float] = 0.20
TEST_FRAC: Final[float] = 0.20

DEFAULT_HELD_OUT_FAMILY: Final[str] = "Infiltration"


@dataclass(frozen=True)
class SplitConfig:
    """Split policy parameters. Defaults are the CLAUDE.md section 7 values."""

    train: float = TRAIN_FRAC
    val: float = VAL_FRAC
    test: float = TEST_FRAC
    time_col: str = "timestamp"
    campaign_col: str = "campaign_id"
    label_col: str = "binary_label"
    family_col: str = "attack_family"
    whole_campaign: bool = False
    respect_episodes: bool = True
    held_out_family: str | None = None


def chronological_split(
    df: pd.DataFrame,
    train: float = TRAIN_FRAC,
    val: float = VAL_FRAC,
    test: float = TEST_FRAC,
    *,
    config: SplitConfig | None = None,
    verbose: bool = True,
) -> dict[str, pd.DataFrame]:
    """Split a labelled frame chronologically into train / val / test.

    Args:
        df: Labelled flow or window records.
        train: Training fraction.
        val: Validation fraction.
        test: Test fraction.
        config: Full policy options; ``train``/``val``/``test`` override its
            fractions when given positionally.
        verbose: Print the split summary table.

    Returns:
        Mapping of split name to frame.

    Raises:
        ValueError: if the fractions do not sum to 1, or the time column is
            missing or unsorted-unsortable.
    """
    cfg = config or SplitConfig()
    cfg = SplitConfig(
        train=train,
        val=val,
        test=test,
        time_col=cfg.time_col,
        campaign_col=cfg.campaign_col,
        label_col=cfg.label_col,
        family_col=cfg.family_col,
        whole_campaign=cfg.whole_campaign,
        respect_episodes=cfg.respect_episodes,
        held_out_family=cfg.held_out_family,
    )

    total = cfg.train + cfg.val + cfg.test
    if not np.isclose(total, 1.0):
        raise ValueError(f"Split fractions must sum to 1.0, got {total}")
    if cfg.time_col not in df.columns:
        raise KeyError(f"{cfg.time_col!r} not in frame; cannot split chronologically")

    work = df.sort_values(
        ([cfg.campaign_col] if cfg.campaign_col in df.columns else []) + [cfg.time_col],
        kind="mergesort",
    ).reset_index(drop=True)

    if cfg.whole_campaign:
        splits = _split_whole_campaigns(work, cfg)
    else:
        splits = _split_within_campaigns(work, cfg)

    if cfg.held_out_family:
        splits = _apply_family_holdout(splits, cfg)

    if verbose:
        print(split_summary(splits, cfg).to_string(index=False))
        n_campaigns = (
            work[cfg.campaign_col].nunique() if cfg.campaign_col in work.columns else 1
        )
        if n_campaigns > 1 and not cfg.whole_campaign:
            print(
                f"  NOTE: {n_campaigns} campaigns, each split along its own timeline, so the\n"
                f"        start/end columns above overlap between splits. That is expected —\n"
                f"        ordering is enforced per campaign. Use per_campaign_summary() to see it."
            )

    return splits


def _split_within_campaigns(df: pd.DataFrame, cfg: SplitConfig) -> dict[str, pd.DataFrame]:
    """Split each campaign along its own timeline (the default reading)."""
    parts: dict[str, list[pd.DataFrame]] = {name: [] for name in SPLIT_NAMES}
    group_key = (
        df[cfg.campaign_col] if cfg.campaign_col in df.columns
        else pd.Series("all", index=df.index)
    )

    for _, group in df.groupby(group_key, sort=True):
        group = group.sort_values(cfg.time_col, kind="mergesort")
        n = len(group)
        cut_train = int(round(n * cfg.train))
        cut_val = int(round(n * (cfg.train + cfg.val)))

        if cfg.respect_episodes and cfg.label_col in group.columns:
            labels = group[cfg.label_col].to_numpy()
            cut_train = _snap_to_episode_edge(labels, cut_train)
            cut_val = _snap_to_episode_edge(labels, cut_val)
            cut_val = max(cut_val, cut_train)

        parts["train"].append(group.iloc[:cut_train])
        parts["val"].append(group.iloc[cut_train:cut_val])
        parts["test"].append(group.iloc[cut_val:])

    return {
        name: (
            pd.concat(frames, ignore_index=True) if frames else df.iloc[0:0].copy()
        )
        for name, frames in parts.items()
    }


def _split_whole_campaigns(df: pd.DataFrame, cfg: SplitConfig) -> dict[str, pd.DataFrame]:
    """Literal reading: each campaign lands entirely in one split, oldest first."""
    if cfg.campaign_col not in df.columns:
        raise KeyError(f"whole_campaign=True needs {cfg.campaign_col!r}")

    order = (
        df.groupby(cfg.campaign_col)[cfg.time_col].min().sort_values().index.tolist()
    )
    n = len(order)
    n_train = max(1, int(round(n * cfg.train)))
    n_val = max(0, int(round(n * cfg.val)))
    assignment = {
        **{c: "train" for c in order[:n_train]},
        **{c: "val" for c in order[n_train : n_train + n_val]},
        **{c: "test" for c in order[n_train + n_val :]},
    }
    return {
        name: df[df[cfg.campaign_col].map(assignment) == name].copy() for name in SPLIT_NAMES
    }


def _snap_to_episode_edge(labels: np.ndarray, cut: int) -> int:
    """Move ``cut`` to the nearest edge of a contiguous attack episode.

    Prevents one attack burst being severed across a split boundary, which would
    let the model see the first half of an episode in training and be graded on
    the second half.
    """
    n = len(labels)
    if cut <= 0 or cut >= n or labels[cut] == 0 or labels[cut - 1] == 0:
        return cut

    forward = cut
    while forward < n and labels[forward] != 0:
        forward += 1
    backward = cut
    while backward > 0 and labels[backward - 1] != 0:
        backward -= 1

    return forward if (forward - cut) <= (cut - backward) else backward


def _apply_family_holdout(
    splits: Mapping[str, pd.DataFrame], cfg: SplitConfig
) -> dict[str, pd.DataFrame]:
    """Remove the held-out family from train/val and move it into test."""
    family = cfg.held_out_family
    out = {name: frame.copy() for name, frame in splits.items()}
    moved = []
    for name in ("train", "val"):
        frame = out[name]
        if cfg.family_col not in frame.columns:
            continue
        mask = frame[cfg.family_col] == family
        if mask.any():
            moved.append(frame[mask])
            out[name] = frame[~mask].copy()
    if moved:
        out["test"] = pd.concat([out["test"], *moved], ignore_index=True)
    return out


def split_summary(
    splits: Mapping[str, pd.DataFrame], config: SplitConfig | None = None
) -> pd.DataFrame:
    """Per-split rows, attack rate, date range and campaign count.

    Print this at the start of every run: a broken split is obvious here and
    invisible everywhere else.
    """
    cfg = config or SplitConfig()
    rows = []
    for name in SPLIT_NAMES:
        frame = splits[name]
        rows.append(
            {
                "split": name,
                "rows": len(frame),
                "pct": f"{len(frame) / max(1, sum(len(s) for s in splits.values())):.1%}",
                "attacks": int(frame[cfg.label_col].sum()) if cfg.label_col in frame else 0,
                "attack_rate": (
                    f"{frame[cfg.label_col].mean():.2%}"
                    if cfg.label_col in frame and len(frame)
                    else "-"
                ),
                "start": str(frame[cfg.time_col].min()) if len(frame) else "-",
                "end": str(frame[cfg.time_col].max()) if len(frame) else "-",
                "campaigns": (
                    frame[cfg.campaign_col].nunique() if cfg.campaign_col in frame else 0
                ),
            }
        )
    return pd.DataFrame(rows)


def per_campaign_summary(
    splits: Mapping[str, pd.DataFrame], config: SplitConfig | None = None
) -> pd.DataFrame:
    """Per-campaign, per-split time ranges — where the ordering is actually visible.

    :func:`split_summary` aggregates across campaigns, so when several campaigns
    are each split along their own timeline the global ranges legitimately
    overlap. This view shows that train really does precede val precedes test
    *within* each campaign, which is the invariant
    :func:`assert_no_leakage` enforces.
    """
    cfg = config or SplitConfig()
    rows = []
    for name in SPLIT_NAMES:
        frame = splits[name]
        if cfg.campaign_col not in frame.columns or frame.empty:
            continue
        for campaign, group in frame.groupby(cfg.campaign_col, sort=True):
            rows.append(
                {
                    "campaign": campaign,
                    "split": name,
                    "rows": len(group),
                    "attack_rate": f"{group[cfg.label_col].mean():.2%}"
                    if cfg.label_col in group
                    else "-",
                    "start": str(group[cfg.time_col].min()),
                    "end": str(group[cfg.time_col].max()),
                }
            )
    out = pd.DataFrame(rows)
    return out.sort_values(["campaign", "start"], kind="mergesort") if not out.empty else out


def assert_no_leakage(
    splits: Mapping[str, pd.DataFrame], config: SplitConfig | None = None
) -> None:
    """Assert the split is honest. The reason this module exists.

    Checks, per campaign, that every train row precedes every val row, and every
    val row precedes every test row.

    Raises:
        AssertionError: naming the specific rule and campaign that failed.
    """
    cfg = config or SplitConfig()
    has_campaign = all(cfg.campaign_col in s.columns for s in splits.values())

    def bounds(frame: pd.DataFrame, campaign: str | None):
        sub = frame if campaign is None else frame[frame[cfg.campaign_col] == campaign]
        if sub.empty:
            return None
        return sub[cfg.time_col].min(), sub[cfg.time_col].max()

    campaigns: Sequence[str | None]
    if has_campaign:
        campaigns = sorted(
            set().union(*(set(s[cfg.campaign_col].unique()) for s in splits.values()))
        )
    else:
        campaigns = [None]

    for campaign in campaigns:
        for earlier, later in (("train", "val"), ("val", "test")):
            a, b = bounds(splits[earlier], campaign), bounds(splits[later], campaign)
            if a is None or b is None:
                continue
            assert a[1] <= b[0], (
                f"Temporal leakage in campaign {campaign!r}: {earlier} ends {a[1]} "
                f"but {later} starts {b[0]} — {earlier} must precede {later}."
            )

    if cfg.held_out_family:
        for name in ("train", "val"):
            frame = splits[name]
            if cfg.family_col in frame.columns:
                assert not (frame[cfg.family_col] == cfg.held_out_family).any(), (
                    f"Held-out family {cfg.held_out_family!r} leaked into {name}."
                )


__all__ = [
    "SPLIT_NAMES",
    "TRAIN_FRAC",
    "VAL_FRAC",
    "TEST_FRAC",
    "DEFAULT_HELD_OUT_FAMILY",
    "SplitConfig",
    "chronological_split",
    "split_summary",
    "per_campaign_summary",
    "assert_no_leakage",
]
