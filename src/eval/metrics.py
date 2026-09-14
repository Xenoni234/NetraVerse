"""Metrics: F1, PR-AUC, lead-time distribution, FPR, stage macro-F1, state MSE.

Every metric is computed **per horizon** ``k in {1, 2, 4}``, never averaged into
a single headline figure — the whole question is how far ahead the forecast
still holds.

Metric notes
------------
**PR-AUC over ROC-AUC.** Attack windows are a few percent of the data. ROC-AUC
looks flattering under that imbalance; precision-recall does not.

**Lead time is the headline.** F1 says the model is right; lead time says it was
early enough to matter. Defined per campaign-entity as the wall-clock gap between
the first sustained alert and the first truly malicious window:

    lead_time = t_first_true_attack - t_first_sustained_alert

Positive means early (good), zero means simultaneous, negative means late.
Campaigns never alerted on are **misses** and are excluded from the lead-time
distribution but must be reported alongside it as a recall figure — otherwise a
model that only alerts on the three easiest campaigns shows a wonderful median
lead time.

**Two FPR views.** *Windowed* FPR is the per-window false positive rate;
*alert-level* FPR — benign hours per false alarm, after the sustain rule — is
what an operator actually feels. Report both.

**Sustain rule.** An alert requires ``sustain`` consecutive windows above the
threshold. Single-window flicker is not an alert; it is noise.

TODO
----
* [ ] Implement ``classification_metrics`` (per horizon, with thresholding).
* [ ] Implement ``lead_time_distribution`` plus the miss-rate it must be shown with.
* [ ] Implement ``false_positive_metrics`` for both views.
* [ ] Implement ``stage_metrics`` (macro-F1 and a confusion matrix).
* [ ] Implement ``state_metrics`` (MSE/MAE vs. the persistence baseline — report
      a skill score, since raw MSE on scaled features means little on its own).
* [ ] Implement ``select_threshold`` on VAL only.
* [ ] Implement ``bootstrap_ci`` — with only a handful of campaigns, a point
      estimate without an interval oversells the result.
* [ ] Implement ``results_table`` producing the single markdown table for the
      report and the pitch deck.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Mapping, Sequence

import numpy as np
import pandas as pd

#: Consecutive windows above threshold required to raise an alert.
DEFAULT_SUSTAIN: Final[int] = 2

#: Percentiles reported for the lead-time distribution.
LEAD_TIME_PERCENTILES: Final[tuple[int, ...]] = (25, 50, 75)

#: Encodes "this campaign was never alerted on" in a lead-time array.
MISSED: Final[float] = float("nan")


@dataclass(frozen=True)
class HorizonMetrics:
    """All metrics at a single horizon.

    Attributes:
        horizon: ``k``.
        seconds_ahead: ``k * stride_seconds``.
        f1: F1 of the risk head at the selected threshold.
        precision: Precision at that threshold.
        recall: Recall at that threshold.
        pr_auc: Area under the precision-recall curve (threshold-free).
        roc_auc: Reported for comparability with prior work; not the headline.
        fpr: Windowed false positive rate.
        support_positive: Number of positive windows — context for the rest.
        threshold: The threshold used, which must come from val, not test.
    """

    horizon: int
    seconds_ahead: int
    f1: float
    precision: float
    recall: float
    pr_auc: float
    roc_auc: float
    fpr: float
    support_positive: int
    threshold: float

    def meets_target(self, targets: Mapping[str, float]) -> dict[str, bool]:
        """Compare against the DESIGN.md section 6 targets for this horizon."""
        raise NotImplementedError("TODO: per-metric comparison against the target dict")


@dataclass(frozen=True)
class LeadTimeStats:
    """Lead-time distribution, reported with its miss rate.

    Attributes:
        values: Per-campaign-entity lead times in seconds, misses excluded.
        median: Median lead time.
        p25: 25th percentile.
        p75: 75th percentile.
        mean: Mean — reported, but the median is the honest summary.
        frac_positive_lead: Fraction of detected campaigns caught early at all.
        n_campaigns: Campaigns considered.
        n_missed: Campaigns never alerted on. Never omit this number.
    """

    values: np.ndarray
    median: float
    p25: float
    p75: float
    mean: float
    frac_positive_lead: float
    n_campaigns: int
    n_missed: int


def classification_metrics(
    y_true: np.ndarray,
    y_score: np.ndarray,
    *,
    threshold: float = 0.5,
    horizon: int = 1,
    stride_seconds: int = 10,
) -> HorizonMetrics:
    """Risk-head metrics at one horizon.

    Args:
        y_true: ``(N,)`` binary future attack labels.
        y_score: ``(N,)`` predicted probabilities.
        threshold: Decision threshold, selected on val.
        horizon: ``k``, for labelling the result.
        stride_seconds: To report seconds-ahead.
    """
    raise NotImplementedError("TODO: sklearn precision/recall/f1, PR-AUC, ROC-AUC, FPR")


def select_threshold(
    y_true: np.ndarray, y_score: np.ndarray, *, objective: str = "f1", max_fpr: float | None = 0.02
) -> float:
    """Choose the decision threshold on the VAL split.

    Args:
        y_true: Validation labels.
        y_score: Validation scores.
        objective: ``"f1"`` or ``"recall_at_fpr"``.
        max_fpr: Cap for the ``recall_at_fpr`` objective — the operationally
            realistic choice, since an analyst's tolerance for false alarms is
            fixed and their appetite for recall is not.

    Returns:
        The selected threshold, to be stored in the checkpoint and reused
        unchanged at test time.
    """
    raise NotImplementedError("TODO: sweep thresholds on the PR curve under the FPR cap")


def lead_time_distribution(
    predictions: pd.DataFrame,
    *,
    threshold: float = 0.5,
    sustain: int = DEFAULT_SUSTAIN,
    stride_seconds: int = 10,
    entity_col: str = "entity_id",
    campaign_col: str = "campaign_id",
) -> LeadTimeStats:
    """Lead time per campaign-entity, with the miss rate attached.

    Args:
        predictions: Per-window predictions with ``window_start``, ``risk``,
            ``is_attack`` and the identity columns.
        threshold: Alert threshold.
        sustain: Consecutive windows required to raise an alert.
        stride_seconds: Window stride, to convert windows into seconds.

    Returns:
        :class:`LeadTimeStats`. Missed campaigns are excluded from ``values`` and
        counted in ``n_missed`` — always report the two together.
    """
    raise NotImplementedError("TODO: per group, first sustained alert vs first true attack")


def false_positive_metrics(
    predictions: pd.DataFrame,
    *,
    threshold: float = 0.5,
    sustain: int = DEFAULT_SUSTAIN,
    window_seconds: int = 30,
    stride_seconds: int = 10,
) -> Mapping[str, float]:
    """Windowed FPR and benign-hours-per-false-alarm.

    The second number is the one to quote to an operator: "you will see about one
    false alarm per shift" is a claim they can evaluate; "FPR 0.019" is not.
    """
    raise NotImplementedError("TODO: windowed FPR, then alert-level rate over benign hours")


def stage_metrics(
    y_true: np.ndarray, y_pred: np.ndarray, *, n_stages: int = 7
) -> Mapping[str, object]:
    """Macro-F1, per-stage F1 and a confusion matrix for the stage head.

    Macro rather than micro: BENIGN dominates, and micro-F1 would report its
    performance as though it were the model's.
    """
    raise NotImplementedError("TODO: macro/per-class F1 plus the confusion matrix")


def state_metrics(
    y_true: np.ndarray, y_pred: np.ndarray, *, baseline_pred: np.ndarray | None = None
) -> Mapping[str, float]:
    """State-head MSE/MAE, plus a skill score against persistence.

    Raw MSE on robust-scaled features is close to uninterpretable. The skill
    score ``1 - MSE_model / MSE_persistence`` answers the real question: did
    learning the dynamics beat assuming nothing changes?
    """
    raise NotImplementedError("TODO: MSE/MAE per feature and overall, plus the skill score")


def bootstrap_ci(
    metric_fn: object,
    y_true: np.ndarray,
    y_score: np.ndarray,
    *,
    n_boot: int = 1000,
    confidence: float = 0.95,
    group: np.ndarray | None = None,
    random_state: int = 1337,
) -> tuple[float, float]:
    """Bootstrap confidence interval for any metric.

    Resample by ``group`` (campaign) rather than by row where possible — rows
    within a campaign are heavily correlated, and row-wise bootstrapping would
    report an interval several times too narrow.
    """
    raise NotImplementedError("TODO: grouped bootstrap resampling, percentile interval")


def results_table(
    metrics_by_horizon: Sequence[HorizonMetrics],
    lead_time: LeadTimeStats,
    *,
    baselines: Mapping[str, Sequence[HorizonMetrics]] | None = None,
    targets: Mapping[str, Mapping[str, float]] | None = None,
) -> pd.DataFrame:
    """Assemble the single results table used in the report and the pitch.

    One row per horizon, baseline columns alongside, and a pass/fail marker
    against the DESIGN.md targets.
    """
    raise NotImplementedError("TODO: build the frame, with baseline columns and target flags")


__all__ = [
    "DEFAULT_SUSTAIN",
    "LEAD_TIME_PERCENTILES",
    "MISSED",
    "HorizonMetrics",
    "LeadTimeStats",
    "classification_metrics",
    "select_threshold",
    "lead_time_distribution",
    "false_positive_metrics",
    "stage_metrics",
    "state_metrics",
    "bootstrap_ci",
    "results_table",
]
