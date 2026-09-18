"""Metrics: precision, recall, F1, PR-AUC, and FPR at fixed operating points.

**PR-AUC over ROC-AUC.** Attack rows are a minority. ROC-AUC looks flattering
under imbalance because the true-negative pool is enormous; precision-recall
does not. ROC-AUC is still reported for comparability with published work, but
it is never the headline.

**Fixed operating points.** A single F1 at threshold 0.5 hides the trade-off an
operator actually faces. :func:`recall_at_fpr` answers the real question — "if I
will tolerate one false alarm in 1000 benign flows, how much of the attack
traffic do I catch?" — which is what determines whether anyone deploys this.

.. note::
   **Lead time is absent from this module** and that is deliberate, not an
   oversight. CLAUDE.md rule 3 makes warning lead time the headline metric, but
   it is only definable for a *forecast* over windows. The flow-level LR
   baseline classifies each flow at the moment it is already complete, so its
   lead time is structurally zero. :func:`lead_time_distribution` lands with
   windowing.
"""

from __future__ import annotations

from typing import Final, Mapping, Sequence

import numpy as np

#: False-positive rates at which recall is reported.
DEFAULT_OPERATING_POINTS: Final[tuple[float, ...]] = (0.001, 0.01, 0.05)

#: Default decision threshold when none is supplied.
DEFAULT_THRESHOLD: Final[float] = 0.5


def compute_all_metrics(
    y_true: np.ndarray | Sequence[int],
    y_pred: np.ndarray | Sequence[int],
    y_prob: np.ndarray | Sequence[float],
    *,
    operating_points: Sequence[float] = DEFAULT_OPERATING_POINTS,
    threshold: float = DEFAULT_THRESHOLD,
) -> dict[str, object]:
    """Compute the full metric set for a binary detector.

    Args:
        y_true: Ground-truth 0/1 labels.
        y_pred: Predicted 0/1 labels at ``threshold``.
        y_prob: Predicted probability of the positive class.
        operating_points: FPRs at which to report recall.
        threshold: The threshold ``y_pred`` was produced at, recorded in the output.

    Returns:
        Dict with precision, recall, f1, pr_auc, roc_auc, fpr, confusion-matrix
        counts, support, and recall at each operating point.
    """
    from sklearn.metrics import (
        average_precision_score,
        confusion_matrix,
        precision_recall_fscore_support,
        roc_auc_score,
    )

    y_true = np.asarray(y_true).astype(int).ravel()
    y_pred = np.asarray(y_pred).astype(int).ravel()
    y_prob = np.asarray(y_prob, dtype="float64").ravel()

    if not (len(y_true) == len(y_pred) == len(y_prob)):
        raise ValueError(
            f"Length mismatch: y_true={len(y_true)}, y_pred={len(y_pred)}, y_prob={len(y_prob)}"
        )

    n_pos = int(y_true.sum())
    n_neg = int(len(y_true) - n_pos)
    single_class = n_pos == 0 or n_neg == 0

    precision, recall, f1, _ = precision_recall_fscore_support(
        y_true, y_pred, average="binary", zero_division=0
    )

    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()

    results: dict[str, object] = {
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
        "pr_auc": float(average_precision_score(y_true, y_prob)) if not single_class else float("nan"),
        "roc_auc": float(roc_auc_score(y_true, y_prob)) if not single_class else float("nan"),
        "fpr": float(fp / (fp + tn)) if (fp + tn) else 0.0,
        "threshold": float(threshold),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "support": {"n_total": int(len(y_true)), "n_positive": n_pos, "n_negative": n_neg,
                    "positive_rate": float(n_pos / len(y_true)) if len(y_true) else 0.0},
    }

    if single_class:
        results["warning"] = (
            "Only one class present in y_true; PR-AUC and ROC-AUC are undefined."
        )
        results["operating_points"] = {}
        return results

    results["operating_points"] = {
        f"recall_at_fpr_{fpr:g}": recall_at_fpr(y_true, y_prob, fpr)
        for fpr in operating_points
    }
    return results


def recall_at_fpr(
    y_true: np.ndarray, y_prob: np.ndarray, target_fpr: float
) -> dict[str, float]:
    """Recall achievable while holding the false-positive rate at or below a cap.

    Args:
        y_true: Ground-truth 0/1 labels.
        y_prob: Predicted positive-class probabilities.
        target_fpr: The FPR ceiling.

    Returns:
        ``{"recall": ..., "threshold": ..., "achieved_fpr": ...}``. Recall is 0.0
        when no threshold meets the cap.
    """
    from sklearn.metrics import roc_curve

    fpr, tpr, thresholds = roc_curve(y_true, y_prob)
    feasible = fpr <= target_fpr
    if not feasible.any():
        return {"recall": 0.0, "threshold": float("nan"), "achieved_fpr": float("nan")}
    idx = int(np.argmax(np.where(feasible, tpr, -np.inf)))
    return {
        "recall": float(tpr[idx]),
        "threshold": float(thresholds[idx]),
        "achieved_fpr": float(fpr[idx]),
    }


def select_threshold(
    y_true: np.ndarray, y_prob: np.ndarray, *, objective: str = "f1",
    max_fpr: float | None = None,
) -> float:
    """Choose a decision threshold on the VALIDATION split.

    Args:
        y_true: Validation labels.
        y_prob: Validation probabilities.
        objective: ``"f1"`` (maximise F1) or ``"recall_at_fpr"`` (maximise recall
            subject to ``max_fpr``).
        max_fpr: Required for the ``recall_at_fpr`` objective.

    Returns:
        The selected threshold, to be reused unchanged at test time.
    """
    from sklearn.metrics import precision_recall_curve

    if objective == "recall_at_fpr":
        if max_fpr is None:
            raise ValueError("max_fpr is required for objective='recall_at_fpr'")
        return float(recall_at_fpr(y_true, y_prob, max_fpr)["threshold"])

    if objective != "f1":
        raise ValueError(f"Unknown objective {objective!r}")

    precision, recall, thresholds = precision_recall_curve(y_true, y_prob)
    with np.errstate(divide="ignore", invalid="ignore"):
        f1 = np.nan_to_num(2 * precision * recall / (precision + recall))
    # precision_recall_curve returns one more point than thresholds
    best = int(np.argmax(f1[:-1])) if len(thresholds) else 0
    return float(thresholds[best]) if len(thresholds) else DEFAULT_THRESHOLD


def format_metrics_table(results: Mapping[str, Mapping[str, object]]) -> str:
    """Render a results table for the console.

    Args:
        results: Mapping of model/split name to a :func:`compute_all_metrics` dict.
    """
    header = (
        f"{'model':<26} {'P':>7} {'R':>7} {'F1':>7} {'PR-AUC':>8} "
        f"{'ROC-AUC':>8} {'FPR':>8} {'n_pos':>9}"
    )
    lines = [header, "-" * len(header)]
    for name, m in results.items():
        support = m.get("support", {}) or {}
        lines.append(
            f"{name:<26} "
            f"{float(m.get('precision', float('nan'))):>7.4f} "
            f"{float(m.get('recall', float('nan'))):>7.4f} "
            f"{float(m.get('f1', float('nan'))):>7.4f} "
            f"{float(m.get('pr_auc', float('nan'))):>8.4f} "
            f"{float(m.get('roc_auc', float('nan'))):>8.4f} "
            f"{float(m.get('fpr', float('nan'))):>8.4f} "
            f"{int(support.get('n_positive', 0)):>9,}"
        )
    return "\n".join(lines)


def format_operating_points(results: Mapping[str, object]) -> str:
    """Render the recall-at-fixed-FPR table."""
    points = results.get("operating_points") or {}
    if not points:
        return "  (no operating points — single-class split)"
    lines = [f"  {'operating point':<26} {'recall':>8} {'threshold':>11} {'achieved FPR':>13}"]
    for name, value in points.items():
        lines.append(
            f"  {name:<26} {value['recall']:>8.4f} "
            f"{value['threshold']:>11.6f} {value['achieved_fpr']:>13.6f}"
        )
    return "\n".join(lines)


def brier_score(y_true: np.ndarray | Sequence[int], y_prob: np.ndarray | Sequence[float]) -> float:
    """Mean squared probability error; lower is better."""
    y = np.asarray(y_true, dtype="float64").ravel()
    p = np.asarray(y_prob, dtype="float64").ravel()
    if len(y) != len(p):
        raise ValueError("y_true and y_prob must have equal length")
    return float(np.mean((p - y) ** 2)) if len(y) else float("nan")


def expected_calibration_error(
    y_true: np.ndarray | Sequence[int], y_prob: np.ndarray | Sequence[float], *, bins: int = 10
) -> float:
    """Equal-width expected calibration error, reported as a probability gap."""
    y = np.asarray(y_true, dtype="float64").ravel()
    p = np.clip(np.asarray(y_prob, dtype="float64").ravel(), 0.0, 1.0)
    if len(y) != len(p) or bins < 1:
        raise ValueError("invalid calibration inputs")
    if not len(y):
        return float("nan")
    edges = np.linspace(0.0, 1.0, bins + 1)
    bucket = np.minimum(np.digitize(p, edges[1:-1], right=False), bins - 1)
    return float(sum(
        (mask.mean()) * abs(y[mask].mean() - p[mask].mean())
        for i in range(bins) if (mask := bucket == i).any()
    ))


def bootstrap_pr_auc(
    y_true: np.ndarray | Sequence[int], y_prob: np.ndarray | Sequence[float], *,
    n_resamples: int = 2000, seed: int = 1337, confidence: float = 0.95,
) -> dict[str, float | int]:
    """Bootstrap PR-AUC confidence interval, preserving paired labels/scores."""
    from sklearn.metrics import average_precision_score

    y = np.asarray(y_true).astype(int).ravel()
    p = np.asarray(y_prob, dtype="float64").ravel()
    if len(y) != len(p):
        raise ValueError("y_true and y_prob must have equal length")
    rng = np.random.default_rng(seed)
    values: list[float] = []
    for _ in range(n_resamples):
        idx = rng.integers(0, len(y), len(y))
        if y[idx].min() == y[idx].max():
            continue
        values.append(float(average_precision_score(y[idx], p[idx])))
    if not values:
        return {"estimate": float("nan"), "lower": float("nan"), "upper": float("nan"), "n_valid": 0}
    alpha = (1.0 - confidence) / 2.0
    return {"estimate": float(average_precision_score(y, p)),
            "lower": float(np.quantile(values, alpha)),
            "upper": float(np.quantile(values, 1.0 - alpha)),
            "n_valid": len(values)}


def false_alerts_per_hour(
    meta: "pd.DataFrame", y_true: np.ndarray | Sequence[int], y_prob: np.ndarray | Sequence[float],
    *, threshold: float = 0.5, time_col: str = "window_start", campaign_col: str = "campaign_id",
) -> float:
    """False-positive alert rows per observed campaign-hour.

    This is deliberately a rate over observed timeline exposure, not over flow
    count. It is an operational measure and should be reported beside FPR.
    """
    import pandas as pd
    y = np.asarray(y_true).astype(int).ravel()
    p = np.asarray(y_prob, dtype="float64").ravel()
    if len(meta) != len(y) or len(y) != len(p):
        raise ValueError("meta, y_true and y_prob must have equal length")
    false_alerts = int(((p >= threshold) & (y == 0)).sum())
    times = pd.to_datetime(meta[time_col], utc=True)
    exposure_seconds = 0.0
    groups = meta[campaign_col] if campaign_col in meta else pd.Series("all", index=meta.index)
    for _, idx in groups.groupby(groups, sort=False).groups.items():
        t = times.loc[idx]
        if len(t) > 1:
            exposure_seconds += float((t.max() - t.min()).total_seconds() + 30.0)
        elif len(t) == 1:
            exposure_seconds += 30.0
    return float(false_alerts / (exposure_seconds / 3600.0)) if exposure_seconds else float("nan")


def per_campaign_metrics(
    meta: "pd.DataFrame", y_true: np.ndarray, y_prob: np.ndarray, *, threshold: float = 0.5,
    campaign_col: str = "campaign_id",
) -> dict[str, dict[str, object]]:
    """Compute the standard metric bundle separately for every campaign."""
    output: dict[str, dict[str, object]] = {}
    for campaign, idx in meta.groupby(campaign_col, sort=True).groups.items():
        indices = np.asarray(list(idx), dtype=int)
        output[str(campaign)] = compute_all_metrics(
            y_true[indices], (y_prob[indices] >= threshold).astype(int), y_prob[indices],
            threshold=threshold,
        )
    return output


def lead_time_distribution(*args: object, **kwargs: object) -> None:
    """Warning lead time per campaign — the project's headline metric.

    Not implementable for a flow-level classifier: a completed flow carries no
    forecast horizon, so lead time is structurally zero. Lands with windowing
    and the forecasting models.
    """
    raise NotImplementedError(
        "lead_time_distribution requires windowed forecasts; see CLAUDE.md rule 3"
    )


__all__ = [
    "DEFAULT_OPERATING_POINTS",
    "DEFAULT_THRESHOLD",
    "compute_all_metrics",
    "recall_at_fpr",
    "select_threshold",
    "format_metrics_table",
    "format_operating_points",
    "brier_score",
    "expected_calibration_error",
    "bootstrap_pr_auc",
    "false_alerts_per_hour",
    "per_campaign_metrics",
    "lead_time_distribution",
]
