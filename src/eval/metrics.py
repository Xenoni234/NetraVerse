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

    tn, fp, fn, tp = (
        confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
        if not single_class
        else (n_neg, 0, 0, n_pos)
    )

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
    "lead_time_distribution",
]
