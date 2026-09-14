"""The full evaluation loop — one command, one report.

Takes a checkpoint and an eval config; produces everything the project is judged
on: per-horizon metrics, the lead-time distribution, false-positive rates, the
stage confusion matrix, the baseline comparison, the ablation table, per-dataset
and held-out-family breakdowns, and the plots.

Pipeline
--------
1. Load the checkpoint — weights, model config, **scaler state** and the
   **threshold selected on val**. Never refit either at test time.
2. Build the eval split via :mod:`src.eval.splits`, and run
   :func:`~src.eval.splits.assert_no_leakage` before scoring anything.
3. Predict over the split (free-running, no teacher forcing), optionally with
   MC-dropout for uncertainty.
4. Compute metrics per horizon, per dataset, per attack family, and separately
   for the held-out family.
5. Run the baselines and ablations under identical conditions.
6. Write ``metrics.json``, ``predictions.parquet``, the plots, and
   ``report.md``.

Design decisions
----------------
**Predictions are saved.** Every downstream question — a per-campaign timeline,
a lead-time plot, the demo's replay data — is then a re-read rather than a
re-run, and nobody re-runs the model on test to answer a follow-up question.

**Baselines run in the same pass.** A separate baseline script inevitably drifts
out of sync with the model's preprocessing, and the resulting comparison is
worthless.

**Test is touched once.** ``eval.split: val`` is the default while iterating.
The harness logs loudly when it is run on test.

TODO
----
* [ ] Implement ``evaluate`` (the entry point for ``scripts/evaluate.py``).
* [ ] Implement ``predict_split`` (batched, no_grad, optional MC-dropout).
* [ ] Implement ``evaluate_baselines`` and ``evaluate_ablations``.
* [ ] Implement ``breakdown_by`` for dataset / family / held-out slices.
* [ ] Implement ``write_report`` (markdown + plots) and ``save_predictions``.
* [ ] Add a "touching test" warning and record it in the report metadata.
* [ ] Include provenance in ``metrics.json``: git SHA, config hash, checkpoint
      path, schema version, timestamp. A results file nobody can reproduce is a
      rumour.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Mapping, Sequence

import pandas as pd

if TYPE_CHECKING:
    from torch import nn

    from src.eval.metrics import HorizonMetrics, LeadTimeStats


@dataclass
class EvaluationReport:
    """Everything one evaluation run produced.

    Attributes:
        horizon_metrics: Per-horizon risk-head metrics.
        lead_time: Lead-time distribution and miss count.
        false_positives: Windowed and alert-level FPR.
        stage: Stage-head macro-F1 and confusion matrix.
        state: State-head errors and the persistence skill score.
        baselines: Metrics for each must-beat baseline.
        ablations: Metrics for each ablation.
        breakdowns: Slices by dataset, attack family and held-out family.
        predictions: Per-window predictions, saved for later analysis.
        provenance: Git SHA, config hash, checkpoint path, schema version, time.
    """

    horizon_metrics: "list[HorizonMetrics]" = field(default_factory=list)
    lead_time: "LeadTimeStats | None" = None
    false_positives: Mapping[str, float] = field(default_factory=dict)
    stage: Mapping[str, object] = field(default_factory=dict)
    state: Mapping[str, float] = field(default_factory=dict)
    baselines: Mapping[str, object] = field(default_factory=dict)
    ablations: Mapping[str, object] = field(default_factory=dict)
    breakdowns: Mapping[str, pd.DataFrame] = field(default_factory=dict)
    predictions: pd.DataFrame | None = None
    provenance: Mapping[str, str] = field(default_factory=dict)

    def to_json(self, path: Path) -> Path:
        """Write ``metrics.json`` — the machine-readable record of this run."""
        raise NotImplementedError("TODO: serialise dataclasses + provenance to JSON")

    def to_markdown(self) -> str:
        """Render the human-readable report, targets marked pass/fail."""
        raise NotImplementedError("TODO: results table, lead-time stats, ablation table")

    def summary_line(self) -> str:
        """One line for the console: headline F1 and median lead time."""
        raise NotImplementedError("TODO: 'F1@k1=0.78 | median lead 40s | FPR 0.014'")


def evaluate(
    config: Mapping[str, Any],
    *,
    checkpoint: Path,
    output_dir: Path | None = None,
    run_baselines: bool = True,
    run_ablations: bool = True,
) -> EvaluationReport:
    """Run the full evaluation and write the report.

    Args:
        config: Resolved ``configs/eval.yaml``.
        checkpoint: Checkpoint to evaluate; supplies the scaler and threshold.
        output_dir: Where to write the report; defaults to ``reports/<name>``.
        run_baselines: Include the must-beat baselines.
        run_ablations: Include the ablation table.

    Returns:
        A populated :class:`EvaluationReport`.
    """
    raise NotImplementedError("TODO: load, split, assert no leakage, predict, score, write")


def predict_split(
    model: "nn.Module",
    windows: pd.DataFrame,
    *,
    config: Mapping[str, Any],
    scaler_state: Mapping[str, Any],
    mc_dropout_samples: int = 0,
    batch_size: int = 512,
    device: str = "auto",
) -> pd.DataFrame:
    """Predict over an entire split, returning one row per window and horizon.

    Runs free-running (no teacher forcing) so the numbers reflect inference
    conditions. With ``mc_dropout_samples > 0`` the frame also carries the
    uncertainty band bounds.

    Returns:
        Frame with identity columns, ``horizon``, ``risk``, ``stage_pred``,
        ``is_attack``, ``attack_stage``, and optional band columns.
    """
    raise NotImplementedError("TODO: batched no_grad inference, optionally MC-dropout")


def evaluate_baselines(
    windows: pd.DataFrame, *, config: Mapping[str, Any], scaler_state: Mapping[str, Any]
) -> Mapping[str, object]:
    """Run the must-beat baselines under identical preprocessing.

    Same split, same scaler, same threshold-selection procedure — otherwise the
    comparison measures preprocessing, not modelling.
    """
    raise NotImplementedError("TODO: persistence + logistic regression, scored identically")


def evaluate_ablations(
    config: Mapping[str, Any], *, checkpoint: Path, ablations: Sequence[str]
) -> Mapping[str, object]:
    """Run each configured ablation and collect its metrics.

    Some ablations need retraining (encoder-only, flow-only,
    no-scheduled-sampling); others are inference-time only (shuffled-time).
    :mod:`src.eval.ablations` says which is which.
    """
    raise NotImplementedError("TODO: dispatch to src.eval.ablations, collect metrics")


def breakdown_by(
    predictions: pd.DataFrame, by: str, *, threshold: float, horizons: Sequence[int] = (1, 2, 4)
) -> pd.DataFrame:
    """Metrics sliced by ``dataset`` / ``attack_family`` / ``campaign_id``.

    The aggregate number hides everything interesting: a model can score well
    overall while completely missing one attack family.
    """
    raise NotImplementedError("TODO: groupby slice, classification_metrics per group")


def save_predictions(predictions: pd.DataFrame, path: Path) -> Path:
    """Write per-window predictions to parquet, for plots and the demo."""
    raise NotImplementedError("TODO: pyarrow write with the identity columns preserved")


def write_report(report: EvaluationReport, output_dir: Path, *, save_plots: bool = True) -> Path:
    """Write ``report.md``, ``metrics.json`` and the plots. Returns the directory."""
    raise NotImplementedError("TODO: render markdown, dump JSON, draw plots")


def plot_lead_time(report: EvaluationReport, path: Path) -> Path:
    """Lead-time histogram with the median marked — the slide that sells this."""
    raise NotImplementedError("TODO: matplotlib histogram with median and target lines")


def plot_risk_timeline(
    predictions: pd.DataFrame, campaign_id: str, entity_id: str, path: Path
) -> Path:
    """Predicted risk over time for one campaign-entity, true attack shaded.

    The single most persuasive figure in the project: the risk curve visibly
    rising before the shaded region starts.
    """
    raise NotImplementedError("TODO: risk line, threshold line, attack span shading")


__all__ = [
    "EvaluationReport",
    "evaluate",
    "predict_split",
    "evaluate_baselines",
    "evaluate_ablations",
    "breakdown_by",
    "save_predictions",
    "write_report",
    "plot_lead_time",
    "plot_risk_timeline",
]
