"""Checkpoint save/load — weights plus everything needed to reproduce a prediction.

A checkpoint here is **self-sufficient**. It stores not just the weights but the
model config, the fitted scaler state, the class weights, the selected decision
threshold and the schema version. That means ``scripts/evaluate.py``, the
Streamlit demo and a teammate's notebook all reproduce an identical prediction
from the file alone, with no dependence on which YAML happened to be lying
around.

Checkpoint payload
------------------
::

    {
      "schema_version":   str,    # must match unified_schema.SCHEMA_VERSION
      "model_config":     dict,   # rebuilds the architecture
      "state_dict":       dict,   # weights
      "optimizer_state":  dict,   # only in "last", for resuming
      "scaler_state":     dict,   # train-fit feature scaler
      "class_weights":    dict,   # risk pos_weight + stage class weights
      "threshold":        float,  # decision threshold chosen on val
      "metrics":          dict,   # val metrics at save time
      "epoch":            int,
      "git_sha":          str,    # provenance
      "created_at":       str,    # ISO-8601 UTC
    }

Loading refuses a checkpoint whose ``schema_version`` differs from the running
code's, rather than silently feeding 32 features into a 34-feature model.

TODO
----
* [ ] Implement ``save_checkpoint`` / ``load_checkpoint`` with the payload above.
* [ ] Implement ``CheckpointManager`` (best-k retention, ``last.ckpt`` symlink or
      copy — note Windows needs a copy, not a symlink, without admin rights).
* [ ] Implement ``resume`` (model + optimizer + epoch).
* [ ] Implement ``git_sha`` lookup, degrading gracefully outside a git repo.
* [ ] Always ``torch.load(..., map_location="cpu")`` so a GPU-trained checkpoint
      opens on a CPU-only laptop — the demo depends on this.
* [ ] Write an atomic save (temp file then replace) so an interrupted save
      cannot corrupt the previous best checkpoint.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Mapping

if TYPE_CHECKING:
    import torch
    from torch import nn

#: Filenames used inside a run directory.
BEST_CHECKPOINT_NAME: str = "best.ckpt"
LAST_CHECKPOINT_NAME: str = "last.ckpt"


@dataclass
class CheckpointManager:
    """Owns a run's checkpoint directory and best-k retention policy.

    Attributes:
        save_dir: Run directory (``models/<run_name>/``).
        monitor: Metric key to track, e.g. ``val/risk_f1_k1``.
        mode: ``"max"`` or ``"min"``.
        save_top_k: How many best checkpoints to keep.
        save_last: Also keep ``last.ckpt`` for resuming.
    """

    save_dir: Path
    monitor: str = "val/risk_f1_k1"
    mode: str = "max"
    save_top_k: int = 1
    save_last: bool = True

    def maybe_save(
        self,
        model: "nn.Module",
        metrics: Mapping[str, float],
        *,
        epoch: int,
        optimizer: "torch.optim.Optimizer | None" = None,
        scaler_state: Mapping[str, Any] | None = None,
        threshold: float | None = None,
    ) -> Path | None:
        """Save if ``metrics[monitor]`` improves. Returns the path, or None.

        Also refreshes ``last.ckpt`` when ``save_last`` is set, regardless of
        improvement.
        """
        raise NotImplementedError("TODO: compare metric, save, prune beyond save_top_k")

    def best_path(self) -> Path:
        """Path of the current best checkpoint."""
        raise NotImplementedError("TODO: save_dir / BEST_CHECKPOINT_NAME")

    def last_path(self) -> Path:
        """Path of the most recent checkpoint."""
        raise NotImplementedError("TODO: save_dir / LAST_CHECKPOINT_NAME")


def save_checkpoint(
    path: Path,
    model: "nn.Module",
    *,
    epoch: int,
    metrics: Mapping[str, float] | None = None,
    optimizer: "torch.optim.Optimizer | None" = None,
    scaler_state: Mapping[str, Any] | None = None,
    class_weights: Mapping[str, Any] | None = None,
    threshold: float | None = None,
) -> Path:
    """Write a self-sufficient checkpoint atomically.

    Writes to ``path.with_suffix(".tmp")`` then replaces, so an interrupted save
    never destroys the previous file.
    """
    raise NotImplementedError("TODO: assemble the payload, torch.save to temp, os.replace")


def load_checkpoint(
    path: Path, *, map_location: str = "cpu", strict_schema: bool = True
) -> dict[str, Any]:
    """Load a checkpoint payload.

    Args:
        path: Checkpoint file.
        map_location: Always ``"cpu"`` by default so GPU-trained checkpoints
            open on a CPU-only machine.
        strict_schema: Raise when the stored ``schema_version`` differs from
            :data:`src.data.unified_schema.SCHEMA_VERSION`.
    """
    raise NotImplementedError("TODO: torch.load(map_location=...), verify schema_version")


def load_model(path: Path, *, device: str = "auto") -> tuple["nn.Module", dict[str, Any]]:
    """Rebuild a model from a checkpoint and move it to ``device``.

    Returns:
        ``(model, payload)`` — the model in ``eval()`` mode, and the rest of the
        payload (scaler state, threshold, metrics) for the caller.
    """
    raise NotImplementedError("TODO: load payload -> WorldModel.from_config -> load_state_dict")


def resume(
    path: Path, model: "nn.Module", optimizer: "torch.optim.Optimizer"
) -> int:
    """Restore model and optimiser state in place; return the next epoch index."""
    raise NotImplementedError("TODO: load into model/optimizer, return epoch + 1")


def git_sha(short: bool = True) -> str:
    """Current git commit for provenance, or ``"unknown"`` outside a repo."""
    raise NotImplementedError("TODO: subprocess git rev-parse, swallow failures")


__all__ = [
    "BEST_CHECKPOINT_NAME",
    "LAST_CHECKPOINT_NAME",
    "CheckpointManager",
    "save_checkpoint",
    "load_checkpoint",
    "load_model",
    "resume",
    "git_sha",
]
