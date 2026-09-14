"""The training loop, with scheduled sampling and early stopping.

Responsibilities
----------------
* build model, optimiser, scheduler and loss from an OmegaConf config
* run epochs of train / validate, with a per-epoch scheduled-sampling ratio
* track the monitored metric (default ``val/risk_f1_k1``) and stop early
* checkpoint the best and last states, including the scaler
* keep everything device-agnostic — the same code path runs on CPU

Deliberate choices
------------------
**Validate with teacher forcing OFF.** Validation must measure the free-running
regime the model faces at inference. Validating with teacher forcing produces a
number that looks good and predicts nothing.

**Monitor an F1, not the loss.** The multitask loss mixes three scales; its
minimum does not coincide with the best forecaster. Monitor the metric the
project is judged on.

**Seed everything.** Same seed, same data, same numbers — otherwise the ablation
table is noise.

TODO
----
* [ ] Implement ``train`` (the public entry point called by ``scripts/train.py``).
* [ ] Implement ``train_one_epoch`` / ``validate``.
* [ ] Wire ``scheduled_sampling.ratio_for_epoch`` into the forward pass.
* [ ] Implement ``EarlyStopping`` with ``mode`` and ``patience``.
* [ ] Implement gradient clipping (``training.grad_clip``) — LSTMs need it.
* [ ] Implement ``build_optimizer`` / ``build_scheduler`` (cosine + warmup).
* [ ] Implement ``set_seed`` covering python / numpy / torch / cudnn.
* [ ] Add an "overfit one batch" smoke mode; if the model cannot drive a single
      batch's loss to ~0, the bug is in the model, not the data.
* [ ] Log throughput (windows/sec) so we notice when the data path regresses.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Mapping

if TYPE_CHECKING:
    import torch
    from torch import nn
    from torch.utils.data import DataLoader


@dataclass
class TrainState:
    """Mutable state carried across epochs.

    Attributes:
        epoch: Zero-based epoch index.
        global_step: Optimiser steps taken so far.
        best_metric: Best value of the monitored metric so far.
        best_epoch: Epoch that produced ``best_metric``.
        history: Per-epoch metric dicts, written alongside the checkpoint.
        should_stop: Set by early stopping.
    """

    epoch: int = 0
    global_step: int = 0
    best_metric: float = float("-inf")
    best_epoch: int = -1
    history: list[dict[str, float]] = field(default_factory=list)
    should_stop: bool = False


class EarlyStopping:
    """Stop when the monitored metric has not improved for ``patience`` epochs.

    Args:
        patience: Epochs to wait before stopping.
        mode: ``"max"`` for F1-like metrics, ``"min"`` for losses.
        min_delta: Improvement smaller than this does not count.
    """

    def __init__(self, patience: int = 8, mode: str = "max", min_delta: float = 0.0) -> None:
        raise NotImplementedError("TODO: store config, initialise the best value")

    def update(self, metric: float) -> bool:
        """Record ``metric``; return True when training should stop."""
        raise NotImplementedError("TODO: compare against best with mode/min_delta")


def train(
    config: Mapping[str, Any],
    *,
    train_loader: "DataLoader",
    val_loader: "DataLoader",
    scaler_state: dict[str, Any] | None = None,
    on_epoch_end: Callable[[TrainState], None] | None = None,
) -> tuple["nn.Module", TrainState]:
    """Run a full training job.

    Args:
        config: Resolved config (``configs/train.yaml`` or ``dev.yaml``).
        train_loader: Batches of ``(x, y_state, y_risk, y_stage)``.
        val_loader: Same, for the validation split.
        scaler_state: Train-fit scaler, stored in the checkpoint so inference
            can reproduce preprocessing exactly.
        on_epoch_end: Optional hook, used by the demo and notebooks to stream
            progress.

    Returns:
        ``(model, state)`` — the best model (weights reloaded from the best
        checkpoint) and the final :class:`TrainState`.
    """
    raise NotImplementedError("TODO: seed, build, loop epochs, early stop, checkpoint")


def train_one_epoch(
    model: "nn.Module",
    loader: "DataLoader",
    criterion: "nn.Module",
    optimizer: "torch.optim.Optimizer",
    *,
    device: "torch.device",
    teacher_forcing_ratio: float,
    grad_clip: float | None = 1.0,
    log_every_n_steps: int = 100,
) -> dict[str, float]:
    """One training epoch. Returns the mean loss components for logging."""
    raise NotImplementedError("TODO: model.train(), iterate, backward, clip, step")


def validate(
    model: "nn.Module",
    loader: "DataLoader",
    criterion: "nn.Module",
    *,
    device: "torch.device",
    horizons: tuple[int, ...] = (1, 2, 4),
) -> dict[str, float]:
    """One validation pass, free-running (teacher forcing disabled).

    Returns loss components plus the per-horizon metrics from
    :mod:`src.eval.metrics`, keyed like ``val/risk_f1_k1``.
    """
    raise NotImplementedError("TODO: model.eval(), no_grad, collect preds, compute metrics")


def build_optimizer(
    model: "nn.Module", config: Mapping[str, Any]
) -> "torch.optim.Optimizer":
    """Build the optimiser (AdamW) from the ``training`` config block."""
    raise NotImplementedError("TODO: AdamW with lr and weight_decay from config")


def build_scheduler(
    optimizer: "torch.optim.Optimizer", config: Mapping[str, Any], steps_per_epoch: int
) -> "Any | None":
    """Build the LR scheduler (``cosine`` with warmup, ``plateau``, or none)."""
    raise NotImplementedError("TODO: cosine-with-warmup and plateau variants")


def set_seed(seed: int, *, deterministic: bool = True) -> None:
    """Seed python, numpy and torch; optionally force deterministic cuDNN.

    Determinism costs some speed and is worth it: the ablation table is only
    meaningful if reruns agree.
    """
    raise NotImplementedError("TODO: random / numpy / torch seeds + cudnn flags")


def overfit_one_batch(
    config: Mapping[str, Any], batch: tuple[Any, ...], *, steps: int = 200
) -> list[float]:
    """Smoke test: drive a single batch's loss toward zero.

    If this does not converge, the bug is in the model or the loss, not in the
    data pipeline. Run it before every long training job.
    """
    raise NotImplementedError("TODO: repeated forward/backward on one batch, return losses")


__all__ = [
    "TrainState",
    "EarlyStopping",
    "train",
    "train_one_epoch",
    "validate",
    "build_optimizer",
    "build_scheduler",
    "set_seed",
    "overfit_one_batch",
]
