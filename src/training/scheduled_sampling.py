"""Scheduled sampling: the teacher-forcing to free-running ramp.

The problem this solves — *exposure bias*. If the decoder is always fed the
ground-truth previous state during training, it never learns to cope with its
own imperfect predictions. At inference it must consume its own output for K
steps, hits inputs it has never seen, and the error compounds. For a system
whose entire value proposition is multi-step forecasting, that failure mode is
fatal.

Scheduled sampling (Bengio et al., 2015) fixes it by flipping a coin at every
decoder step: with probability ``p`` feed the model's own prediction, otherwise
feed the ground truth. ``p`` ramps from ``start_prob`` (0.0 — pure teacher
forcing, easy to learn) to ``end_prob`` (0.9 — nearly free-running, matching
inference) across training.

Three schedules
---------------
``linear``           ``p = start + (end - start) * progress``
``exponential``      ``p = end - (end - start) * decay ** epoch``
``inverse_sigmoid``  ``p`` follows a sigmoid in epoch — slow start, fast middle,
                     gentle finish. The usual default: it keeps the early epochs
                     stable while still reaching the free-running regime.

Note the convention: ``p`` is the probability of using the model's **own
prediction**, i.e. ``1 - teacher_forcing_ratio``. It is defined this way so that
"p goes up as training progresses" matches "the task gets harder". Be explicit
about it at every call site — sign errors here are silent and expensive.

TODO
----
* [ ] Implement the three schedule functions.
* [ ] Implement ``ScheduledSampler.ratio_for_epoch`` and ``should_use_prediction``.
* [ ] Decide per-step vs. per-sequence coin flips. Per-step is standard; per-
      sequence gives a cleaner "fully free-running" signal. Ablate.
* [ ] Add the ``no_scheduled_sampling`` ablation path (always teacher forcing)
      so ``src/eval/ablations.py`` can measure what this buys.
* [ ] Plot the realised ratio per epoch into the training report.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Literal

import numpy as np

Schedule = Literal["linear", "exponential", "inverse_sigmoid", "constant"]

#: Steepness constant for the inverse-sigmoid schedule; larger = slower ramp.
INVERSE_SIGMOID_K: Final[float] = 12.0


@dataclass(frozen=True)
class ScheduledSamplingConfig:
    """Scheduled-sampling parameters, from the ``training`` config block.

    Attributes:
        enabled: When False, always teacher-force (the ablation baseline).
        schedule: Ramp shape.
        start_prob: Probability of using the model's own prediction at epoch 0.
        end_prob: Probability at the final epoch.
        warmup_epochs: Epochs of pure teacher forcing before the ramp starts.
        per_step: Flip the coin per decoder step (True) or once per sequence.
    """

    enabled: bool = True
    schedule: Schedule = "inverse_sigmoid"
    start_prob: float = 0.0
    end_prob: float = 0.9
    warmup_epochs: int = 5
    per_step: bool = True


class ScheduledSampler:
    """Produces the sampling ratio for an epoch and the per-step coin flips."""

    def __init__(self, config: ScheduledSamplingConfig, total_epochs: int, seed: int = 1337) -> None:
        raise NotImplementedError("TODO: store config, total_epochs, seed an RNG")

    def ratio_for_epoch(self, epoch: int) -> float:
        """Probability of feeding the model's own prediction at this epoch.

        Returns 0.0 during warmup and when ``enabled`` is False.
        """
        raise NotImplementedError("TODO: dispatch on schedule after the warmup offset")

    def should_use_prediction(self, ratio: float, batch_size: int, *, per_step: bool | None = None) -> np.ndarray:
        """Boolean mask deciding, per sample, whether to feed the prediction.

        Returns:
            ``(batch_size,)`` bool array. True means "use the model's own
            prediction"; False means "use the ground truth".
        """
        raise NotImplementedError("TODO: rng.random(batch_size) < ratio")


def linear_schedule(progress: float, start: float, end: float) -> float:
    """Straight-line ramp. ``progress`` in ``[0, 1]``."""
    raise NotImplementedError("TODO: start + (end - start) * clamped progress")


def exponential_schedule(progress: float, start: float, end: float, decay: float = 0.85) -> float:
    """Fast early ramp that flattens out near ``end``."""
    raise NotImplementedError("TODO: end - (end - start) * decay ** (progress * n)")


def inverse_sigmoid_schedule(
    progress: float, start: float, end: float, k: float = INVERSE_SIGMOID_K
) -> float:
    """Sigmoid ramp — slow, then fast, then gentle. The recommended default."""
    raise NotImplementedError("TODO: sigmoid in progress, rescaled onto [start, end]")


def constant_schedule(progress: float, start: float, end: float) -> float:
    """Fixed ratio, ignoring progress. Useful for controlled ablations."""
    raise NotImplementedError("TODO: return end")


def schedule_preview(config: ScheduledSamplingConfig, total_epochs: int) -> list[float]:
    """Return the ratio for every epoch, for plotting into the training report.

    Cheap way to catch a mis-parameterised schedule before burning an hour of
    GPU on it.
    """
    raise NotImplementedError("TODO: [ratio_for_epoch(e) for e in range(total_epochs)]")


__all__ = [
    "Schedule",
    "INVERSE_SIGMOID_K",
    "ScheduledSamplingConfig",
    "ScheduledSampler",
    "linear_schedule",
    "exponential_schedule",
    "inverse_sigmoid_schedule",
    "constant_schedule",
    "schedule_preview",
]
