"""MC-dropout inference — turning a point forecast into a band.

"Attack probability at +40 s is 0.63" is not actionable on its own. "0.63, with
a 90 % band of 0.58-0.68" is a call to act; "0.63, band 0.10-0.95" means the
model has no idea and the analyst should look at the raw traffic instead. For a
forecasting system that asks people to act *before* anything has happened, that
distinction is the difference between a usable tool and an ignored one.

Method. Dropout is normally switched off at eval time. MC-dropout leaves it on,
runs the same input ``T`` times, and treats the spread of the outputs as an
approximation to the model's posterior (Gal & Ghahramani, 2016). It is cheap,
needs no architecture change, and composes with the K-step rollout: each of the
``T`` passes is a *different simulated future*, so the band naturally widens with
horizon — which is exactly the behaviour we want to show on the dashboard.

Two sources of spread are worth separating:

* **epistemic** — model uncertainty, what MC-dropout measures; shrinks with more
  training data
* **aleatoric** — irreducible noise in the traffic itself

Only epistemic is estimated here. Say so in the report rather than implying the
band covers everything.

Cost: ``T`` forward passes. ``T=30`` is the config default; the dev config uses 0
(disabled), and the demo can drop to ~10 for interactivity.

TODO
----
* [ ] Implement ``mc_dropout_simulate`` (T rollouts with dropout active).
* [ ] Implement ``UncertaintyBand`` percentile computation.
* [ ] Implement ``enable_dropout`` / ``restore_eval`` as a context manager, so a
      caller cannot accidentally leave dropout on for normal inference.
* [ ] Batch the T passes where memory allows (repeat along the batch axis) —
      far faster than a Python loop over T.
* [ ] Implement ``predictive_entropy`` for the stage head.
* [ ] Calibrate: reliability diagram + Brier score on the val split, and decide
      whether temperature scaling is needed. Record in DESIGN.md.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final, Iterator, Mapping, Sequence

import numpy as np

if TYPE_CHECKING:
    from torch import nn

    from src.inference.forward_sim import SimulationResult

#: Default number of stochastic forward passes.
DEFAULT_MC_SAMPLES: Final[int] = 30

#: Default central interval reported on the dashboard.
DEFAULT_CONFIDENCE: Final[float] = 0.90


@dataclass(frozen=True)
class UncertaintyBand:
    """Point estimate plus an uncertainty interval over a simulated future.

    Attributes:
        mean: ``(B, n_steps)`` mean prediction across MC samples.
        median: ``(B, n_steps)`` median — more robust for display.
        lower: ``(B, n_steps)`` lower percentile of the band.
        upper: ``(B, n_steps)`` upper percentile.
        std: ``(B, n_steps)`` standard deviation across samples.
        confidence: The interval's nominal coverage, e.g. 0.90.
        n_samples: How many stochastic passes produced this band.
    """

    mean: np.ndarray
    median: np.ndarray
    lower: np.ndarray
    upper: np.ndarray
    std: np.ndarray
    confidence: float = DEFAULT_CONFIDENCE
    n_samples: int = DEFAULT_MC_SAMPLES

    def width(self) -> np.ndarray:
        """``upper - lower`` — the headline "how sure are we" number."""
        raise NotImplementedError("TODO: upper - lower")

    def is_confident(self, max_width: float = 0.25) -> np.ndarray:
        """Boolean mask of predictions whose band is tight enough to act on."""
        raise NotImplementedError("TODO: width() <= max_width")


@contextmanager
def dropout_enabled(model: "nn.Module") -> Iterator["nn.Module"]:
    """Context manager that activates dropout layers only, then restores state.

    Keeps the rest of the model (notably any normalisation layers) in eval mode.
    Using a context manager rather than a bare setter means dropout cannot be
    left on by accident for ordinary inference.
    """
    raise NotImplementedError("TODO: record module training flags, set Dropout.train(), restore")


def mc_dropout_simulate(
    model: "nn.Module",
    history: np.ndarray,
    *,
    n_samples: int = DEFAULT_MC_SAMPLES,
    n_steps: int = 4,
    confidence: float = DEFAULT_CONFIDENCE,
    device: str = "auto",
    batch_samples: bool = True,
    **sim_kwargs: Any,
) -> tuple["SimulationResult", dict[str, UncertaintyBand]]:
    """Run ``n_samples`` stochastic rollouts and summarise the spread.

    Args:
        model: Trained world model.
        history: ``(B, L, F)`` scaled history.
        n_samples: Stochastic forward passes; 0 disables MC-dropout and returns
            a deterministic result with zero-width bands.
        n_steps: Simulation depth.
        confidence: Nominal coverage of the reported interval.
        device: ``auto`` / ``cpu`` / ``cuda``.
        batch_samples: Repeat the batch along dim 0 to run all T passes at once.
        **sim_kwargs: Forwarded to :func:`src.inference.forward_sim.simulate`.

    Returns:
        ``(mean_result, bands)`` where ``bands`` has keys ``"risk"`` and
        ``"state"`` (and ``"stage"`` once predictive entropy is implemented).
    """
    raise NotImplementedError("TODO: T rollouts under dropout_enabled, then summarise")


def summarise_samples(
    samples: np.ndarray, *, confidence: float = DEFAULT_CONFIDENCE
) -> UncertaintyBand:
    """Turn ``(T, B, n_steps)`` stochastic samples into an :class:`UncertaintyBand`."""
    raise NotImplementedError("TODO: mean/median/std and the two percentiles")


def predictive_entropy(stage_probs: np.ndarray) -> np.ndarray:
    """Entropy of the mean stage distribution — "which kind of attack" doubt.

    Args:
        stage_probs: ``(T, B, n_steps, n_stages)`` MC samples.

    Returns:
        ``(B, n_steps)`` entropy, higher meaning less certain about the stage.
    """
    raise NotImplementedError("TODO: mean over T, then -sum(p log p) over classes")


def reliability_curve(
    probabilities: np.ndarray, labels: np.ndarray, *, n_bins: int = 10
) -> Mapping[str, np.ndarray]:
    """Reliability (calibration) curve plus the Brier score.

    If predicted 0.7 does not mean "happens 70 % of the time", the bands above
    are decorative. Run this on val before trusting any of it.
    """
    raise NotImplementedError("TODO: bin by predicted prob, compare to empirical rate")


__all__ = [
    "DEFAULT_MC_SAMPLES",
    "DEFAULT_CONFIDENCE",
    "UncertaintyBand",
    "dropout_enabled",
    "mc_dropout_simulate",
    "summarise_samples",
    "predictive_entropy",
    "reliability_curve",
]
