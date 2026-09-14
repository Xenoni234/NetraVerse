"""Ablations — evidence that each design choice actually earns its place.

An ablation table is the difference between "we built an LSTM encoder-decoder
world model with scheduled sampling and MC-dropout" and "here is what each of
those parts contributed". The second is a result; the first is a description.

The ablations
-------------
``encoder_only``          Drop the decoder; predict all horizons from the encoder
                          state with per-horizon heads. **The key ablation** — if
                          this matches the full model, the world-model framing is
                          unjustified and we should say so.
``flow_only``             Drop packet-level features. Decides whether the TShark
                          dependency is worth carrying.
``shuffled_time``         Shuffle windows within a sequence. A **sanity check**,
                          not a comparison: performance must collapse toward
                          chance. If it does not, the model is reading something
                          static (a host fingerprint) rather than dynamics, and
                          every other number is suspect.
``no_scheduled_sampling`` Pure teacher forcing. Should hurt most at ``k=4``,
                          which is precisely where lead time comes from.
``no_baseline_features``  Drop the per-host / peer-group z-scores. Tests whether
                          normalising against a host's own behaviour matters.
``single_horizon``        Train separate models per ``k``. Tests whether shared
                          multitask training helps or hurts.

Retrain vs. inference-only
--------------------------
``shuffled_time`` and ``flow_only`` (zeroing the packet columns) can run against
an existing checkpoint. The rest need retraining, which costs real time — plan
the ablation budget before the deadline, not after.

Fairness rules
--------------
Identical splits, identical seeds, identical epoch budget and identical
threshold-selection procedure. An ablation trained for fewer epochs is not an
ablation; it is a shorter run.

TODO
----
* [ ] Implement ``run_ablation`` dispatch and the six config mutators.
* [ ] Implement ``encoder_only`` — requires a model variant flag.
* [ ] Implement ``shuffled_time`` as an inference-time transform.
* [ ] Implement ``ablation_table`` with deltas against the full model.
* [ ] Add an assertion that shuffled-time actually collapses; if it does not,
      fail the run loudly rather than quietly reporting a great number.
* [ ] Record wall-clock cost per ablation so the budget can be planned.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Final, Mapping, Sequence

import numpy as np
import pandas as pd

#: Ablations that can be evaluated against an existing checkpoint.
INFERENCE_ONLY: Final[frozenset[str]] = frozenset({"shuffled_time", "flow_only"})

#: Ablations that require a fresh training run.
REQUIRES_RETRAIN: Final[frozenset[str]] = frozenset(
    {"encoder_only", "no_scheduled_sampling", "no_baseline_features", "single_horizon"}
)

#: Performance floor below which shuffled-time is considered to have collapsed
#: correctly. Anything above this is a red flag, not a good result.
SHUFFLED_TIME_MAX_F1: Final[float] = 0.30


@dataclass(frozen=True)
class AblationSpec:
    """One ablation: what it changes, and what it is meant to prove.

    Attributes:
        name: Identifier used in configs and tables.
        description: One line for the report.
        hypothesis: What we expect to happen, written down *before* running it.
        requires_retrain: Whether a fresh training run is needed.
        config_patch: Config keys overridden for this ablation.
    """

    name: str
    description: str
    hypothesis: str
    requires_retrain: bool
    config_patch: Mapping[str, Any]


#: The registry. Hypotheses are recorded up front so a surprising result is
#: visibly a surprise rather than something rationalised afterwards.
ABLATIONS: Final[Mapping[str, AblationSpec]] = {
    "encoder_only": AblationSpec(
        name="encoder_only",
        description="No decoder; per-horizon heads read the encoder state directly.",
        hypothesis="Comparable at k=1, clearly worse at k=4, since only the "
        "autoregressive decoder models compounding dynamics.",
        requires_retrain=True,
        config_patch={"model.arch": "encoder_only"},
    ),
    "flow_only": AblationSpec(
        name="flow_only",
        description="Packet-level features zeroed out.",
        hypothesis="Small drop overall; a larger drop on C2/botnet traffic, "
        "where beacon periodicity is the distinguishing signal.",
        requires_retrain=False,
        config_patch={"features.use_packet_features": False},
    ),
    "shuffled_time": AblationSpec(
        name="shuffled_time",
        description="Window order shuffled within each sequence. Sanity check.",
        hypothesis="Collapse toward chance. If it does not, the model is keying "
        "on static host characteristics, not dynamics.",
        requires_retrain=False,
        config_patch={},
    ),
    "no_scheduled_sampling": AblationSpec(
        name="no_scheduled_sampling",
        description="Pure teacher forcing throughout training.",
        hypothesis="Fine at k=1, degrading at k=2 and k=4 from exposure bias.",
        requires_retrain=True,
        config_patch={"training.scheduled_sampling.enabled": False},
    ),
    "no_baseline_features": AblationSpec(
        name="no_baseline_features",
        description="Per-host and peer-group z-scores removed.",
        hypothesis="Noticeable drop, and a larger one on cross-dataset "
        "generalisation, where absolute volumes are not comparable.",
        requires_retrain=True,
        config_patch={"features.use_baselines": False},
    ),
    "single_horizon": AblationSpec(
        name="single_horizon",
        description="A separate model trained per horizon k.",
        hypothesis="Marginally better at k=1, worse at k=4, and 3x the training "
        "cost — multitask sharing should act as a regulariser.",
        requires_retrain=True,
        config_patch={"model.horizons": [1]},
    ),
}


def run_ablation(
    name: str,
    config: Mapping[str, Any],
    *,
    checkpoint: Path | None = None,
    output_dir: Path | None = None,
) -> Mapping[str, Any]:
    """Run one ablation and return its metrics.

    Retrains when the spec requires it; otherwise evaluates the existing
    checkpoint under the ablation's inference-time transform.

    Raises:
        ValueError: if ``name`` is unknown, or a retrain-requiring ablation is
            requested without a training config.
    """
    raise NotImplementedError("TODO: look up spec, patch config, retrain or evaluate")


def run_all(
    config: Mapping[str, Any],
    names: Sequence[str],
    *,
    checkpoint: Path,
    output_dir: Path | None = None,
) -> Mapping[str, Mapping[str, Any]]:
    """Run every requested ablation, cheapest (inference-only) first.

    Ordering matters in practice: the inference-only ablations finish in minutes
    and often reveal a problem worth fixing before committing hours to retrains.
    """
    raise NotImplementedError("TODO: sort by cost, run each, collect results")


def shuffle_time_transform(x: np.ndarray, *, random_state: int = 1337) -> np.ndarray:
    """Shuffle the ``L`` axis independently per sample.

    Destroys temporal order while preserving the marginal feature distribution,
    isolating "does sequence order matter?" from "are these features useful?".
    """
    raise NotImplementedError("TODO: per-row permutation along axis 1")


def zero_packet_features(x: np.ndarray) -> np.ndarray:
    """Zero the packet-derived feature columns for the flow-only ablation."""
    raise NotImplementedError("TODO: zero the packet feature indices from FEATURE_COLUMNS")


def assert_shuffled_time_collapses(metrics: Mapping[str, float]) -> None:
    """Fail loudly if the shuffled-time sanity check does *not* collapse.

    A model that scores well on shuffled input is not reading dynamics, which
    invalidates the entire premise. Better to fail the run than to publish it.
    """
    raise NotImplementedError("TODO: assert f1 <= SHUFFLED_TIME_MAX_F1 with a clear message")


def ablation_table(
    full_model: Mapping[str, Any], ablations: Mapping[str, Mapping[str, Any]]
) -> pd.DataFrame:
    """Build the ablation table: one row per ablation, deltas from the full model.

    Columns: ablation, F1 at each horizon, delta F1, median lead time, delta lead
    time, whether the recorded hypothesis held.
    """
    raise NotImplementedError("TODO: assemble the frame with signed deltas")


__all__ = [
    "INFERENCE_ONLY",
    "REQUIRES_RETRAIN",
    "SHUFFLED_TIME_MAX_F1",
    "AblationSpec",
    "ABLATIONS",
    "run_ablation",
    "run_all",
    "shuffle_time_transform",
    "zero_packet_features",
    "assert_shuffled_time_collapses",
    "ablation_table",
]
