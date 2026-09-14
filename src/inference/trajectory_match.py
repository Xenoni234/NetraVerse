"""Match a simulated future against a library of known attack trajectories.

The risk head says *how likely*; the stage head says *what kind*. This module
answers the question an analyst asks next: **"what does this look like?"** — by
comparing the simulated trajectory against stored exemplars of attack campaigns
seen during training.

Output is a ranked list of matches:

    "Next 40 s resembles 'CIC-IDS2017 Tuesday FTP brute force', similarity 0.84"

That is a concrete, checkable claim: the analyst can pull up the reference
campaign and compare. It also makes the world model's simulated future *useful*
rather than merely decorative — matching operates on the predicted trajectory,
something a plain classifier cannot produce.

Method
------
A trajectory is the ``(L + n_steps, F)`` sequence of observed history followed by
simulated future. Exemplars are the same shape, extracted from labelled attack
campaigns in the training split. Similarity via:

* **cosine similarity** over a flattened, normalised trajectory — fast baseline
* **DTW** (dynamic time warping) — tolerant of an attack unfolding faster or
  slower than the exemplar; more expensive, better matches
* **feature-subset matching** — restrict to the features that define a stage
  (fan-out and failed connections for RECON, rate and SYN fraction for IMPACT)

Start with cosine, add DTW if the matches are unconvincing.

Honesty requirement
-------------------
Always report the similarity score with the label, and suppress matches below
``MIN_SIMILARITY``. A confident-sounding wrong match is worse than no match: it
sends an analyst down the wrong path. Novel attacks *should* return "no close
match" — that is a useful answer, not a failure.

TODO
----
* [ ] Implement ``TrajectoryLibrary`` (build from train split, save/load).
* [ ] Implement ``match`` returning ranked :class:`TrajectoryMatch` objects.
* [ ] Implement ``cosine_similarity`` and ``dtw_distance`` (pure numpy; do not
      add a dependency just for DTW).
* [ ] Normalise trajectories before comparison — shape should matter, absolute
      volume should not, or every high-traffic host matches every other.
* [ ] Decide exemplar granularity: one per campaign, per attack family, or
      k-means centroids within a family? Start with per-family centroids.
* [ ] Cap library size and use a vectorised distance over the whole library —
      the demo needs a match in well under a second.
* [ ] Evaluate: does the top-1 match's family agree with the true family? That
      is a real, reportable number, not just a demo flourish.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal, Sequence

import numpy as np

#: Matches below this similarity are suppressed as "no close match".
MIN_SIMILARITY: Final[float] = 0.60

#: Default number of matches returned.
TOP_K: Final[int] = 3

SimilarityMetric = Literal["cosine", "dtw", "euclidean"]


@dataclass(frozen=True)
class TrajectoryExemplar:
    """One stored reference trajectory from a known campaign.

    Attributes:
        trajectory: ``(T, F)`` normalised feature sequence.
        attack_family: Canonical family, e.g. ``"PortScan"``.
        attack_stage: ATT&CK stage id 0..6.
        campaign_id: Source campaign, so an analyst can go look at it.
        dataset: Source dataset.
        description: Human-readable label used in the UI.
    """

    trajectory: np.ndarray
    attack_family: str
    attack_stage: int
    campaign_id: str
    dataset: str
    description: str


@dataclass(frozen=True)
class TrajectoryMatch:
    """A scored match between a simulated future and a stored exemplar."""

    exemplar: TrajectoryExemplar
    similarity: float
    metric: SimilarityMetric
    aligned_offset: int = 0  # DTW/shift alignment, for plotting the overlay

    def is_confident(self, threshold: float = MIN_SIMILARITY) -> bool:
        """Whether this match is strong enough to show to a human."""
        raise NotImplementedError("TODO: similarity >= threshold")


class TrajectoryLibrary:
    """A searchable collection of known attack trajectories.

    Built once from the TRAIN split (never val or test — that would leak), saved
    next to the checkpoint, and loaded by the eval harness and the demo.
    """

    def __init__(self, exemplars: Sequence[TrajectoryExemplar] | None = None) -> None:
        raise NotImplementedError("TODO: store exemplars, pre-stack into a matrix for speed")

    @classmethod
    def build(
        cls,
        windows: object,
        *,
        history_length: int = 10,
        n_steps: int = 4,
        per_family: int = 8,
        random_state: int = 1337,
    ) -> "TrajectoryLibrary":
        """Extract exemplars from labelled training windows.

        Args:
            windows: Labelled, windowed training frame.
            history_length: ``L``, to match the model's input.
            n_steps: Simulated depth the library must be comparable against.
            per_family: Exemplars kept per attack family (k-means centroids).
            random_state: Seed for the clustering.
        """
        raise NotImplementedError("TODO: slice attack trajectories, cluster per family")

    def match(
        self,
        trajectory: np.ndarray,
        *,
        top_k: int = TOP_K,
        metric: SimilarityMetric = "cosine",
        min_similarity: float = MIN_SIMILARITY,
    ) -> list[TrajectoryMatch]:
        """Rank library exemplars against a query trajectory.

        Args:
            trajectory: ``(T, F)`` history + simulated future.
            top_k: Maximum matches to return.
            metric: Similarity measure.
            min_similarity: Matches below this are dropped — an empty list means
                "nothing in the library looks like this", which is a legitimate
                and informative answer.

        Returns:
            Matches sorted by descending similarity; possibly empty.
        """
        raise NotImplementedError("TODO: vectorised distance over the stacked library")

    def save(self, path: Path) -> Path:
        """Persist the library (npz of trajectories + parquet of metadata)."""
        raise NotImplementedError("TODO: save arrays and metadata together")

    @classmethod
    def load(cls, path: Path) -> "TrajectoryLibrary":
        """Load a library written by :meth:`save`."""
        raise NotImplementedError("TODO: inverse of save")

    def __len__(self) -> int:
        raise NotImplementedError


def normalise_trajectory(trajectory: np.ndarray) -> np.ndarray:
    """Per-feature normalisation so shape, not magnitude, drives the match."""
    raise NotImplementedError("TODO: per-feature centring and unit scaling, NaN-safe")


def cosine_similarity(a: np.ndarray, b: np.ndarray) -> float:
    """Cosine similarity between two flattened trajectories, in ``[-1, 1]``."""
    raise NotImplementedError("TODO: dot / (norm * norm) with a zero-norm guard")


def dtw_distance(a: np.ndarray, b: np.ndarray, *, band: int | None = None) -> float:
    """Dynamic time warping distance, tolerant of differing attack speeds.

    Args:
        a: ``(T1, F)`` query trajectory.
        b: ``(T2, F)`` exemplar trajectory.
        band: Sakoe-Chiba band width; limits warping and keeps cost down.
    """
    raise NotImplementedError("TODO: banded DTW over the per-step distance matrix, pure numpy")


def match_accuracy(matches: Sequence[Sequence[TrajectoryMatch]], true_families: Sequence[str]) -> float:
    """Top-1 family accuracy of the matcher — a reportable number, not a demo trick."""
    raise NotImplementedError("TODO: compare top match family against ground truth")


__all__ = [
    "MIN_SIMILARITY",
    "TOP_K",
    "SimilarityMetric",
    "TrajectoryExemplar",
    "TrajectoryMatch",
    "TrajectoryLibrary",
    "normalise_trajectory",
    "cosine_similarity",
    "dtw_distance",
    "match_accuracy",
]
