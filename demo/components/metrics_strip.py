"""Headline test-set metrics, for credibility.

A thin strip of the numbers from the real evaluation: F1 per horizon,
median lead time, false-positive rate, and how each compares to the baselines.
Read from ``reports/<run>/metrics.json``, never recomputed.

Its job is to answer "is this demo cherry-picked?" before anyone asks. Include
the provenance line - checkpoint, git SHA, split - so the numbers are
traceable.

TODO
----
* [ ] Implement ``render`` from metrics.json.
* [ ] Show the baseline delta next to each number, not the number alone.
* [ ] State clearly which split these came from (test, touched once).
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence


def render(metrics: Mapping[str, Any] | None, *, horizons: Sequence[int] = (1, 2, 4)) -> None:
    """Draw the metrics strip."""
    raise NotImplementedError("TODO: st.metric tiles per horizon, deltas against the baseline")


def render_provenance(provenance: Mapping[str, str] | None) -> None:
    """Small caption: checkpoint, git SHA, split, schema version."""
    raise NotImplementedError("TODO: single-line caption, hidden when provenance is missing")


__all__ = ["render", "render_provenance"]
