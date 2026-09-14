"""Current feature values against the host's own baseline.

A compact table of the features that matter right now: current value, the
host's baseline, and the deviation. Backs up whatever the explanation panel
claims with the raw numbers - an analyst who does not trust the narrative can
check it here.

Shows real units (bytes/s, distinct ports), never scaled z-scores; that means
inverse-transforming through the saved scaler.

TODO
----
* [ ] Implement ``render`` with inverse-scaled real units.
* [ ] Sort highlighted (explanation-cited) features to the top.
* [ ] Show an explicit 'no baseline yet' state for cold-start hosts.
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence


def render(current: Mapping[str, float], baseline: Mapping[str, float] | None = None, *, highlight: Sequence[str] = (), max_rows: int = 12) -> None:
    """Draw the feature comparison table."""
    raise NotImplementedError("TODO: current vs baseline vs delta, highlighted rows first, real units")


def format_row(name: str, current: float, baseline: float | None) -> None:
    """Format one row with a human-readable unit and delta."""
    raise NotImplementedError("TODO: delegate number formatting to human_readable.format_magnitude")


__all__ = ["render", "format_row"]
