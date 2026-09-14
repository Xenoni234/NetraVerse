"""The simulated future: what the world model thinks the next 40 s look like.

Shows the K-step forward simulation from :mod:`src.inference.forward_sim`:
predicted risk per step ahead, with the MC-dropout confidence band, plus the two
or three feature trajectories that are moving most.

This is the panel that demonstrates the world model *is* a world model - it
projects a future state, not just a score. Show the band widening with horizon;
that honesty is a feature, not an admission.

TODO
----
* [ ] Implement ``render`` with the band ribbon.
* [ ] Show seconds-ahead on the x axis, not step indices - judges read seconds.
* [ ] Pick displayed features by largest simulated change, not a fixed list.
* [ ] Handle the band-absent case (MC-dropout disabled) without a layout jump.
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence


def render(simulation: Mapping[str, Any], *, band: Mapping[str, Any] | None = None, stride_seconds: int = 10, top_features: int = 3) -> None:
    """Draw the simulated future into the current Streamlit container."""
    raise NotImplementedError("TODO: per-step risk line, ribbon band, small feature sparklines")


def render_feature_trajectories(simulation: Mapping[str, Any], feature_names: Sequence[str]) -> None:
    """Sparklines of the features moving most across the simulated steps."""
    raise NotImplementedError("TODO: pick top movers by absolute change, draw compact sparklines")


__all__ = ["render", "render_feature_trajectories"]
