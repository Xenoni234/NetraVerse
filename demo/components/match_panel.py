"""Closest known attack trajectory, with its similarity score.

Renders the ranked output of
:meth:`src.inference.trajectory_match.TrajectoryLibrary.match`: which known
campaign the simulated future resembles, how closely, and an overlay of the two
trajectories.

Always show the similarity number next to the label. And when nothing matches
above threshold, say so plainly - "no close match to known patterns" is a useful
answer that flags a possible novel attack, not an empty panel.

TODO
----
* [ ] Implement ``render`` including the explicit no-match state.
* [ ] Link each match to its source campaign so it can be checked.
* [ ] Never round a weak similarity up into sounding confident.
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence


def render(matches: Sequence[Any] | None, *, top_k: int = 3, show_overlay: bool = True) -> None:
    """Draw the match list and optional trajectory overlay."""
    raise NotImplementedError("TODO: ranked list with scores, overlay chart, explicit no-match message")


def render_overlay(query: Any, exemplar: Any) -> None:
    """Overlay the simulated trajectory on the matched exemplar."""
    raise NotImplementedError("TODO: two-line chart per key feature, aligned on the match offset")


__all__ = ["render", "render_overlay"]
