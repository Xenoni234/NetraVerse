"""Risk-over-time timeline — the single most important panel in the demo.

Draws predicted risk against wall-clock time for the selected host, with the
true-attack span shaded and the alert threshold marked. When the model works,
the curve climbs into the red *before* the shading begins, and the gap between
those two points is the lead time the whole project is about.

Only data the controller marks visible at the current replay step may be drawn —
see :meth:`demo.replay_controller.ReplayController.visible_window`.

TODO
----
* [ ] Implement ``render`` (matplotlib or Altair — pick one and use it everywhere).
* [ ] Shade the true-attack span, mark the threshold, mark the first alert.
* [ ] Annotate the lead-time gap with an arrow and a large label.
* [ ] Draw the uncertainty band as a shaded ribbon when available.
* [ ] Keep it readable at projector distance: thick lines, large fonts.
"""

from __future__ import annotations

from typing import Any, Mapping

import pandas as pd


def render(
    visible: pd.DataFrame,
    *,
    threshold: float = 0.5,
    band: Mapping[str, Any] | None = None,
    show_true_attack: bool = True,
    height: int = 320,
) -> None:
    """Draw the risk timeline into the current Streamlit container.

    Args:
        visible: Windows visible at the current replay step, time-ordered.
        threshold: Alert threshold, drawn as a horizontal rule.
        band: Optional uncertainty band, drawn as a ribbon.
        show_true_attack: Shade the ground-truth attack span.
        height: Chart height in pixels.
    """
    raise NotImplementedError("TODO: risk line, threshold rule, attack shading, lead-time arrow")


def annotate_lead_time(chart: Any, first_alert_time: pd.Timestamp, attack_time: pd.Timestamp) -> Any:
    """Annotate the gap between first alert and true attack start."""
    raise NotImplementedError("TODO: arrow plus a large 'N s early' label")


__all__ = ["render", "annotate_lead_time"]
