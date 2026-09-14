"""Plain-English explanation of the current forecast.

Renders an :class:`src.explain.human_readable.AlertNarrative`: the headline,
the evidence clauses, and the confidence wording. Optionally a small SHAP bar
chart behind an expander, for the technically curious judge.

The sentences come precomputed from the cached attributions; this panel only
formats them. If the SHAP cache is missing, hide the panel rather than computing
live - kernel SHAP mid-demo would hang the page.

TODO
----
* [ ] Implement ``render`` from AlertNarrative.as_markdown().
* [ ] Colour the confidence chip to match the risk colour scale.
* [ ] Hide the whole panel when the SHAP cache is absent - never compute live.
* [ ] Keep to three evidence bullets; more is a data dump, not an explanation.
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence


def render(narrative: Any | None, *, show_shap_chart: bool = False) -> None:
    """Draw the narrative into the current Streamlit container."""
    raise NotImplementedError("TODO: headline, evidence bullets, confidence chip, optional SHAP expander")


def render_shap_bars(attribution: Any, *, top_k: int = 5) -> None:
    """Horizontal bar chart of signed per-feature attributions."""
    raise NotImplementedError("TODO: diverging bars, feature names on the axis, sign preserved")


__all__ = ["render", "render_shap_bars"]
