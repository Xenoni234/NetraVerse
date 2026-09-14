"""Dashboard widgets — one function per panel, each drawing from replay data only.

Panels
------
``risk_timeline``      Risk over time with the true-attack span shaded. The
                       money shot: the curve visibly rising before the shading.
``forecast_panel``     The simulated next 40 s, with the MC-dropout band.
``explanation_panel``  Plain-English "why", from ``src.explain.human_readable``.
``match_panel``        Closest known attack trajectory and its similarity score.
``feature_table``      Current feature values against the host's own baseline.
``alert_banner``       Big, unmissable current alert state and lead time.
``metrics_strip``      Headline test-set numbers, for credibility.

Rules for every panel
---------------------
1. **Pure rendering.** Take data, draw. No model calls, no file reads, no
   computation beyond formatting — those belong upstream.
2. **Degrade gracefully.** Given ``None``, render a short "not available" note
   and return. Never raise.
3. **Honest about uncertainty.** Where a band exists, show it. Never present a
   hedged number as a flat one.
4. **Readable from three metres.** This is shown on a projector to people
   standing up. Large type, high contrast, few elements.

TODO
----
* [ ] Implement each panel in its own module under this package.
* [ ] Share one colour scale for risk across every panel (colourblind-safe).
* [ ] Test each panel with empty / partial data before the demo, not during it.
"""

from __future__ import annotations

from typing import Final

#: Risk colour thresholds, shared across panels so colour means one thing.
RISK_COLOURS: Final[tuple[tuple[float, str], ...]] = (
    (0.3, "#2e7d32"),   # green  - quiet
    (0.6, "#f9a825"),   # amber  - elevated
    (1.01, "#c62828"),  # red    - alerting
)

#: Colour of the shaded true-attack span on the timeline.
TRUE_ATTACK_COLOUR: Final[str] = "#90a4ae"

__all__ = [
    "RISK_COLOURS",
    "TRUE_ATTACK_COLOUR",
    "risk_timeline",
    "forecast_panel",
    "explanation_panel",
    "match_panel",
    "feature_table",
    "alert_banner",
    "metrics_strip",
]
