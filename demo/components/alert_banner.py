"""Big, unmissable current alert state and lead time.

The top strip of the dashboard. Four states from
:class:`demo.replay_controller.AlertState` - quiet, elevated, alerting, attack
active - each with its own colour from the shared risk scale.

Once a sustained alert has fired and the true attack has started, this is where
the lead time goes, in large type. That number is the pitch.

TODO
----
* [ ] Implement ``render`` for all four states.
* [ ] Large type - readable from three metres on a projector.
* [ ] Do not show a lead time until both events have actually occurred.
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence


def render(state: Any, *, risk: float, lead_time_seconds: float | None = None, entity_id: str = '', horizon_seconds: int = 20) -> None:
    """Draw the alert banner into the current Streamlit container."""
    raise NotImplementedError("TODO: state-coloured banner, risk percentage, large lead-time readout")


def state_colour(state: Any) -> None:
    """Map an AlertState onto the shared risk colour scale."""
    raise NotImplementedError("TODO: lookup against RISK_COLOURS in demo.components")


__all__ = ["render", "state_colour"]
