"""Timeline playback for the demo — stepping a recorded campaign forward in time.

Owns the "what does the system know at time t?" question, and owns it strictly:
at replay step ``t`` the UI may only see windows ``<= t``. That is not a
cosmetic detail. A demo that plots the whole risk curve at once, including the
future, is showing a forecast that has already seen the answer — and an
experienced judge will notice within seconds.

Responsibilities
----------------
* hold the timeline position and advance it on play
* expose only the windows visible at the current step
* expose the forecast made *at* the current step (the next K windows)
* report whether an alert is active, using the sustain rule
* jump to interesting moments: first alert, attack start, maximum risk

Streamlit reruns the whole script on every interaction, so the controller is
kept as plain serialisable state in ``st.session_state`` rather than as a
long-lived object with internal threads.

TODO
----
* [ ] Implement ``ReplayController`` over a predictions frame.
* [ ] Implement ``step`` / ``play`` / ``pause`` / ``seek`` / ``reset``.
* [ ] Implement ``visible_window`` — the causality guarantee. Test it.
* [ ] Implement ``current_forecast`` and ``alert_state``.
* [ ] Implement ``jump_to`` for the three interesting moments.
* [ ] Handle playback timing with ``st.rerun`` plus a timestamp, not ``sleep``.
* [ ] Add a "live mode" that tails a growing parquet, for the stretch goal of a
      real-time capture demo.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Final, Literal, Mapping, Sequence

import pandas as pd

#: Wall-clock seconds between frames at 1x speed.
FRAME_INTERVAL_SECONDS: Final[float] = 0.5

#: Selectable playback speeds.
SPEEDS: Final[tuple[float, ...]] = (0.5, 1.0, 2.0, 4.0, 8.0)


class AlertState(str, Enum):
    """What the dashboard should be showing right now."""

    QUIET = "quiet"            # risk below threshold
    ELEVATED = "elevated"      # above threshold but not yet sustained
    ALERTING = "alerting"      # sustained — a real alert
    ATTACK_ACTIVE = "attack"   # ground truth says the attack has begun


@dataclass
class ReplayController:
    """Steps a recorded campaign forward, exposing only what is known so far.

    Attributes:
        predictions: Per-window predictions for one campaign, time-ordered.
        entity_id: Host being followed.
        step: Current position, in windows from the campaign start.
        playing: Whether playback is advancing.
        speed: Playback multiplier.
        threshold: Alert threshold.
        sustain: Consecutive windows above threshold required to alert.
        stride_seconds: Window stride, for converting steps to wall-clock time.
    """

    predictions: pd.DataFrame
    entity_id: str
    step: int = 0
    playing: bool = False
    speed: float = 1.0
    threshold: float = 0.5
    sustain: int = 2
    stride_seconds: int = 10
    _last_frame_time: float = field(default=0.0, repr=False)

    # ---- navigation ---------------------------------------------------- #

    def step_forward(self, n: int = 1) -> "ReplayController":
        """Advance ``n`` windows, clamped at the end of the campaign."""
        raise NotImplementedError("TODO: increment step with clamping")

    def step_back(self, n: int = 1) -> "ReplayController":
        """Rewind ``n`` windows, clamped at zero."""
        raise NotImplementedError("TODO: decrement step with clamping")

    def seek(self, step: int) -> "ReplayController":
        """Jump to an absolute position (the scrubber)."""
        raise NotImplementedError("TODO: clamp and assign")

    def reset(self) -> "ReplayController":
        """Back to the start, paused."""
        raise NotImplementedError("TODO: step = 0, playing = False")

    def play(self) -> "ReplayController":
        """Start playback."""
        raise NotImplementedError("TODO: set playing and the frame timestamp")

    def pause(self) -> "ReplayController":
        """Stop playback."""
        raise NotImplementedError("TODO: clear playing")

    def tick(self, now: float) -> bool:
        """Advance if enough wall-clock time has passed. Returns whether it did.

        Timing lives here rather than in a ``sleep``, so the Streamlit rerun loop
        stays responsive to user input during playback.
        """
        raise NotImplementedError("TODO: compare now against _last_frame_time and speed")

    # ---- the causality guarantee ---------------------------------------- #

    def visible_window(self, lookback: int | None = None) -> pd.DataFrame:
        """Rows the UI is allowed to see at the current step.

        **Strictly** ``window_index <= step``. This is the method that keeps the
        demo honest; it deserves a test of its own.
        """
        raise NotImplementedError("TODO: filter to <= step, optionally trim to lookback")

    def current_forecast(self) -> pd.DataFrame:
        """The forecast made *at* the current step, for horizons ``K``.

        These rows are future-facing by construction — that is the whole point —
        but they were produced from history only.
        """
        raise NotImplementedError("TODO: select the horizon rows at window_index == step")

    def ground_truth_future(self) -> pd.DataFrame:
        """What actually happened next.

        For the post-hoc comparison panel only. Never feed this into anything
        the forecast display uses.
        """
        raise NotImplementedError("TODO: rows after step, clearly separated from the forecast")

    # ---- state ---------------------------------------------------------- #

    def alert_state(self) -> AlertState:
        """Current alert state under the sustain rule."""
        raise NotImplementedError("TODO: check the last `sustain` visible risks vs threshold")

    def current_time(self) -> pd.Timestamp:
        """Wall-clock timestamp of the current step."""
        raise NotImplementedError("TODO: look up window_start at the current step")

    def progress(self) -> float:
        """Playback position in ``[0, 1]``, for the progress bar."""
        raise NotImplementedError("TODO: step / (n_steps - 1), guarding a single-step campaign")

    def lead_time_so_far(self) -> float | None:
        """Seconds between the first sustained alert and the true attack start.

        ``None`` before both events exist. This is the number to put on screen in
        large type the moment it becomes available.
        """
        raise NotImplementedError("TODO: first sustained alert vs first true attack window")

    # ---- shortcuts ------------------------------------------------------- #

    def jump_to(self, moment: Literal["first_alert", "attack_start", "max_risk"]) -> "ReplayController":
        """Jump to an interesting moment — for answering questions live."""
        raise NotImplementedError("TODO: locate the moment, then seek to it")

    def interesting_moments(self) -> Mapping[str, int]:
        """Step indices of the notable moments, for timeline markers."""
        raise NotImplementedError("TODO: compute first_alert / attack_start / max_risk")


def build_controller(
    predictions: pd.DataFrame, campaign_id: str, entity_id: str, **kwargs: object
) -> ReplayController:
    """Construct a controller for one campaign-entity, sorted and re-indexed."""
    raise NotImplementedError("TODO: filter, sort by window_start, add window_index")


def list_campaigns(predictions: pd.DataFrame) -> Sequence[str]:
    """Campaigns available for replay, most interesting first.

    "Interesting" means containing a real attack with a clear pre-attack ramp —
    a campaign with no attack makes for a dull demo.
    """
    raise NotImplementedError("TODO: rank campaigns by attack presence and ramp length")


def list_entities(predictions: pd.DataFrame, campaign_id: str) -> Sequence[str]:
    """Hosts in a campaign, attacked ones first."""
    raise NotImplementedError("TODO: sort entities by peak risk / attack presence")


__all__ = [
    "FRAME_INTERVAL_SECONDS",
    "SPEEDS",
    "AlertState",
    "ReplayController",
    "build_controller",
    "list_campaigns",
    "list_entities",
]
