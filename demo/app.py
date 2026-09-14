"""Streamlit dashboard — the five minutes that decide how this project is judged.

Run with::

    streamlit run demo/app.py

What it has to show, in order
-----------------------------
1. A recorded attack campaign replaying on a timeline.
2. The forecast risk curve **rising before** the shaded true-attack region.
   This single visual is the entire pitch.
3. The simulated future — what the model thinks the next 40 s look like — with
   an MC-dropout confidence band.
4. A plain-English explanation of *why*, from :mod:`src.explain.human_readable`.
5. The closest matching known attack trajectory, with its similarity score.

Design constraints
------------------
**No live training, no live dataset loading.** Everything is precomputed into a
replay artefact by ``scripts/evaluate.py`` (predictions parquet + cached SHAP).
The demo reads files and draws. A dashboard that recomputes is a dashboard that
hangs in front of judges.

**CPU only.** Assume no GPU on the presenting machine.

**Degrade, never crash.** Missing SHAP cache -> hide the explanation panel and
carry on. Missing trajectory library -> hide the match panel. An exception
traceback on the projector costs more than a missing feature.

**Honest uncertainty.** Show the band, and let the risk curve be wrong where it
is wrong. A demo that only replays the model's best campaign invites exactly the
question we do not want to be asked live.

TODO
----
* [ ] Implement ``main`` with the sidebar / timeline / panel layout.
* [ ] Implement ``load_replay_data`` behind ``@st.cache_data``.
* [ ] Implement ``load_model_bundle`` behind ``@st.cache_resource``.
* [ ] Wire :mod:`demo.replay_controller` to the play/pause/scrub controls.
* [ ] Build the panels in ``demo/components/``.
* [ ] Add a "what am I looking at?" explainer box — judges see this for the
      first time with no context.
* [ ] Precompute a demo artefact bundle and check the load path on a cold start.
* [ ] Have someone outside the team drive it once, without narration.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

#: Default replay artefact, produced by scripts/evaluate.py.
DEFAULT_REPLAY_PATH = Path("reports/eval_full/predictions.parquet")

#: Default checkpoint used for live forward simulation.
DEFAULT_CHECKPOINT_PATH = Path("models/best.ckpt")

#: Campaign shown on first load. Pick one that is representative, not the best.
DEFAULT_CAMPAIGN = "cicids2017-tuesday"

PAGE_TITLE = "Network Attack Forecasting - SIH26153"
PAGE_ICON = "shield"


@dataclass
class DemoState:
    """Everything the dashboard needs for the current frame.

    Attributes:
        campaign_id: Campaign being replayed.
        entity_id: Host currently selected.
        current_step: Timeline position, in windows from the campaign start.
        playing: Whether playback is running.
        speed: Playback multiplier.
        threshold: Alert threshold, loaded from the checkpoint (adjustable so a
            judge can watch precision and recall trade off live).
        show_uncertainty: Toggle the MC-dropout band.
        show_explanation: Toggle the SHAP panel.
    """

    campaign_id: str = DEFAULT_CAMPAIGN
    entity_id: str = ""
    current_step: int = 0
    playing: bool = False
    speed: float = 1.0
    threshold: float = 0.5
    show_uncertainty: bool = True
    show_explanation: bool = True


def main() -> None:
    """Entry point. Lays out the page and drives the render loop.

    Layout::

        +------------------+--------------------------------------------+
        | sidebar          |  risk timeline (the money shot)            |
        |  campaign        +--------------------------------------------+
        |  host            |  simulated future | explanation | match    |
        |  threshold       +--------------------------------------------+
        |  toggles         |  feature detail table                      |
        +------------------+--------------------------------------------+
    """
    raise NotImplementedError("TODO: st.set_page_config, sidebar, panels, playback loop")


def load_replay_data(path: Path = DEFAULT_REPLAY_PATH) -> Mapping[str, Any]:
    """Load the precomputed replay artefact. Decorate with ``@st.cache_data``.

    Returns predictions, per-window features, cached SHAP attributions and the
    trajectory library. Missing optional pieces come back as ``None`` so the UI
    can hide the corresponding panel rather than failing.
    """
    raise NotImplementedError("TODO: read parquet + optional caches, tolerate absences")


def load_model_bundle(path: Path = DEFAULT_CHECKPOINT_PATH) -> Mapping[str, Any]:
    """Load model, scaler and threshold. Decorate with ``@st.cache_resource``.

    Always ``map_location="cpu"``. Returns ``None`` when absent — the demo then
    runs in pure replay mode, which is a perfectly good fallback on stage.
    """
    raise NotImplementedError("TODO: checkpointing.load_model with a graceful absence path")


def render_sidebar(state: DemoState, data: Mapping[str, Any]) -> DemoState:
    """Campaign / host pickers, threshold slider, playback controls, toggles."""
    raise NotImplementedError("TODO: sidebar widgets returning an updated state")


def render_header() -> None:
    """Title plus the one-paragraph "what am I looking at?" explainer.

    Judges arrive with no context. Two sentences on what is being forecast and
    what "lead time" means saves the first minute of every conversation.
    """
    raise NotImplementedError("TODO: title, subtitle, expandable explainer")


def render_footer(state: DemoState, data: Mapping[str, Any]) -> None:
    """Model provenance: checkpoint, git SHA, test metrics, schema version.

    Shows the numbers are from a real evaluation rather than the demo itself.
    """
    raise NotImplementedError("TODO: small provenance caption from metrics.json")


if __name__ == "__main__":
    main()
