"""Turn SHAP attributions into sentences an analyst can act on.

A SHAP bar chart is for the modelling team. The person on shift at 3 a.m. needs
a sentence. This module owns that translation:

    Input:  RiskAttribution + the raw feature window
    Output: "Risk of attack on 192.168.10.50 in the next 20 s: 81 % (high
             confidence). Distinct destination ports rose from 3 to 47 over the
             last minute and 91 % of connection attempts are failing — this is
             the signature of a port scan. Closest known pattern: CIC-IDS2017
             Tuesday PortScan (similarity 0.84)."

Design rules
------------
1. **State the evidence, not the model.** "Fan-out rose from 3 to 47" beats
   "feature 11 had SHAP value 0.42". Every sentence cites an observed number.
2. **Direction and magnitude.** Say whether a signal rose or fell, and by how
   much relative to the host's own baseline.
3. **Cap at ~3 signals.** More than that is a data dump, not an explanation.
4. **Carry the uncertainty through.** A wide MC-dropout band becomes "low
   confidence" in the text; never state a hedged forecast as a flat fact.
5. **No invented causality.** SHAP gives association, not cause. Write "this
   pattern is consistent with", never "this host is being scanned".
6. **Templates, not an LLM.** Deterministic, auditable, offline, and it cannot
   hallucinate a hostname. The templates live in :data:`FEATURE_PHRASES`.

TODO
----
* [ ] Fill in ``FEATURE_PHRASES`` for all 32 features (rise and fall phrasing).
* [ ] Implement ``explain_alert`` — the single public entry point.
* [ ] Implement ``describe_feature_change`` with baseline-relative magnitudes.
* [ ] Implement ``confidence_phrase`` mapping band width to words.
* [ ] Implement ``stage_narrative`` — one clause per ATT&CK stage.
* [ ] Add a ``verbosity`` switch: one-line (SOC ticket) vs. paragraph (report).
* [ ] Have a non-modelling teammate read 20 generated alerts and flag any that
      are confusing or overclaim. That review is the real acceptance test.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Final, Literal, Mapping, Sequence

if TYPE_CHECKING:
    from src.explain.shap_wrapper import RiskAttribution
    from src.inference.trajectory_match import TrajectoryMatch
    from src.inference.uncertainty import UncertaintyBand

Verbosity = Literal["oneline", "standard", "detailed"]

#: Per-feature phrasing: how to describe a rise and a fall, in plain English.
#: Keys must match ``src.data.unified_schema.FEATURE_COLUMNS``.
FEATURE_PHRASES: Final[Mapping[str, Mapping[str, str]]] = {
    "n_distinct_dst_port": {
        "rise": "connections are spreading across many more destination ports",
        "fall": "connections are narrowing onto fewer destination ports",
        "unit": "ports",
    },
    "failed_conn_ratio": {
        "rise": "a growing share of connection attempts are failing",
        "fall": "connection attempts are succeeding more often",
        "unit": "%",
    },
    "bytes_per_sec": {
        "rise": "outbound throughput is climbing",
        "fall": "outbound throughput is dropping",
        "unit": "B/s",
    },
    # TODO: the remaining 29 features.
}

#: Band width -> confidence wording. Thresholds to be calibrated on val data.
CONFIDENCE_BANDS: Final[tuple[tuple[float, str], ...]] = (
    (0.15, "high confidence"),
    (0.35, "moderate confidence"),
    (1.01, "low confidence"),
)

#: One clause per ATT&CK stage, used to name what the forecast looks like.
STAGE_NARRATIVE: Final[Mapping[int, str]] = {
    0: "normal activity",
    1: "reconnaissance — the host appears to be mapping the network",
    2: "an attempt to gain initial access",
    3: "execution of code or delivery of an exploit",
    4: "command-and-control communication",
    5: "lateral movement toward other internal hosts",
    6: "impact — denial of service or data exfiltration",
}


@dataclass(frozen=True)
class AlertNarrative:
    """A rendered, human-readable alert.

    Attributes:
        headline: One line, suitable for a SOC ticket title.
        body: Two to four sentences of evidence.
        evidence: The individual evidence clauses, for UI bullet rendering.
        confidence: Confidence wording derived from the uncertainty band.
        stage_text: What kind of activity this resembles.
        match_text: Closest known trajectory, or a "no close match" note.
        risk: The risk probability being explained.
        horizon_seconds: How far ahead this forecast looks.
    """

    headline: str
    body: str
    evidence: tuple[str, ...]
    confidence: str
    stage_text: str
    match_text: str
    risk: float
    horizon_seconds: int

    def as_markdown(self) -> str:
        """Render for the Streamlit demo."""
        raise NotImplementedError("TODO: headline + bullets + match line")

    def as_plain_text(self) -> str:
        """Render for a log line or an exported ticket."""
        raise NotImplementedError("TODO: single-paragraph rendering")


def explain_alert(
    attribution: "RiskAttribution",
    *,
    entity_id: str,
    risk: float,
    horizon_seconds: int,
    current_features: Mapping[str, float],
    baseline_features: Mapping[str, float] | None = None,
    stage: int | None = None,
    band: "UncertaintyBand | None" = None,
    matches: "Sequence[TrajectoryMatch] | None" = None,
    top_k: int = 3,
    verbosity: Verbosity = "standard",
) -> AlertNarrative:
    """Compose the full narrative for one forecast.

    Args:
        attribution: SHAP attributions for this prediction.
        entity_id: Host or host-pair the alert is about.
        risk: Predicted attack probability.
        horizon_seconds: Seconds ahead this forecast looks.
        current_features: Observed feature values in the latest window.
        baseline_features: The host's own baseline, for relative phrasing.
        stage: Predicted ATT&CK stage id.
        band: Uncertainty band, which drives the confidence wording.
        matches: Trajectory matches, best first.
        top_k: Maximum evidence clauses.
        verbosity: Output length.

    Returns:
        A rendered :class:`AlertNarrative`.
    """
    raise NotImplementedError("TODO: top features -> clauses -> assemble narrative")


def describe_feature_change(
    feature: str,
    current_value: float,
    baseline_value: float | None,
    shap_value: float,
) -> str:
    """One evidence clause for one feature.

    Cites the observed numbers ("from 3 to 47") rather than the SHAP value, and
    uses the direction of ``shap_value`` to decide rise/fall phrasing.
    """
    raise NotImplementedError("TODO: FEATURE_PHRASES lookup + formatted magnitudes")


def confidence_phrase(band: "UncertaintyBand | None", index: int = 0) -> str:
    """Map an uncertainty band's width onto :data:`CONFIDENCE_BANDS` wording.

    Returns ``"confidence not estimated"`` when MC-dropout was disabled — better
    an explicit gap than an implied certainty.
    """
    raise NotImplementedError("TODO: width lookup against CONFIDENCE_BANDS")


def stage_narrative(stage: int | None, stage_confidence: float | None = None) -> str:
    """Describe the predicted ATT&CK stage, hedged when confidence is low."""
    raise NotImplementedError("TODO: STAGE_NARRATIVE lookup with hedging")


def match_narrative(matches: "Sequence[TrajectoryMatch] | None") -> str:
    """Describe the closest known attack trajectory, or say there is none.

    "No close match to known patterns" is a legitimate and useful output — it
    flags a possible novel attack. Never stretch a weak match to fill the slot.
    """
    raise NotImplementedError("TODO: top match with similarity, or the no-match sentence")


def format_magnitude(value: float, unit: str = "") -> str:
    """Human-friendly number formatting (1.2 MB/s, 47 ports, 91 %)."""
    raise NotImplementedError("TODO: SI-ish scaling and sensible rounding per unit")


__all__ = [
    "Verbosity",
    "FEATURE_PHRASES",
    "CONFIDENCE_BANDS",
    "STAGE_NARRATIVE",
    "AlertNarrative",
    "explain_alert",
    "describe_feature_change",
    "confidence_phrase",
    "stage_narrative",
    "match_narrative",
    "format_magnitude",
]
