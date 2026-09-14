"""Explainability: why does the model think an attack is coming?

``shap_wrapper``    SHAP attributions over the risk head
``human_readable``  attributions -> sentences an analyst can act on

An unexplained forecast is an unusable forecast. We are asking a human to act
before anything visibly bad has happened; "the LSTM said 0.81" is not a reason
they can defend to their manager. "Fan-out to distinct destination ports rose
from 3 to 47 over the last 60 seconds, and failed connections are at 91 % — this
matches reconnaissance" is.

Explanations target the **risk head** specifically, because that is the output a
human acts on. Explaining the state head would describe the model's internal
dynamics, which is interesting for debugging and useless in an alert.
"""

from __future__ import annotations

__all__ = ["shap_wrapper", "human_readable"]
