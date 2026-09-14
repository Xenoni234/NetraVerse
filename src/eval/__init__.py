"""Evaluation layer: the numbers that decide whether this project worked.

``harness``    the full evaluation loop, producing the report
``metrics``    F1, PR-AUC, lead-time distribution, FPR, stage macro-F1
``splits``     the LOCKED chronological / campaign-aware split policy
``ablations``  encoder-only, flow-only, shuffled-time and friends

Rules of engagement
-------------------
* The **test split is touched once**. While iterating, evaluate on val.
* Every headline number is reported **per horizon** ``k in {1, 2, 4}``, because
  a single averaged figure hides the thing we actually care about: how far ahead
  the forecast still holds.
* Every results table carries the baselines from DESIGN.md section 6.5 in
  adjacent columns. A number with nothing to compare it to is not a result.
* Lead time is the headline metric for the pitch. F1 says we are right; lead
  time says we were early enough to matter.
"""

from __future__ import annotations

__all__ = ["harness", "metrics", "splits", "ablations"]
