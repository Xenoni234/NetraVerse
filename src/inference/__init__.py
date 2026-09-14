"""Inference layer: simulate the future, quantify doubt, recognise the pattern.

``forward_sim``       roll the world model K steps ahead, free-running
``uncertainty``       MC-dropout sampling -> confidence bands on the forecast
``trajectory_match``  compare a simulated future against known attack campaigns

This is where the world model pays off. A classifier gives a number; this layer
gives an analyst a *story*: "over the next 40 seconds this host's fan-out and
failed-connection ratio keep climbing, the risk band stays above 0.8 even at the
pessimistic end, and the shape matches the reconnaissance phase of the scan
campaign we saw on Tuesday."

Everything here runs under ``torch.no_grad()`` and must work on CPU.
"""

from __future__ import annotations

__all__ = ["forward_sim", "uncertainty", "trajectory_match"]
