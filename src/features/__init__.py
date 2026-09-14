"""Feature layer: turn a window's worth of traffic into the LOCKED 32 features.

``extractor``        flow-level aggregates (volume, rate, fan-out, protocol, flags)
``packet_features``  optional packet-level enrichment from PCAP via TShark
``baselines``        per-host and peer-group normality, for deviation z-scores
``trajectory``       first derivatives — how fast the state is changing

Ordering matters: ``extractor`` runs first, then ``packet_features`` merges in,
then ``baselines`` and ``trajectory`` append their derived columns. The final
column set must equal ``src.data.unified_schema.FEATURE_COLUMNS`` exactly.

Every feature is causal: computing the value for window ``t`` may only read data
with timestamp ``< window_end(t)``. Baselines in particular must use a trailing
window, never a centred one.
"""

from __future__ import annotations

__all__ = ["extractor", "packet_features", "baselines", "trajectory"]
