"""Data layer: raw files in, model-ready windowed tensors out.

The pipeline is strictly ordered, and every stage is a pure function of the
previous one:

``paths``           where the bytes live on disk
``loaders``         per-dataset readers -> raw ``pandas.DataFrame``
``unified_schema``  per-dataset column mapping -> the LOCKED unified flow schema
``labeller``        adds ``is_attack`` / ``attack_stage`` / ``dist_to_attack``
``windowing``       time-ordered aggregation into ``(N, L, F)`` sequence samples

Nothing in this package may look at a future timestamp when computing a value
for window ``t``. That is the one invariant the whole project rests on.
"""

from __future__ import annotations

__all__ = ["paths", "loaders", "unified_schema", "labeller", "windowing"]
