"""SIH26153 — AI-based network attack forecasting via a sequential world model.

Package layout
--------------
``src.data``       Raw dataset loading, unified schema mapping, labelling, windowing.
``src.features``   Flow- and packet-level feature extraction, baselines, trajectory features.
``src.models``     Baselines plus the LSTM encoder-decoder world model and its heads.
``src.training``   Training loop, scheduled sampling, checkpointing.
``src.inference``  K-step forward simulation, MC-dropout uncertainty, trajectory matching.
``src.explain``    SHAP over the risk head and its translation into English.
``src.eval``       Evaluation harness, metrics, split policy, ablations.
``src.mitre``      Attack-family to MITRE ATT&CK stage mapping.

Conventions enforced across the package (see DESIGN.md):

* filesystem paths are ``pathlib.Path``, never ``str``
* tabular data is ``pandas`` + ``pyarrow`` parquet
* models are PyTorch >= 2.0 and must run on CPU when no GPU is present
* the feature schema, window parameters, labelling scheme and split policy are LOCKED
"""

from __future__ import annotations

__version__ = "0.1.0"
__ps_id__ = "SIH26153"

__all__ = ["__version__", "__ps_id__"]
