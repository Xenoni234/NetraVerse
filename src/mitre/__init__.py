"""MITRE ATT&CK integration.

``stage_mapping``  attack family -> coarse kill-chain stage (the stage-head label)

Why map to ATT&CK at all. Three reasons, in order of importance:

1. **It is the label the stage head predicts.** Raw dataset families are
   inconsistent across sources — "PortScan" (CIC), "Reconnaissance" (UNSW) and a
   CTU scan scenario are the same behaviour under three names. Mapping onto a
   shared stage vocabulary is what makes multi-dataset training coherent.
2. **It makes the forecast actionable.** "RECON predicted in 40 s" tells an
   analyst what to do; "attack family 7" does not.
3. **It is the vocabulary the field already uses.** Judges, SOC teams and every
   commercial tool speak ATT&CK.

We deliberately use **coarse tactics, not techniques**. Technique-level labels
(T1046, T1110, ...) are not reliably recoverable from flow records, and claiming
them would be overfitting the story to the data.
"""

from __future__ import annotations

__all__ = ["stage_mapping"]
