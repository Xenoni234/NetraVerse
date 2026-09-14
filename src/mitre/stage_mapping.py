"""Attack family -> MITRE ATT&CK stage, the label the stage head predicts.

Implements the labelling schema in CLAUDE.md section 8 (LOCKED). **Six classes**:
BENIGN plus the five ATT&CK stages named in the problem statement.

=== ==================== ========================== =================================
id  Stage                ATT&CK tactic              Example families
=== ==================== ========================== =================================
0   BENIGN               --                         normal traffic
1   RECON                TA0043 Reconnaissance      PortScan, Fuzzers, Analysis
2   INITIAL_ACCESS       TA0001 Initial Access      SSH/FTP-BruteForce, Web Attack, Heartbleed, Exploits
3   LATERAL_MOVEMENT     TA0008 Lateral Movement    Infiltration, Worms, internal spread
4   C2                   TA0011 Command & Control   Bot/Botnet, Backdoor, CTU-13 bot channels
5   EXFILTRATION         TA0010 Exfiltration        large outbound transfers, data theft
=== ==================== ========================== =================================

Judgement calls worth stating out loud
--------------------------------------
* **Brute force is INITIAL_ACCESS, not a separate execution stage.** It is an
  attempt to obtain credentials.
* **UNSW's "Backdoor" is C2.** We label what the network can see; the install is
  invisible to flow records, the control channel is not.
* **CIC "Infiltration" is LATERAL_MOVEMENT.** The problem statement's six-class
  scheme has no EXECUTION stage. Infiltration's network-observable phase is the
  post-drop internal scanning, which is lateral movement.
* **Coarse tactics only.** Technique-level labels (T1046, T1110, ...) are not
  recoverable from flow records; claiming them would be storytelling.

.. warning::
   **DoS and DDoS have no home in the six-class scheme** and they are a large
   fraction of attack windows in CIC-IDS2017/2018. They are neither
   reconnaissance, access, lateral movement, C2, nor exfiltration. Mapping them
   to EXFILTRATION would be simply wrong.

   Current handling: :data:`STAGE_MASKED` — these windows keep
   ``binary_label = 1`` and train the **risk head**, but are **masked out of the
   stage-head loss**. See CLAUDE.md section 10-E; this needs a team decision
   before training.

Unknown families map to :data:`UNKNOWN_STAGE` and are **logged, not silently
absorbed**. A new dataset with unmapped families must fail visibly.

TODO
----
* [ ] Complete ``FAMILY_TO_STAGE`` for every family across all seven datasets.
* [ ] Implement ``family_to_stage`` (scalar) and ``map_families`` (vectorised).
* [ ] Implement ``stage_loss_mask`` and wire it into ``losses.stage_loss``.
* [ ] Implement ``unmapped_families`` and call it during data loading.
* [ ] Cross-check against ``docs/attack_taxonomy.md`` — a test must enforce it.
* [ ] RESOLVE 10-E (DoS/DDoS) before any stage-head training run.
* [ ] DECIDE: label *pre-attack* windows BENIGN, or with the upcoming stage?
      The latter is what would let the model forecast *which* attack is coming.
"""

from __future__ import annotations

from typing import Final, Iterable, Mapping

import pandas as pd

# --------------------------------------------------------------------------- #
# Stage ids — LOCKED (6 classes: 5 ATT&CK stages + benign)
# --------------------------------------------------------------------------- #

BENIGN: Final[int] = 0
RECON: Final[int] = 1
INITIAL_ACCESS: Final[int] = 2
LATERAL_MOVEMENT: Final[int] = 3
C2: Final[int] = 4
EXFILTRATION: Final[int] = 5

N_STAGES: Final[int] = 6

#: Fallback for a family not in the table. Logged, never silently absorbed.
UNKNOWN_STAGE: Final[int] = BENIGN

#: Sentinel for windows that are genuine attacks but have no valid stage in the
#: six-class scheme (currently DoS/DDoS). Masked out of the stage-head loss;
#: still train the risk head. See CLAUDE.md section 10-E.
STAGE_MASKED: Final[int] = -1

STAGE_NAMES: Final[Mapping[int, str]] = {
    BENIGN: "BENIGN",
    RECON: "RECON",
    INITIAL_ACCESS: "INITIAL_ACCESS",
    LATERAL_MOVEMENT: "LATERAL_MOVEMENT",
    C2: "C2",
    EXFILTRATION: "EXFILTRATION",
}

#: ATT&CK tactic ids, for the report and dashboard tooltips.
STAGE_TACTICS: Final[Mapping[int, str]] = {
    BENIGN: "",
    RECON: "TA0043",
    INITIAL_ACCESS: "TA0001",
    LATERAL_MOVEMENT: "TA0008",
    C2: "TA0011",
    EXFILTRATION: "TA0010",
}

#: Short descriptions used by :mod:`src.explain.human_readable`.
STAGE_DESCRIPTIONS: Final[Mapping[int, str]] = {
    BENIGN: "No attack behaviour observed.",
    RECON: "Mapping the network: scanning hosts, ports or services.",
    INITIAL_ACCESS: "Trying to get in: credential brute force or exploiting an exposed service.",
    LATERAL_MOVEMENT: "Spreading from a compromised host to other internal systems.",
    C2: "Maintaining a control channel to a compromised host.",
    EXFILTRATION: "Moving data out of the network.",
}

# --------------------------------------------------------------------------- #
# Family -> stage. Keys are canonical families from labeller.normalise_attack_family.
# --------------------------------------------------------------------------- #

FAMILY_TO_STAGE: Final[Mapping[str, int]] = {
    # ---- benign ----
    "BENIGN": BENIGN,
    "Normal": BENIGN,
    # ---- reconnaissance ----
    "PortScan": RECON,
    "Reconnaissance": RECON,
    "Fuzzers": RECON,
    "Analysis": RECON,
    # ---- initial access ----
    "FTP-BruteForce": INITIAL_ACCESS,
    "SSH-BruteForce": INITIAL_ACCESS,
    "FTP-Patator": INITIAL_ACCESS,
    "SSH-Patator": INITIAL_ACCESS,
    "BruteForce": INITIAL_ACCESS,
    "WebAttack": INITIAL_ACCESS,
    "Heartbleed": INITIAL_ACCESS,
    "Exploits": INITIAL_ACCESS,
    "Shellcode": INITIAL_ACCESS,
    # ---- lateral movement ----
    "Infiltration": LATERAL_MOVEMENT,   # DEFAULT held-out family
    "Worms": LATERAL_MOVEMENT,
    # ---- command and control ----
    "Bot": C2,
    "Botnet": C2,
    "Backdoor": C2,
    # ---- exfiltration ----
    "Exfiltration": EXFILTRATION,
    # ---- NO VALID STAGE: masked from the stage loss, see CLAUDE.md 10-E ----
    "DoS": STAGE_MASKED,
    "DDoS": STAGE_MASKED,
    "Generic": STAGE_MASKED,
    # TODO: complete from docs/attack_taxonomy.md, incl. CIC-IoT-2023 families.
}


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #


def family_to_stage(family: str, *, strict: bool = False) -> int:
    """Map one canonical attack family to its ATT&CK stage id.

    Args:
        family: Canonical family string, from
            :func:`src.data.labeller.normalise_attack_family`.
        strict: Raise on an unmapped family instead of returning
            :data:`UNKNOWN_STAGE`. Use ``strict=True`` in tests and when
            onboarding a new dataset.

    Returns:
        A stage id in ``0..5``, or :data:`STAGE_MASKED` for an attack family with
        no valid stage.

    Raises:
        KeyError: when ``strict`` and the family is unmapped.
    """
    raise NotImplementedError("TODO: dict lookup with the strict/fallback branch")


def map_families(families: pd.Series, *, strict: bool = False) -> pd.Series:
    """Vectorised family -> stage mapping over a column.

    Logs the distinct unmapped families once, not per row.
    """
    raise NotImplementedError("TODO: Series.map with a logged unmapped set")


def stage_loss_mask(stages: pd.Series) -> pd.Series:
    """Boolean mask of windows that should contribute to the stage-head loss.

    False where the stage is :data:`STAGE_MASKED` (an attack with no valid stage
    in the six-class scheme). Those windows still train the risk head — they are
    real attacks — they just carry no usable stage target.
    """
    raise NotImplementedError("TODO: stages != STAGE_MASKED")


def unmapped_families(families: Iterable[str]) -> set[str]:
    """Return the families absent from :data:`FAMILY_TO_STAGE`.

    Call during data loading: a new dataset with unmapped families should surface
    immediately, not be silently absorbed into BENIGN.
    """
    raise NotImplementedError("TODO: set difference against the table keys")


def stage_name(stage: int) -> str:
    """Human-readable stage name."""
    raise NotImplementedError("TODO: STAGE_NAMES lookup with a clear error")


def stage_description(stage: int) -> str:
    """One-sentence description, used in alert narratives."""
    raise NotImplementedError("TODO: STAGE_DESCRIPTIONS lookup")


def stage_order() -> tuple[int, ...]:
    """Stages in kill-chain order, for plotting and confusion-matrix axes.

    Ordering the confusion matrix by kill-chain position makes the interesting
    errors visible: confusing adjacent stages is forgivable, confusing RECON with
    EXFILTRATION is not.
    """
    raise NotImplementedError("TODO: return the ids in kill-chain order")


def families_for_stage(stage: int) -> tuple[str, ...]:
    """Inverse lookup: every family mapped to ``stage``."""
    raise NotImplementedError("TODO: invert FAMILY_TO_STAGE")


__all__ = [
    "BENIGN",
    "RECON",
    "INITIAL_ACCESS",
    "LATERAL_MOVEMENT",
    "C2",
    "EXFILTRATION",
    "N_STAGES",
    "UNKNOWN_STAGE",
    "STAGE_MASKED",
    "STAGE_NAMES",
    "STAGE_TACTICS",
    "STAGE_DESCRIPTIONS",
    "FAMILY_TO_STAGE",
    "family_to_stage",
    "map_families",
    "stage_loss_mask",
    "unmapped_families",
    "stage_name",
    "stage_description",
    "stage_order",
    "families_for_stage",
]
