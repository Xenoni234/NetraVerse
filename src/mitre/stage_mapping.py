"""Attack family -> MITRE ATT&CK stage, the label the stage head predicts.

Implements DESIGN.md section 4.2 (LOCKED). Seven classes: BENIGN plus six coarse
kill-chain stages.

=== ==================== ======================= =================================
id  Stage                ATT&CK tactic           Example families
=== ==================== ======================= =================================
0   BENIGN               --                      normal traffic
1   RECON                TA0043 Reconnaissance   PortScan, Fuzzers, Analysis
2   INITIAL_ACCESS       TA0001 Initial Access   Web Attack, Brute Force, Heartbleed
3   EXECUTION            TA0002 Execution        Infiltration, Exploits, Shellcode
4   C2                   TA0011 Command & Control Botnet, CTU-13 bot channels
5   LATERAL_MOVEMENT     TA0008 Lateral Movement internal scanning, spread
6   IMPACT               TA0040 Impact           DoS, DDoS, exfiltration
=== ==================== ======================= =================================

Judgement calls worth stating out loud
--------------------------------------
* **Brute force is INITIAL_ACCESS, not EXECUTION.** It is an attempt to obtain
  credentials, which is access, not code execution.
* **UNSW's "Backdoor" is C2**, not EXECUTION — the observable network behaviour
  is a control channel, and we label what the network can actually see.
* **LATERAL_MOVEMENT is under-represented** in all four public datasets, which
  is why the success criterion is macro-F1 over 7 classes rather than accuracy.
  Expect this class to be the weakest and say so in the report.
* **Coarse tactics only.** Technique-level labels are not recoverable from flow
  records; claiming them would be storytelling.

Unknown families map to :data:`UNKNOWN_STAGE` and are **logged, not silently
absorbed**. A new dataset with unmapped families must fail visibly.

TODO
----
* [ ] Complete ``FAMILY_TO_STAGE`` for every family in all four datasets.
* [ ] Implement ``family_to_stage`` (scalar) and ``map_families`` (vectorised).
* [ ] Implement ``unmapped_families`` and call it during data loading.
* [ ] Cross-check the table against ``docs/attack_taxonomy.md`` — the two must
      agree, and a test should enforce it.
* [ ] Decide how to label the *pre-attack* windows of a campaign: BENIGN, or the
      upcoming stage? Labelling them with the upcoming stage is what would let
      the model forecast *which* attack is coming, not just that one is. This is
      an open design question — resolve it in DESIGN.md before training.
"""

from __future__ import annotations

from typing import Final, Iterable, Mapping

import pandas as pd

# --------------------------------------------------------------------------- #
# Stage ids — LOCKED
# --------------------------------------------------------------------------- #

BENIGN: Final[int] = 0
RECON: Final[int] = 1
INITIAL_ACCESS: Final[int] = 2
EXECUTION: Final[int] = 3
C2: Final[int] = 4
LATERAL_MOVEMENT: Final[int] = 5
IMPACT: Final[int] = 6

N_STAGES: Final[int] = 7

#: Fallback for a family not in the table. Logged, never silently absorbed.
UNKNOWN_STAGE: Final[int] = BENIGN

STAGE_NAMES: Final[Mapping[int, str]] = {
    BENIGN: "BENIGN",
    RECON: "RECON",
    INITIAL_ACCESS: "INITIAL_ACCESS",
    EXECUTION: "EXECUTION",
    C2: "C2",
    LATERAL_MOVEMENT: "LATERAL_MOVEMENT",
    IMPACT: "IMPACT",
}

#: ATT&CK tactic ids, for the report and the dashboard tooltips.
STAGE_TACTICS: Final[Mapping[int, str]] = {
    BENIGN: "",
    RECON: "TA0043",
    INITIAL_ACCESS: "TA0001",
    EXECUTION: "TA0002",
    C2: "TA0011",
    LATERAL_MOVEMENT: "TA0008",
    IMPACT: "TA0040",
}

#: Short descriptions used by :mod:`src.explain.human_readable`.
STAGE_DESCRIPTIONS: Final[Mapping[int, str]] = {
    BENIGN: "No attack behaviour observed.",
    RECON: "Mapping the network: scanning hosts, ports or services.",
    INITIAL_ACCESS: "Trying to get in: credential brute force or exploiting an exposed service.",
    EXECUTION: "Running code on a target or delivering an exploit payload.",
    C2: "Maintaining a control channel to a compromised host.",
    LATERAL_MOVEMENT: "Spreading from the compromised host to other internal systems.",
    IMPACT: "Causing damage: denial of service or data exfiltration.",
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
    "FTP-Patator": INITIAL_ACCESS,
    "SSH-Patator": INITIAL_ACCESS,
    "BruteForce": INITIAL_ACCESS,
    "WebAttack": INITIAL_ACCESS,
    "Heartbleed": INITIAL_ACCESS,
    # ---- execution ----
    "Infiltration": EXECUTION,   # the DEFAULT held-out family (DESIGN.md section 5)
    "Exploits": EXECUTION,
    "Shellcode": EXECUTION,
    "Worms": EXECUTION,
    # ---- command and control ----
    "Bot": C2,
    "Botnet": C2,
    "Backdoor": C2,              # network-observable behaviour is a control channel
    # ---- lateral movement ----
    # TODO: under-represented in the public datasets. CTU-13 internal spread
    # scenarios are the best candidate source — confirm and add them here.
    # ---- impact ----
    "DoS": IMPACT,
    "DDoS": IMPACT,
    "Generic": IMPACT,
    "Exfiltration": IMPACT,
    # TODO: complete from docs/attack_taxonomy.md; a test must keep the two in sync.
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

    Raises:
        KeyError: when ``strict`` and the family is unmapped.
    """
    raise NotImplementedError("TODO: dict lookup with the strict/fallback branch")


def map_families(families: pd.Series, *, strict: bool = False) -> pd.Series:
    """Vectorised family -> stage mapping over a column.

    Logs the distinct unmapped families once, rather than per row.
    """
    raise NotImplementedError("TODO: Series.map with a logged unmapped set")


def unmapped_families(families: Iterable[str]) -> set[str]:
    """Return the families absent from :data:`FAMILY_TO_STAGE`.

    Call this during data loading: a new dataset with unmapped families should
    surface immediately, not be silently absorbed into BENIGN.
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
    IMPACT is not.
    """
    raise NotImplementedError("TODO: return the ids in kill-chain order")


def families_for_stage(stage: int) -> tuple[str, ...]:
    """Inverse lookup: every family mapped to ``stage``.

    Used by the ablation report and by ``docs/attack_taxonomy.md`` generation.
    """
    raise NotImplementedError("TODO: invert FAMILY_TO_STAGE")


__all__ = [
    "BENIGN",
    "RECON",
    "INITIAL_ACCESS",
    "EXECUTION",
    "C2",
    "LATERAL_MOVEMENT",
    "IMPACT",
    "N_STAGES",
    "UNKNOWN_STAGE",
    "STAGE_NAMES",
    "STAGE_TACTICS",
    "STAGE_DESCRIPTIONS",
    "FAMILY_TO_STAGE",
    "family_to_stage",
    "map_families",
    "unmapped_families",
    "stage_name",
    "stage_description",
    "stage_order",
    "families_for_stage",
]
