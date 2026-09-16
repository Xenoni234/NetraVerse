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
IMPACT: Final[int] = 6   # TA0040 — DoS/DDoS/availability attacks

N_STAGES: Final[int] = 7

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
    IMPACT: "IMPACT",
}

#: ATT&CK tactic ids, for the report and dashboard tooltips.
STAGE_TACTICS: Final[Mapping[int, str]] = {
    BENIGN: "",
    RECON: "TA0043",
    INITIAL_ACCESS: "TA0001",
    LATERAL_MOVEMENT: "TA0008",
    C2: "TA0011",
    EXFILTRATION: "TA0010",
    IMPACT: "TA0040",
}

#: Short descriptions used by :mod:`src.explain.human_readable`.
STAGE_DESCRIPTIONS: Final[Mapping[int, str]] = {
    BENIGN: "No attack behaviour observed.",
    RECON: "Mapping the network: scanning hosts, ports or services.",
    INITIAL_ACCESS: "Trying to get in: credential brute force or exploiting an exposed service.",
    LATERAL_MOVEMENT: "Spreading from a compromised host to other internal systems.",
    C2: "Maintaining a control channel to a compromised host.",
    EXFILTRATION: "Moving data out of the network.",
    IMPACT: "Disrupting availability: denial-of-service / flooding.",
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
    # ---- impact (TA0040): availability attacks (resolved CLAUDE.md 10-E) ----
    "DoS": IMPACT,
    "DDoS": IMPACT,
    "Generic": IMPACT,
    # TODO: complete from docs/attack_taxonomy.md, incl. CIC-IoT-2023 families.
}


# --------------------------------------------------------------------------- #
# CTU-13 raw label strings -> canonical family
# --------------------------------------------------------------------------- #


def ctu13_family(raw_label: str, *, strict: bool = False) -> str:
    """Map a CTU-13 binetflow ``Label`` (e.g. ``flow=From-Botnet-V45-TCP``) to a family.

    Substring rules: anything containing "Botnet" is the bot's malicious traffic
    (-> Bot -> C2). "Normal" and "Background" are treated as benign, which gives
    infected hosts a benign run-up before their C2 onset (the ramp we forecast).
    Background is unverified traffic; treating it as benign is a documented choice.
    """
    s = str(raw_label)
    if "Botnet" in s:
        return "Bot"
    if "Normal" in s or "Background" in s:
        return "BENIGN"
    if strict:
        raise KeyError(f"Unmapped CTU-13 label {raw_label!r}")
    return "BENIGN"


# --------------------------------------------------------------------------- #
# CIC-IDS2018 raw label strings -> canonical family
# --------------------------------------------------------------------------- #

#: Exact ``Label`` column values as they appear in the CSE-CIC-IDS2018 CSVs,
#: mapped to the canonical families in :data:`FAMILY_TO_STAGE`.
#:
#: These strings are matched **verbatim** (after whitespace strip). The dataset
#: is inconsistent about case and spacing, and one label is misspelled in the
#: source data — do not "fix" the keys, they must match the CSVs byte for byte:
#:
#: * ``"SSH-Bruteforce"`` — lowercase ``f``, unlike ``"FTP-BruteForce"``
#: * ``"Infilteration"`` — **misspelled in the dataset**. This is the default
#:   held-out family, so the misspelling matters: a silent miss here would put
#:   the held-out family back into the training set.
#: * ``"DDOS attack-HOIC"`` vs ``"DDoS attacks-LOIC-HTTP"`` — inconsistent caps
#:   and plurals across days.
CICIDS2018_LABEL_TO_FAMILY: Final[Mapping[str, str]] = {
    "Benign": "BENIGN",
    "BENIGN": "BENIGN",
    # Wednesday-14-02-2018
    "FTP-BruteForce": "FTP-BruteForce",
    "SSH-Bruteforce": "SSH-BruteForce",
    # Thursday-15-02-2018 / Friday-16-02-2018
    "DoS attacks-GoldenEye": "DoS",
    "DoS attacks-Slowloris": "DoS",
    "DoS attacks-Hulk": "DoS",
    "DoS attacks-SlowHTTPTest": "DoS",
    # Tuesday-20-02-2018 / Wednesday-21-02-2018
    "DDoS attacks-LOIC-HTTP": "DDoS",
    "DDOS attack-HOIC": "DDoS",
    "DDOS attack-LOIC-UDP": "DDoS",
    # Thursday-22-02-2018 / Friday-23-02-2018
    "Brute Force -Web": "WebAttack",
    "Brute Force -XSS": "WebAttack",
    "SQL Injection": "WebAttack",
    # Thursday-01-03-2018  (misspelled in the source data)
    "Infilteration": "Infiltration",
    # Friday-02-03-2018
    "Bot": "Bot",
}

#: The label string the CSVs use for benign traffic.
BENIGN_LABEL: Final[str] = "Benign"


# --------------------------------------------------------------------------- #
# CIC-IDS2017 raw label strings -> canonical family
# --------------------------------------------------------------------------- #

#: CIC-IDS2017 ``Label`` values -> canonical family. The web-attack labels contain
#: a UTF-8 en-dash (``Web Attack – Brute Force``); rather than depend on that
#: byte surviving every re-encoding, :func:`cicids2017_family` matches any label
#: starting with "Web Attack" as ``WebAttack``. The rest match verbatim.
CICIDS2017_LABEL_TO_FAMILY: Final[Mapping[str, str]] = {
    "BENIGN": "BENIGN",
    "Bot": "Bot",
    "DDoS": "DDoS",
    "DoS GoldenEye": "DoS",
    "DoS Hulk": "DoS",
    "DoS Slowhttptest": "DoS",
    "DoS slowloris": "DoS",
    "FTP-Patator": "FTP-Patator",
    "SSH-Patator": "SSH-Patator",
    "Heartbleed": "Heartbleed",
    "Infiltration": "Infiltration",   # default held-out family
    "PortScan": "PortScan",
    # "Web Attack – ..." handled by prefix in cicids2017_family()
}


def cicids2017_family(raw_label: str, *, strict: bool = False) -> str:
    """Map a raw CIC-IDS2017 ``Label`` value to a canonical family.

    Web-attack variants (which carry an en-dash in the source) collapse to
    ``WebAttack`` by prefix; everything else matches :data:`CICIDS2017_LABEL_TO_FAMILY`
    verbatim after whitespace strip.
    """
    key = str(raw_label).strip()
    if key.startswith("Web Attack"):
        return "WebAttack"
    if key in CICIDS2017_LABEL_TO_FAMILY:
        return CICIDS2017_LABEL_TO_FAMILY[key]
    if strict:
        raise KeyError(
            f"Unmapped CIC-IDS2017 label {raw_label!r}. Add it to "
            f"CICIDS2017_LABEL_TO_FAMILY; known: {sorted(CICIDS2017_LABEL_TO_FAMILY)}"
        )
    return "UNKNOWN"


def cicids2018_family(raw_label: str, *, strict: bool = False) -> str:
    """Map a raw CIC-IDS2018 ``Label`` value to a canonical family.

    Args:
        raw_label: Verbatim cell value from the ``Label`` column.
        strict: Raise on an unknown label instead of returning ``"UNKNOWN"``.

    Returns:
        Canonical family string, a key of :data:`FAMILY_TO_STAGE`.

    Raises:
        KeyError: when ``strict`` and the label is not in the table.
    """
    key = str(raw_label).strip()
    if key in CICIDS2018_LABEL_TO_FAMILY:
        return CICIDS2018_LABEL_TO_FAMILY[key]
    if strict:
        raise KeyError(
            f"Unmapped CIC-IDS2018 label {raw_label!r}. "
            f"Add it to CICIDS2018_LABEL_TO_FAMILY; known labels: "
            f"{sorted(CICIDS2018_LABEL_TO_FAMILY)}"
        )
    return "UNKNOWN"


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
    key = str(family).strip()
    if key in FAMILY_TO_STAGE:
        return FAMILY_TO_STAGE[key]
    if strict:
        raise KeyError(
            f"Unmapped attack family {family!r}. Add it to FAMILY_TO_STAGE "
            f"(and docs/attack_taxonomy.md)."
        )
    return UNKNOWN_STAGE


def map_families(families: pd.Series, *, strict: bool = False) -> pd.Series:
    """Vectorised family -> stage mapping over a column.

    Logs the distinct unmapped families once, not per row.
    """
    import logging

    cleaned = families.astype("string").str.strip()
    missing = set(cleaned.dropna().unique()) - set(FAMILY_TO_STAGE)
    if missing:
        if strict:
            raise KeyError(f"Unmapped attack families: {sorted(missing)}")
        logging.getLogger(__name__).warning(
            "Unmapped attack families mapped to BENIGN: %s", sorted(missing)
        )
    return cleaned.map(FAMILY_TO_STAGE).fillna(UNKNOWN_STAGE).astype("int64")


def stage_loss_mask(stages: pd.Series) -> pd.Series:
    """Boolean mask of windows that should contribute to the stage-head loss.

    False where the stage is :data:`STAGE_MASKED` (an attack with no valid stage
    in the six-class scheme). Those windows still train the risk head — they are
    real attacks — they just carry no usable stage target.
    """
    return stages != STAGE_MASKED


def unmapped_families(families: Iterable[str]) -> set[str]:
    """Return the families absent from :data:`FAMILY_TO_STAGE`.

    Call during data loading: a new dataset with unmapped families should surface
    immediately, not be silently absorbed into BENIGN.
    """
    return {str(f).strip() for f in families} - set(FAMILY_TO_STAGE)


def stage_name(stage: int) -> str:
    """Human-readable stage name."""
    if stage == STAGE_MASKED:
        return "NO_STAGE(masked)"
    try:
        return STAGE_NAMES[stage]
    except KeyError:
        raise KeyError(f"Unknown stage id {stage}; valid ids are {sorted(STAGE_NAMES)}") from None


def stage_description(stage: int) -> str:
    """One-sentence description, used in alert narratives."""
    if stage == STAGE_MASKED:
        return "Attack traffic with no stage in the six-class scheme (see CLAUDE.md 10-E)."
    return STAGE_DESCRIPTIONS.get(stage, "Unknown stage.")


def stage_order() -> tuple[int, ...]:
    """Stages in kill-chain order, for plotting and confusion-matrix axes.

    Ordering the confusion matrix by kill-chain position makes the interesting
    errors visible: confusing adjacent stages is forgivable, confusing RECON with
    EXFILTRATION is not.
    """
    return (BENIGN, RECON, INITIAL_ACCESS, LATERAL_MOVEMENT, C2, EXFILTRATION, IMPACT)


def families_for_stage(stage: int) -> tuple[str, ...]:
    """Inverse lookup: every family mapped to ``stage``."""
    return tuple(sorted(f for f, s in FAMILY_TO_STAGE.items() if s == stage))


__all__ = [
    "BENIGN_LABEL",
    "CICIDS2017_LABEL_TO_FAMILY",
    "cicids2017_family",
    "ctu13_family",
    "CICIDS2018_LABEL_TO_FAMILY",
    "cicids2018_family",
    "BENIGN",
    "RECON",
    "INITIAL_ACCESS",
    "LATERAL_MOVEMENT",
    "C2",
    "EXFILTRATION",
    "IMPACT",
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
