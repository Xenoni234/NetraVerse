# Attack Taxonomy — dataset families to MITRE ATT&CK stages

The reference table behind `src/mitre/stage_mapping.py` and the `attack_stage`
label defined in [DESIGN.md](../DESIGN.md) section 4.2.

> **This file and `FAMILY_TO_STAGE` must agree.** A test should enforce it. If
> you add a family here, add it there in the same commit.

---

## 1. Why map at all

The four source datasets name the same behaviour three different ways. CIC calls
a scan `PortScan`; UNSW calls it `Reconnaissance`; CTU-13 encodes it in a
free-text flow label. Training one model across all of them requires a shared
vocabulary, and MITRE ATT&CK is the vocabulary the field already uses — so the
stage label does double duty: it makes multi-dataset training coherent, and it
makes the forecast something an analyst can act on without translation.

## 2. Granularity: tactics, not techniques

We map to **coarse tactics** (7 classes), not techniques (T1046, T1110, ...).

Flow records show volume, timing, fan-out and flags. That is enough to tell
reconnaissance from impact. It is *not* enough to distinguish T1046 (Network
Service Discovery) from T1595.002 (Vulnerability Scanning) — those differ in
payload and intent, not in the network statistics we observe. Claiming technique
labels would be fitting the story to the data rather than the other way round.

## 3. The seven stages

| id | Stage | ATT&CK tactic | What it looks like on the wire |
|---|---|---|---|
| 0 | `BENIGN` | — | Normal traffic |
| 1 | `RECON` | TA0043 Reconnaissance | High fan-out to distinct ports/IPs, high failed-connection ratio, low bytes per flow |
| 2 | `INITIAL_ACCESS` | TA0001 Initial Access | Repeated connections to one service, many auth failures, or a single anomalous request to a vulnerable service |
| 3 | `EXECUTION` | TA0002 Execution | Payload delivery: an unusual transfer to a host that does not normally receive one |
| 4 | `C2` | TA0011 Command & Control | Low-volume, highly periodic beaconing to an external host |
| 5 | `LATERAL_MOVEMENT` | TA0008 Lateral Movement | An internal host suddenly scanning or connecting to internal peers it never talks to |
| 6 | `IMPACT` | TA0040 Impact | Very high rate (DoS/DDoS) or a large sustained outbound transfer (exfiltration) |

---

## 4. Family mapping per dataset

### 4.1 CIC-IDS2017

| Source label | Canonical family | Stage | Note |
|---|---|---|---|
| `BENIGN` | `BENIGN` | 0 | |
| `PortScan` | `PortScan` | 1 RECON | |
| `FTP-Patator` | `FTP-Patator` | 2 INITIAL_ACCESS | Credential brute force |
| `SSH-Patator` | `SSH-Patator` | 2 INITIAL_ACCESS | Credential brute force |
| `Web Attack - Brute Force` | `WebAttack` | 2 INITIAL_ACCESS | |
| `Web Attack - XSS` | `WebAttack` | 2 INITIAL_ACCESS | |
| `Web Attack - Sql Injection` | `WebAttack` | 2 INITIAL_ACCESS | Very few samples |
| `Heartbleed` | `Heartbleed` | 2 INITIAL_ACCESS | Very few samples |
| `Infiltration` | `Infiltration` | 3 EXECUTION | **Default held-out family** |
| `Bot` | `Bot` | 4 C2 | |
| `DoS Hulk` / `DoS GoldenEye` / `DoS slowloris` / `DoS Slowhttptest` | `DoS` | 6 IMPACT | Collapsed into one family |
| `DDoS` | `DDoS` | 6 IMPACT | |

### 4.2 CSE-CIC-IDS2018

Same family vocabulary as 2017, with `DDOS attack-HOIC`, `DDOS attack-LOIC-UDP`
and `Brute Force -Web` as extra variants. They collapse onto the same canonical
families.

> TODO: enumerate the full 2018 label list once the CSVs are downloaded — some
> labels differ in spacing and capitalisation from 2017 and must be normalised
> by `labeller.normalise_attack_family`, not by hand.

### 4.3 UNSW-NB15

| Source `attack_cat` | Canonical family | Stage | Note |
|---|---|---|---|
| (empty) / `Normal` | `BENIGN` | 0 | Blank means benign in this dataset |
| `Reconnaissance` | `Reconnaissance` | 1 RECON | |
| `Fuzzers` | `Fuzzers` | 1 RECON | Probing for input-handling faults |
| `Analysis` | `Analysis` | 1 RECON | Port scan / spam / HTML-file probing |
| `Exploits` | `Exploits` | 3 EXECUTION | |
| `Shellcode` | `Shellcode` | 3 EXECUTION | |
| `Worms` | `Worms` | 3 EXECUTION | Self-propagating; arguably also stage 5 — see below |
| `Backdoor` | `Backdoor` | 4 C2 | Network-observable behaviour is a control channel |
| `Generic` | `Generic` | 6 IMPACT | Cipher-block attacks; the weakest mapping in the table |
| `DoS` | `DoS` | 6 IMPACT | |

### 4.4 CTU-13

Labels are free text (`flow=From-Botnet-V45-TCP-Attempt`), matched by substring:

| Substring | Canonical family | Stage |
|---|---|---|
| `Background` | dropped | — |
| `Normal` | `BENIGN` | 0 |
| `From-Botnet` + `CC` | `Botnet` | 4 C2 |
| `From-Botnet` + `SPAM` | `Botnet` | 6 IMPACT |
| `From-Botnet` + `DDoS` | `DDoS` | 6 IMPACT |
| `From-Botnet` + `PortScan` | `PortScan` | 1 RECON |

> TODO: CTU-13 `Background` traffic is unlabelled rather than verified benign.
> Decide whether to drop it (safe, loses volume) or treat it as benign (more
> data, risks label noise). Record the decision in DESIGN.md.

---

## 5. Judgement calls, stated openly

**Brute force is INITIAL_ACCESS, not EXECUTION.** It is an attempt to obtain
credentials. Nothing is executed.

**Backdoor is C2, not EXECUTION.** We label what the network can see. The
installation is invisible to flow records; the control channel is not.

**Worms could be EXECUTION or LATERAL_MOVEMENT.** Currently EXECUTION. The
self-propagation that would justify stage 5 is not cleanly separable in
UNSW-NB15's flow labels. Revisit if the confusion matrix shows the model
consistently predicting stage 5 for worm traffic — that would be the model
telling us the mapping is wrong.

**`Generic` -> IMPACT is weak.** UNSW's `Generic` covers cryptographic attacks
against block ciphers, which do not map cleanly to any network-observable stage.
IMPACT is the least-bad option. Flag it in the report rather than hiding it.

**LATERAL_MOVEMENT is under-represented.** None of the four public datasets
labels internal spread as a distinct class. Expect this to be the weakest stage,
and expect the confusion matrix to show it. This is why the success criterion is
macro-F1 over 7 classes, not accuracy — accuracy would let the model ignore
stage 5 entirely and still look excellent.

---

## 6. Open questions

- [ ] How should *pre-attack* windows be labelled — `BENIGN`, or the stage that
      is coming? Labelling them with the upcoming stage is what would let the
      model forecast *which* attack is coming rather than only that one is.
      Resolve before training. (Also tracked in DESIGN.md section 8.)
- [ ] Should the held-out family (`Infiltration`) also be held out from
      pre-attack labels? Leaving it in leaks a hint about its timing.
- [ ] Is a 7-class stage head too fine given how sparse stages 3 and 5 are?
      A 4-class variant (BENIGN / RECON / ACCESS+EXEC / C2+IMPACT) is the
      fallback if macro-F1 stays near chance.
