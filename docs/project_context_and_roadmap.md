# SIH26153 Project Context and Roadmap

Last consolidated: 2026-09-18

This document records the decisions, findings and roadmap agreed during project analysis. Update it whenever the problem definition, datasets, model, evaluation claims or deployment scope changes.

## 1. Problem objective

The project must be presented as a predictive cyber-defence prototype, not only as an intrusion classifier.

The intended system should:

- learn normal and changing network behaviour;
- represent the current network state as features and eventually as a temporal graph;
- learn state-transition dynamics;
- forecast attack onset and progression over future time horizons;
- map forecasts to ATT&CK tactics/techniques where the telemetry supports it;
- explain the evidence, uncertainty and expected progression;
- provide decision support for defenders;
- work offline and be applicable to enterprise/Critical Information Infrastructure scenarios.

The scientifically correct target is: given a non-attack current window, estimate whether an attack will begin within the next 30, 60 or 120 seconds. Detecting an attack already in progress must not be counted as advance warning.

## 2. Current repository capability

The repository currently contains:

- an LSTM encoder-decoder with autoregressive future rollout;
- multi-horizon risk and stage heads;
- temporal attention and MC-dropout uncertainty;
- per-host 30-second windows with ten-window history;
- CSV, PCAP and PCAPNG upload paths;
- SHAP and attention-based explanations;
- ATT&CK-style stage mapping;
- Streamlit and FastAPI offline interfaces;
- persistence and logistic-regression benchmark artifacts;
- chronological split and held-out-family design.

The current system is a credible prototype architecture. It is not yet production-grade or sufficiently validated as a high-quality attack forecaster.

## 3. Current limitations

### Model quality

The recorded benchmark is weak:

| Horizon | F1 | PR-AUC |
|---|---:|---:|
| +30 seconds | 0.087 | 0.077 |
| +60 seconds | 0.136 | 0.071 |
| +120 seconds | 0.128 | 0.079 |

The model beats the stored baselines, but the baselines are also weak. These numbers do not meet the original target values and must not be presented as production-quality performance.

### Upload ground truth

Uploaded/live data is deliberately treated as unlabeled. The upload path injects placeholder benign labels, so an upload cannot prove that an attack occurred, measure genuine warning lead time, or show a verified attack interval. It produces a forecast only.

### Live monitoring status

The repository already contains a prototype live-monitoring path:

```text
owned server interface
  -> tcpdump/CICFlowMeter capture
  -> 30-second flow files
  -> live_windows()
  -> rolling per-host forecast
  -> risk/stage predictions
  -> parquet/stdout output
```

Relevant components are `agent/capture.sh`, `scripts/live_forecast.py`, `scripts/live_sync.sh`, `src/inference/live.py` and `docs/live_test_runbook.md`. The live loop requires approximately five minutes of consecutive history before normal forecasts become available and intentionally has roughly one 30-second window of capture latency.

The live server test demonstrated feasibility on an owned Ubuntu/Tailscale server, but the observed scan alert was principally detection at or near onset rather than reliable advance warning. This is evidence that the pipeline works, not evidence of production-grade predictive performance.

For production live monitoring, the forecaster should run close to the capture source, with a durable event queue, alert deduplication/cooldown, server-specific calibration, health monitoring, clock normalization, persistent storage and a controlled SIEM/notification integration. The current CLI/parquet loop is the prototype starting point.

### Live failure diagnosis checklist

When live testing fails, diagnose the stages in this order:

1. **Capture:** the capture process needs Linux, root permissions and the correct interface. `tailscale0` sees direct Tailscale-IP traffic; traffic sent through a Cloudflare/public proxy may expose only proxy addresses. `eth0` or the actual LAN interface is required for other traffic.
2. **Flow conversion:** CICFlowMeter must be installed and able to write completed CSV flow records. The recorded test found a Python `cicflowmeter` 0.5.0 signature-order issue and an offline `tcpdump/libpcap` dependency issue. The canonical Java CICFlowMeter path is preferred for feature parity.
3. **Data arrival:** a quiet 30-second interval may produce no file or no row for a host. The strict forecaster rejects gaps; a host needs ten consecutive 30-second windows, approximately five minutes, before ordinary forecasting is available.
4. **Feature compatibility:** the live CSV must contain a supported CICFlowMeter header variant, a timestamp and source IP. Missing fields are filled with zero, which can make predictions unreliable even when ingestion technically succeeds.
5. **Clock:** live CICFlowMeter timestamps may be server-local while the pipeline assumes UTC. This can shift displayed times and corrupt lead-time interpretation.
6. **Model/threshold:** `models/wm_server/best.ckpt` should be trained or calibrated for the target server's benign traffic. Falling back to `wm_final` can produce domain-shifted scores and no alerts. A threshold calibrated on one server should not be assumed valid on another.
7. **Alert semantics:** the live loop requires sustained risk for multiple windows. An abrupt attack may alert at onset, while a short event may never satisfy the sustain rule. No alert does not prove that capture or inference failed.

The first diagnostic evidence required from a failed run is: capture command output, number and names of generated CSVs, one CSV header plus a few rows, the number of windows/hosts produced, checkpoint path, threshold, interface, and the exact `live_forecast.py` output.

### Packet-level coverage

The upload path uses CICFlowMeter-derived flow and packet-summary fields. The dedicated raw-PCAP packet-feature module still has incomplete functionality. Full TTL, fragmentation, retransmission and packet-signature coverage is not yet demonstrated.

### Representation

The main model is per-host. This limits lateral-movement forecasting because lateral movement is a relationship between hosts, users, services and destinations. A temporal graph representation is the main planned architecture upgrade.

### Evaluation and documentation

Some evaluation/training/feature modules still contain TODO or `NotImplementedError` sections, while benchmark artifacts already exist. The benchmark must eventually be reproducible from a single command. README, DESIGN, CLAUDE and implementation details also need reconciliation around feature count, stride and stage count.

## 4. 10 am–3 pm upload interpretation

For a capture covering 10:00–15:00:

- observed windows exist only inside that interval;
- forecasts are available once a 5-minute history exists;
- the final forecast can cover approximately the next 30, 60 or 120 seconds after the last observed window;
- the system cannot confirm what actually happens after 15:00;
- unlabeled uploads cannot confirm whether an attack happened inside 10:00–15:00 either.

Therefore, post-15:00 output is a model forecast, not an observed attack result. Measured lead time requires later traffic plus verified ground truth.

## 5. Dataset strategy

Do not merge every dataset immediately. Use staged acquisition.

### Immediate datasets

1. **CIC-IDS2017** — primary development dataset for timestamps, PCAP/flow alignment, feature validation and onset labels.
2. **CTU-13** — C2 and botnet progression.
3. **UNSW-NB15** — initially held out for cross-dataset generalization.

### Later datasets

- CSE-CIC-IDS2018 for additional attack diversity and scale;
- TON_IoT for network plus host/IoT/IIoT telemetry;
- LANL Cyber Security Dataset for authentication, process, DNS, network and red-team graph modelling;
- CIC Modbus 2023 if Critical Information Infrastructure/substation applicability is claimed;
- CIC IoT 2023 or BoT-IoT only if IoT is an intended deployment scope.

### Data audit update — 2026-09-18

The newly added local data was audited in [reports/data_audit_phase1_2026-09-18.md](../reports/data_audit_phase1_2026-09-18.md). CIC-IoT-2023 currently contains 309 aggregate per-attack CSV files and 63 merged CSVs but no local PCAP/PCAPNG files; the observed schema has no timestamp or source/destination identity, so it cannot be safely used for the current per-host temporal onset target. UNSW-NB15 contains four headerless raw CSVs with source/destination fields, `Stime`/`Ltime`, attack category and labels, but its loader and unified schema mapping are still incomplete. CTU-13 original `.binetflow` files are present under the extracted archive and remain the preferred temporal source.

Decision: implement UNSW-NB15 temporal loading next; keep CIC-IoT-2023 outside the current world-model cache until an IoT-specific temporal/entity strategy is defined.

Implementation update: the UNSW-NB15 raw adapter is now implemented in
`src/data/loaders.py`. It reads only the four timestamped raw files, derives the
canonical flow features, preserves source/destination identity and campaign
ordering, and supports the archive's `NUSW` feature-dictionary filename. The
unified schema and label normalizer now support `unsw_nb15` and its attack
categories.

Validation completed: a 2,000-row raw UNSW sample passed loader -> unified
schema -> label generation, with timestamps ordered and blank `attack_cat`
values correctly treated as benign. Full-dataset training remains gated on
Phase 4 labels and Phase 5 evaluation.

Phase 4 update: window construction now emits `attack_onset` and
`onset_left_censored`, and sequence metadata records `next_attack_distance`.
The onset target excludes active-origin windows and requires complete future
windows; missing future data is not relabelled as benign. The full UNSW audit
found 46,384 source-host windows, 6,375 attack windows, but only 6 observable
onsets and 7 left-censored transitions. UNSW is therefore retained primarily
as a held-out generalization benchmark. See
`reports/phase4_onset_label_audit_2026-09-18.md`.

Phase 4 update: window construction now emits `attack_onset` and
`onset_left_censored`, and sequence metadata records `next_attack_distance`.
The onset target excludes active-origin windows and requires complete future
windows; missing future data is not relabelled as benign. See
`reports/phase4_onset_label_audit_2026-09-18.md` for validation and the
remaining full-capture audit gate.

### CTU-13 decision

The extracted `CTU-13-Dataset.tar.bz` is sufficient. Do not download individual Botnet-42 through Botnet-54 captures at this stage. The repository loader expects the original labelled `.binetflow` files and supports `scenario="all"`. Use all 13 numbered scenarios if present. Individual PCAPs are only needed later if raw packet-level CTU feature extraction is implemented.

## 6. Agreed ten-phase execution roadmap

### Phase 1 — Freeze the scientific definition

Define the entity, 30-second window, ten-window history, 30/60/120-second horizons, attack-onset definition, stage labels, warning-success criteria and acceptable false-alert rate.

### Phase 2 — Acquire and audit the initial datasets

Start with CIC-IDS2017, CTU-13 and UNSW-NB15. Audit each dataset separately for campaigns, hosts, timestamps, attack families, onset events, missing fields, labels and class balance.

### Phase 3 — Build the canonical temporal schema

Create consistent adapters for timestamps, campaigns, entities, source/destination relationships, protocols, ports, bytes, packets, flags, timing features, packet features and labels. Preserve missingness explicitly.

Status: UNSW-NB15 adapter, canonical mapping and family vocabulary are
implemented and smoke-tested. CIC-IoT-2023 remains intentionally unadapted
because its local CSVs have no timestamps or network entity identifiers.

### Phase 4 — Create correct forecasting labels

Generate attack-onset targets for every horizon, current stage, next stage, time-to-next-stage and capture-censoring indicators. Do not count detection of an already active attack as advance warning.

Status: onset/censoring fields and target-validity rules are implemented and
synthetically validated. The full-capture audit is complete; Phase 5 can now
proceed with CIC-IDS2017/CTU-13 development data and UNSW held out.

Status: onset/censoring fields and target-validity rules are implemented and
synthetically validated. The full-capture audit is still required before
headline Phase 5 metrics.

### Phase 5 — Establish trustworthy baselines and evaluation

Compare persistence, logistic regression, tree-based models, TCN and the current LSTM. Report PR-AUC, precision, recall, F1, false alerts per hour, lead-time percentiles, calibration and per-campaign results.

Status: reusable prior, persistence, logistic and random-forest baselines are
implemented in `src/eval/baselines.py`. On the repaired CIC-IDS2017 test cache,
the world model PR-AUC is 0.0952 / 0.1667 / 0.2311 at +30/+60/+120 seconds,
versus logistic 0.0432 / 0.1166 / 0.1868 and random forest 0.0023 / 0.0097 /
0.0180. These results are preliminary because the test positives are only
3/5/7. See `reports/phase5_baseline_evaluation_2026-09-18.md`; confidence
intervals, calibration, false-alert rates and held-out UNSW evaluation remain.

Phase 5 completion update: bootstrap PR-AUC confidence intervals, Brier score,
expected calibration error, false alerts per campaign-hour and per-campaign
metric reporting are implemented in `src/eval/metrics.py`. The repaired test
run reports PR-AUC CIs of [0.0123, 0.3839], [0.0529, 0.4325] and [0.0900,
0.5081] for +30/+60/+120 seconds, with 2.62, 2.24 and 4.86 false alerts per
hour. These rates are not production-acceptable. UNSW has only six observable
onsets in the full audit, so a statistically meaningful held-out forecast score
requires streaming sequence extraction and additional onset-support data.

### Phase 6 — Improve the existing LSTM world model

Use onset-only targets, hard benign negatives, class-balanced loss, host-specific baselines, history/horizon experiments, calibrated thresholds, uncertainty and abstention. Add explicit next-stage and time-to-stage objectives.

Implementation update: Phase 6 foundations are implemented. `src/data/synthetic.py`
generates deterministic, safe canonical episodes for all six stages with
episode provenance; `scripts/generate_phase6_data.py` writes parquet/CSV
artifacts plus an explicit PCAP-replay manifest. `src/models/self_supervised.py`
and `scripts/pretrain_phase6.py` implement masked reconstruction, next-state
and temporal-difference pretraining. `scripts/train_repaired_model.py` now
accepts a pretrained encoder and caps synthetic sequence augmentation at the
configured fraction. Calibration support is available in
`src/eval/calibration.py`, and `src/deployment/registry.py` provides offline
promotion and rollback.

Smoke validation passed for deterministic generation, sequence conversion,
finite pretraining loss, encoder transfer, calibration round-trip and the full
test suite. Actual PCAP replay is intentionally not fabricated; it requires an
authorized external lab/replay tool. Phase 6 performance acceptance still
requires a real retraining run, mixed/real-only evaluation, and calibration
metrics on the resulting checkpoint.

Phase 6 run completed: `models/wm_phase6/best.ckpt` is the validation-selected
`phase6_residual` candidate trained with 25% capped synthetic augmentation and
self-supervised encoder initialization. Test PR-AUC improved from
0.0952/0.1667/0.2311 to 0.1794/0.1956/0.2679 at +30/+60/+120 seconds. The
full report is `reports/phase6_implementation_report_2026-09-18.md`.

Next-improvement update: CTU-13 scenarios 5, 7 and 12 were audited and yielded
0 observable source-host onsets despite attack windows, so they were not
blindly added to supervised onset training. Episode-balanced sampling is now
implemented and has been evaluated. The rerun selected `phase6_baseline`, but
did not retain the original Phase 6 PR-AUC gain on the tiny real-only test
set; this confirms that additional observable real attack episodes are the
next priority. See
`reports/real_onset_audit_ctu13_2026-09-18.md`.

30-minute forecasting upgrade completed experimentally. The configured
horizons are +30s/+1m/+2m/+4m/+8m/+15m/+30m, using autoregressive near-term
outputs and direct long-horizon heads. The live CLI now exposes tiered
advisory/warning/urgent levels. The current real repaired validation and test
splits contain zero positive onset examples at these horizons, so the new
checkpoint is not production-validated; independent continuous real captures
with 30-minute future coverage are required before claiming early-warning
accuracy. See `reports/phase7_30min_forecast_2026-09-18.md`.

### Phase 7 — Add multi-source telemetry

Add DNS, authentication and endpoint/process events. Preserve common timestamps, entity identifiers and missingness indicators. Do not force host telemetry into the current flow-only vector.

### Phase 8 — Add temporal graph modelling

Represent host-host, user-host, host-service and host-domain relationships. Compare the LSTM with a temporal GNN or hybrid temporal-GNN plus future-state decoder. Add next-victim and next-edge prediction.

### Phase 9 — Build defender decision support

Every alert should include risk by horizon, predicted stage, likely next victim/action, lead time, evidence windows, top contributing signals, uncertainty, asset criticality and a recommended human-approved response.

### Phase 10 — Production validation and operational readiness

Test cross-dataset generalization, unseen attack families, temporal drift, missing telemetry, sensor failure, encrypted traffic, inference latency, throughput, calibration degradation, rollback and safe failure behaviour.

Live monitoring is an implementation target within Phases 9–10: first prove the rolling capture-to-forecast loop on an authorized server, then harden it as a monitored service with calibrated alerts and safe operational controls.

Phase 7–10 operational integration update: the FastAPI backend now exposes
telemetry readiness, endpoint-graph coverage, human-approved defender
decision-support guidance and a conservative production-readiness gate. The
existing operator console surfaces these on the Model, Forecast and Network
views. Phase 8 remains data-limited because the loaded aggregate state cache
does not retain source/destination edges; Phase 9 intentionally takes no
automated defensive action; Phase 10 remains blocked until real long-horizon
test positives and multi-source live telemetry are available.

## 7. Current systems perspective

Existing attack-forecasting approaches generally fall into four groups:

- reactive IDS/SIEM/NDR systems that detect and correlate observed events;
- attack-graph systems that estimate plausible future paths from alerts, topology and vulnerabilities;
- probabilistic sequence systems such as HMMs, Bayesian attack graphs and process-mining models;
- neural temporal or temporal-graph systems that predict future alerts, victims, stages or actions.

The strongest practical direction is hybrid: telemetry normalization, temporal graph construction, learned forecasting, ATT&CK/asset constraints, calibrated risk and defender action support.

## 8. Positioning statement

For the current submission, use:

> An offline, explainable temporal network-behaviour forecasting prototype that simulates future traffic states and estimates short-horizon attack-onset risk.

Do not claim production-grade predictive accuracy until the benchmark, cross-dataset testing, calibration and lead-time results support it.

## 9. Update rule

Update this document when any of the following changes:

- dataset or scenario selection;
- feature schema;
- window, history or horizon definition;
- attack-onset or stage labelling;
- model architecture;
- evaluation numbers;
- production/deployment scope;
- claims made in the README, demo or presentation.
