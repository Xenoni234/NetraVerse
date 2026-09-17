# Phase 4 offline demo report

Verified 2026-09-17 on Windows, Python 3.13, CPU inference. No Phase 4 commit or push was created.

## Built

Replaced the old replay/live dashboard with **Dataset replay** and **Upload capture**. The console automatically loads `models/wm_final/best.ckpt` and the newest matching gallery parquet. It displays all three risk horizons, the selected checkpoint threshold, sustained-alert confirmation, labelled attack intervals, API warning lead time, predicted ATT&CK stages, flagged host windows, signed SHAP features, temporal attention and observed feature elevations. Optional uncertainty uses 20 MC-dropout passes.

Gallery loads include file modification time in their cache keys. Replay inference and focused explanations are cached by checkpoint/source/host/time; uncertainty is part of the timeline key. Deterministic explanations can be reused across uncertainty settings. Uploaded windows and computed outputs stay in session state, not the shared replay cache. Generated temporary filenames are removed after ingestion. Forecaster and explainer have separate model instances and locks. The 100 reference histories are sampled deterministically from fully benign, consecutive gallery histories. Checkpoint scaling is applied exactly once before SHAP; timeline inference receives raw features.

The benchmark text attributes the PR-AUC/F1 comparison to the recorded `wm_final` table in `RESULTS.md`. It does not use `lr_baseline.json` or claim accuracy on uploads. Upload labels are unknown, so no attack shading or measured warning lead time is shown. SHAP has no displayed additive baseline because the existing wrapper's base value is a placeholder.

## Files

| File | Purpose |
|---|---|
| `demo/app.py` | Offline controls, resource/session caches, real model charts, tables and explanations. |
| `demo/helpers.py` | Consecutive-history selection, benign references, feature audit, safe temporary ingestion, converter compatibility and alert/label helpers. |
| `demo/requirements.txt` | Pins the demo converter to `cicflowmeter==0.5.0`. |
| `.streamlit/config.toml` | Localhost binding, dark theme, 200 MB upload limit and disabled telemetry. |
| `src/inference/live.py` | Adds only the nine authorized column-map entries below. |
| `tests/test_demo.py` | History isolation, scaling/inference/SHAP agreement, attention, alert timing, input errors and real converter smoke tests. |
| `docs/phase4_demo_report.md` | This handoff report. |
| `docs/phase4_verification.json` | Dependency versions, checkpoint hash, campaign checks, browser checks and measured capture coverage. |
| `docs/screenshots/phase4_replay.png` | Stable dataset replay overview. |
| `docs/screenshots/phase4_upload.png` | Real CSV upload overview with unknown labels. |
| `docs/screenshots/phase4_explanation.png` | Real upload SHAP, attention, explanation and empty flagged table. |
| `docs/screenshots/phase4_pcap.png` | Public PCAP's legitimate insufficient-history state. |

No model, checkpoint, training, labelling, scaling or windowing file was modified. Existing live-capture scripts remain available outside this UI.

## Dependencies and converter compatibility

Installed runtime dependencies: **cicflowmeter 0.5.0**, **scapy 2.7.0**. Already available: Streamlit 1.63.0, SHAP 0.52.0, Plotly 7.0.0. Verification-only installations: Playwright 1.63.0, pyee 13.0.1, greenlet 3.5.6. Browser checks use the existing Microsoft Edge executable; Playwright is not a runtime dependency.

The helper idempotently changes only this signature in `.venv/Lib/site-packages/cicflowmeter/sniffer.py`:

```python
# Before
create_sniffer(input_file, input_interface, output_mode, output,
               input_directory=None, fields=None, verbose=False)
# After
create_sniffer(input_file, input_interface, output_mode, output,
               fields=None, verbose=False, input_directory=None)
```

Unknown signatures or versions are rejected, rather than broadly rewritten. This repair is reproducible on first PCAP upload after installation.

**Additional observed converter issue:** even after the signature repair, `cicflowmeter -f ... -c ...` invokes `tcpdump` for its offline BPF filter, and fails on this machine without libpcap/tcpdump. The helper first invokes that command via an argument list. On the specific `tcpdump is not available` failure, it starts `python -m demo.helpers <capture> <csv>` instead. That subprocess uses Scapy `PcapReader`, an equivalent IPv4 TCP/UDP predicate, and the installed CICFlowMeter `FlowSession.process()` / `flush_flows()` feature engine. It does not implement replacement or reduced feature formulas. No additional installed-source patch, capture driver, live capture, shell command interpolation or network service is used. The UI discloses this reader fallback.

Both subprocess attempts share a five-minute budget. Exit status, file existence, valid CSV header and nonempty records are checked. An initial development attempt used `toPacketList()`, which deadlocks in this package due to nested non-reentrant locking; the final helper uses its explicit `flush_flows()` method. Final smoke and real-capture checks pass.

## Authorized mappings

| Converter key | Unified flow column | Derived model column |
|---|---|---|
| `fwd_pkt_len_mean` | `fwd_pkt_len_mean` | `mean_fwd_pkt_len` |
| `bwd_pkt_len_mean` | `bwd_pkt_len_mean` | `mean_bwd_pkt_len` |
| `pkt_len_var` | `pkt_len_var` | `pkt_len_var` |
| `fwd_iat_mean` | `fwd_iat_mean` | `mean_fwd_iat_s` |
| `bwd_iat_mean` | `bwd_iat_mean` | `mean_bwd_iat_s` |
| `init_fwd_win_byts` | `init_win_fwd` | `mean_init_win_fwd` |
| `init_bwd_win_byts` | `init_win_bwd` | `mean_init_win_bwd` |
| `active_mean` | `active_mean` | `active_s` |
| `idle_mean` | `idle_mean` | `idle_s` |

Existing windowing converts microsecond timing values to seconds. The UI uses these explicit nine model names to distinguish packet-derived features from flow volume and behavior.

## Run commands

From PowerShell:

```powershell
Set-Location E:\Netraverse\sih26153-world-model
# Installation requires package access once; app runtime requires none.
.\.venv\Scripts\python.exe -m pip install -r demo\requirements.txt
.\.venv\Scripts\python.exe -m streamlit run demo/app.py --server.headless true
```

Open `http://127.0.0.1:8501`. Choose **Dataset replay**, then campaign and host. For **Upload capture**, select a CSV/PCAP/PCAPNG file using the same app. Maximum 200 MB. The public verification capture is `data/demo_verification/http.pcap`; its PCAPNG representation is `http.pcapng`. A full real upload example already on this machine is `data/live/server_attack.csv`. These ignored data files are local verification assets, not bundled demo data.

Optional standalone offline conversion, including the compatibility reader when required:

```powershell
.\.venv\Scripts\python.exe -c "from demo.helpers import convert_capture; convert_capture('data/demo_verification/http.pcap', 'data/demo_verification/http.csv')"
.\.venv\Scripts\python.exe -m pytest -q
```

## Verification evidence

- Tiny two-packet fixture: nonempty CICFlowMeter CSV with header verified before UI upload wiring. The fixture is a converter test only, not a fabricated dashboard result.
- Public recorded capture: [Wireshark simple HTTP request/response](https://wiki.wireshark.org/uploads/27707187aeb30df68e70c8fb9d614981/http.cap), 25,803 bytes. Downloaded for development only. SHA-256: `25a72bdf10339f2c29916920c8b9501d294923108de8f29b19aba7cc001ab60d`.
- Converted capture: **3 flow records, 1 host window, all 43 model columns finite, 31 nonzero columns, no missing source feature fields**. All nine packet-source headers exist, and their resulting model values were numerically checked against flow means and existing unit conversions. PCAPNG re-encoding produces matching 43-column values.
- The 12 all-zero model columns are `rst_count`, `urg_count`, `failed_conn_ratio`, `frac_icmp`, `active_s`, `idle_s`, `off_hours_ratio`, `baseline_deviation`, `trajectory_velocity`, `mask_new_peer_count`, `mask_baseline_deviation`, `mask_trajectory_velocity`. No values were invented to increase coverage.
- Public PCAP/PCAPNG is too short for a forecast. The UI correctly reports insufficient history. Real `server_attack.csv` yields 19 windows across hosts; selected host `100.81.46.8` has 16 windows and 7 forecasts, with all analysis panels rendered. Its empty flagged table is expected under the unchanged checkpoint threshold.
- All **13 campaigns** pass Streamlit AppTest and were exercised in headless Edge, including explicit benign fallback. Browser checks also exercised primary horizon changes, focused time changes, uncertainty on/off, CSV upload, PCAP upload, PCAPNG upload and repeated CSV upload. Recorded browser page errors: **0**. Recorded external browser requests: **0**.
- Conversion and the verification Streamlit process ran with external socket connections denied by a development-only `sitecustomize.py`; browser routing also denied non-local requests. This is process-level offline verification, not an OS-wide network disconnect. No runtime download code is included in the app.
- Tests check direct API risk agreement, correct history timestamps/order, separate SHAP model, finite SHAP shape `(10, 43)`, prediction agreement within `1e-6`, ten finite attention weights summing to one, MC bounds, gap-aware sustained alerts and original-window shading. Invalid/empty input, unsupported headers and simulated converter failure/timeout were exercised. Final errors are readable UI messages.
- Final regression command with visible summary: `.\.venv\Scripts\python.exe -m pytest -q -o addopts='' --junitxml=data/demo_verification/pytest.xml`: **27 passed, 0 failed, 50 skipped**, 13.14 seconds. Skips are existing scaffold tests. The requested plain `-m pytest -q` also passed earlier; repository `addopts = '-q'` suppresses its summary.
- `git diff --check` passes. Core-source diff is exactly the nine additions in `live.py`. Model/checkpoint/training/pipeline files have no diff.

## Limitations and deviations

- **Tuesday, CTU-13 #10 and CTU-13 #7 have no attacked hosts with ten consecutive windows required by inference.** They remain visible and offer explicitly selected eligible benign hosts. Monday and CTU-13 #1 have no attack labels in the cached gallery. Histories are never padded.
- The recorded model sometimes predicts BENIGN throughout a replay; the stage chart shows those real values rather than manufacturing progression. Low risk or absent advance warning is retained.
- The warning-lead API uses attack labels in forecast rows and its existing horizon qualification. Original attack intervals outside those rows are still shaded. The first sustained marker can represent a different, earlier alert from the API's qualified warning. Thresholds and lead semantics were not changed.
- CICFlowMeter's extra tcpdump dependency required the documented native-feature reader fallback above, rather than the originally proposed reduced-feature extractor. Finite mapped features establish schema coverage, not empirical parity of every Java/Python extractor calculation or forecasting accuracy on arbitrary captures. IPv6/non-TCP/UDP traffic is outside this converter filter.
- Reference features come from labelled benign gallery histories, not a verified per-upload normal profile. SHAP is approximate; attention is model weighting, not causal evidence. MC inference and SHAP can take longer on large hosts. Cache entries are bounded for replay; session upload outputs last for the session.
- Initial browser checks encountered lazy-component loading and custom-input hit targets; final checks waited for all charts and clicked visible labels. Initial per-host reference enumeration was slow and was replaced with vectorized eligibility selection without altering inference semantics.
- Benchmark values are the recorded `RESULTS.md` table, not a newly evaluated benchmark. No retraining or model-quality claim was made.
- No Phase 4 commit was created. No co-author attribution was added.

## Follow-up: distinguish forecasts from measured lead time (2026-09-17)

The upload view's previous headline, `Unavailable - labels unknown`, described an unmeasurable evaluation metric but looked like a forecasting failure. Updated `demo/app.py` to lead with the focused onset-risk score, its checkpoint threshold, the time the forecast becomes available, horizon coverage, peak risk and first sustained alert. Uploaded data still has unknown ground truth; the UI now explains that only measured warning lead time needs a verified actual onset. Recorded-label lead time remains available in a separate expander for replay.

Added `forecast_log()` in `demo/helpers.py` and a chronological table/CSV download. Every observed window is present, with the model's original three risk scores and stages, selected-horizon status and observed feature elevations against the benign gallery reference. Initial/incomplete histories retain missing predictions, not zero risk. The displayed forecast is available at the current window's close and covers the following K windows. Feature elevations are explicitly separate from focused SHAP attribution. This is a rolling 30/60/120-second forecast, not a claim to predict the entire attack lifecycle or exact attack start.

Added a regression in `tests/test_demo.py` for chronological order, missing-history rows, threshold selection, forecast coverage boundaries, feature evidence and preservation of API risk values. No inference/model/training/ingestion semantics were modified by this follow-up. Existing untracked `demo/samples/` and `tests/test_upload_and_model.py` were not edited.

Verification: uploaded the existing `demo/samples/sample_webattack_192.168.10.8.csv` in local Edge and downloaded the forecast log. The log contains **25 observed windows, 16 forecasts, 9 history-only rows, 4 above-threshold forecasts** at +120 seconds. Focused risk is **45.2%**; peak risk is **91.8%** at origin `2017-07-06 02:33:30 UTC`; first sustained alert is confirmed at `02:34:00 UTC`. These are model scores/alerts, not confirmed attack timestamps or calibrated probabilities. All four analysis charts render, the misleading unavailable headline is absent, and browser page errors are zero. Screenshot: `docs/screenshots/phase4_forecast_summary.png`. Local downloaded verification CSV: `data/demo_verification/sample_forecast_log.csv` (ignored data directory).

Streamlit was restarted to load the changed helper cleanly; existing browser sessions may need a refresh and re-upload. Full suite, including the pre-existing untracked upload/model tests: `python -m pytest -q -o addopts=''` -> **35 passed, 50 skipped**, 28.70 seconds. `git diff --check` passes. No follow-up commit or push was made.
