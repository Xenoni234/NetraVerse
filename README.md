# NetraVerse — SIH26153 Network Attack Forecasting

NetraVerse is a research and demonstration system for forecasting network attack
progression from rolling CICFlowMeter telemetry. It builds per-host 30-second
windows, uses a sequential world model to forecast future risk, and maps the
forecast to six stage-level MITRE ATT&CK categories:

`Reconnaissance` · `Initial Access` · `Lateral Movement` · `Command & Control` · `Exfiltration` · `Impact`

The SIH demo exposes +60s, +90s and +120s forecasts, replay controls, coloured
temporal graphs, attention/explanation views, stage-linked advisory actions, and
a live-monitoring path for an owned server.

> This is a defensive research/demo system. Forecasts are warnings, not proof of
> compromise, and recommendations require human approval.

## Repository map

```text
api/server.py                 FastAPI forecast, upload, replay and live APIs
frontend/                     Vite frontend and NetraVerse UI
src/data/                     Loading, schema normalization and windowing
src/models/                   World model, losses and attention localization
src/inference/                Forecasting, rollout, live and uncertainty logic
src/mitre/                    Stage mapping and advisory playbooks
scripts/                      Data generation, training, evaluation and live tools
demo/                         Streamlit demo helpers and small sample metadata
docs/setup.md                 Full installation and operating guide
docs/live_test_runbook.md     Authorized server-monitoring runbook
agent/                        CICFlowMeter capture-agent scripts
tests/                        Unit and pipeline tests
```

## Quick start

The complete setup is in [docs/setup.md](docs/setup.md). On Windows, the short
version is:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
pip install -e .
cd frontend
npm install
cd ..
```

Start the backend from the repository root:

```powershell
.\.venv\Scripts\python.exe -m uvicorn api.server:app --host 127.0.0.1 --port 8000 --reload
```

In a second terminal start the frontend:

```powershell
cd frontend
npm run dev -- --host 127.0.0.1
```

Open <http://localhost:5173/simulate>. The frontend uses the API at
`http://localhost:8000`; set `NV_API_BASE` in the browser shell if the API is
hosted elsewhere.

## Demo data and checkpoints

Raw CIC-IDS/CTU data, generated 200k+ row CSV suites, experiment checkpoints,
parquet files, and live predictions are intentionally excluded from Git. They
are large or environment-specific and are regenerated locally. See
`.gitignore` and [docs/setup.md](docs/setup.md) for the data layout.

If local SIH weights exist at `models/wm_sih_demo/best.ckpt`, the API uses them.
Otherwise it falls back to the tracked reference checkpoint at
`models/wm_final/best.ckpt`. To select a checkpoint explicitly:

```powershell
$env:NETRAVERSE_CHECKPOINT = "$PWD\models\wm_sih_demo\best.ckpt"
```

Create local labelled demo uploads after placing the required CIC-IDS2017 files
under `data/raw/CIC-IDS2017/TrafficLabelling/`:

```powershell
python scripts/build_demo_samples.py
python scripts/build_large_labelled_demo_datasets.py
python scripts/build_mixed_labelled_demo_datasets.py
```

The generated files remain local and can be uploaded through **Simulate**.

## Live server monitoring

The supported flow is:

```text
owned server interface → CICFlowMeter → rolling flow files → calibration
→ SIH checkpoint → live predictions → FastAPI → Live page
```

Capture only on a server and interface that you own or are authorized to test.
Install and run the capture agent using [agent/README.md](agent/README.md), then
start the forecast loop:

```bash
python scripts/live_forecast.py \
  --flows ~/nv_flows \
  --checkpoint models/wm_sih_demo/best.ckpt \
  --interval 30
```

Use [docs/live_test_runbook.md](docs/live_test_runbook.md) for calibration,
feed-health checks, and the authorized server demo procedure.

## Testing

```powershell
pytest
```

Frontend checks:

```powershell
cd frontend
npm run build
node --check public/api.js
```

## Design and limitations

- Replay is causal: future windows and labelled attack intervals are not revealed
  until playback reaches them.
- The peak-risk summary is deferred until replay completion.
- Attention is displayed as model focus, not causal proof.
- Live traffic is prediction-only; measured lead time requires a trusted operator
  event or a labelled replay.
- A sudden attack with no observable precursor may only be detected at onset.
- Stage labels are stage-level ATT&CK mappings, not individual technique claims.

See [DESIGN.md](DESIGN.md), [docs/architecture.md](docs/architecture.md), and
[docs/attack_taxonomy.md](docs/attack_taxonomy.md) for the locked schemas and
mapping details.

## License

MIT. See [pyproject.toml](pyproject.toml).
