# NetraVerse setup and operating guide

This guide starts the local NetraVerse UI, prepares local demo data, and explains
the optional live-server path. Run commands from the repository root unless a
command changes directory explicitly.

## 1. Prerequisites

- Python 3.10 or newer; Python 3.11 is recommended.
- Node.js 18 or newer and npm for the Vite frontend.
- Git.
- Wireshark/TShark only when working with PCAP files.
- CICFlowMeter on the monitored server for live traffic. The model expects
  CICFlowMeter-compatible flow columns.

Raw datasets and generated model artifacts are not stored in this repository.
They must be supplied locally and are covered by `.gitignore`.

## 2. Python environment

### Windows PowerShell

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
pip install -e .
```

If PowerShell blocks activation, either run the commands using the interpreter
directly (`.\.venv\Scripts\python.exe`) or allow local scripts for the current
user according to your organization’s policy.

### Linux or macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
pip install -e .
```

## 3. Frontend environment

```bash
cd frontend
npm install
cd ..
```

The frontend is a static Vite client. It does not contain model data or fixture
forecasts; it calls the FastAPI backend.

## 4. Start the local application

Use two terminals.

### Terminal A — API

Windows:

```powershell
.\.venv\Scripts\python.exe -m uvicorn api.server:app --host 127.0.0.1 --port 8000 --reload
```

Linux/macOS:

```bash
.venv/bin/python -m uvicorn api.server:app --host 127.0.0.1 --port 8000 --reload
```

Check that it is running:

```text
http://localhost:8000/api/health
```

### Terminal B — UI

```bash
cd frontend
npm run dev -- --host 127.0.0.1
```

Open <http://localhost:5173/simulate>. Use **Simulate** to upload a CSV, PCAP,
or PCAPNG capture. Use **Forecast**, **ATT&CK**, **Investigate**, and **Network**
to inspect the same active capture.

After backend or frontend changes, use `Ctrl+Shift+R`. Upload sessions are held
in backend memory, so restart-and-reupload is required after restarting the API.

## 5. Checkpoint selection

The API uses this order:

1. `NETRAVERSE_CHECKPOINT`, when set.
2. `models/wm_sih_demo/best.ckpt`, when present locally.
3. `models/wm_final/best.ckpt` as the tracked reference fallback.

Windows:

```powershell
$env:NETRAVERSE_CHECKPOINT = "$PWD\models\wm_sih_demo\best.ckpt"
```

Linux/macOS:

```bash
export NETRAVERSE_CHECKPOINT="$PWD/models/wm_sih_demo/best.ckpt"
```

Set the variable before starting Uvicorn. Do not commit private or experimental
checkpoints; the SIH and generated model directories are ignored.

## 6. Local demo datasets

Place the required CIC-IDS2017 TrafficLabelling files under:

```text
data/raw/CIC-IDS2017/TrafficLabelling/
```

Then generate local uploads:

```bash
python scripts/build_demo_samples.py
python scripts/build_large_labelled_demo_datasets.py
python scripts/build_mixed_labelled_demo_datasets.py
```

The large suites are intended for local demonstration and evaluation. They are
not newly captured traffic and are not committed to Git. The scripts write their
manifests beside the generated files.

For the isolated six-stage SIH checkpoint, generate the local mixed suite first,
then run:

```bash
python scripts/train_sih_demo.py
```

Training writes to `models/wm_sih_demo/`, which is intentionally ignored.

## 7. Live server monitoring

Only monitor an interface and server that you own or are authorized to test.
The live path is:

```text
server interface → CICFlowMeter → rolling flow files → calibration
→ checkpoint → live_forecast.py → predictions.parquet → API/UI
```

Install CICFlowMeter and capture-agent requirements on the server using
[agent/README.md](../agent/README.md). A typical Linux capture command is:

```bash
sudo IFACE=tailscale0 \
  CFM=/opt/CICFlowMeter/bin/cfm \
  OUTDIR=~/nv_flows \
  ./agent/capture.sh
```

Capture at least 30–60 minutes of normal traffic before calibration. Then run:

```bash
python scripts/calibrate.py \
  --flows ~/nv_flows \
  --checkpoint models/wm_final/best.ckpt \
  --out models/wm_server/best.ckpt

python scripts/live_forecast.py \
  --flows ~/nv_flows \
  --checkpoint models/wm_server/best.ckpt \
  --interval 30
```

The live page is prediction-only. It requires approximately ten history windows
before a normal forecast is available and reports feed freshness when the live
prediction file is stale or missing. See [live_test_runbook.md](live_test_runbook.md)
for the complete authorized test procedure.

## 8. Validation and troubleshooting

Run the test suite:

```bash
pytest
```

Build/check the frontend:

```bash
cd frontend
npm run build
node --check public/api.js
```

Common fixes:

- **API offline:** start Uvicorn on port 8000 and refresh the browser.
- **Upload has no forecastable host:** provide at least ten consecutive 30-second
  windows for one host.
- **Decision-support 404 for an upload:** restart the API, refresh the UI, and
  re-upload; uploaded sessions are in-memory and require the upload ID.
- **Missing graph edges:** re-upload the capture after starting the current API;
  endpoint edges require retained source/destination columns.
- **Missing SIH checkpoint:** set `NETRAVERSE_CHECKPOINT` or use the tracked
  `models/wm_final/best.ckpt` fallback.

## 9. Publishing safely

Before staging, verify that large local data, checkpoints, secrets, and runtime
outputs are ignored:

```bash
git status --short --ignored
git check-ignore -v demo/large_labelled/* models/wm_sih_demo/* data/raw/*
```

The push workflow is documented in the project handoff instructions; never use
`git add -f` for raw datasets, generated CSV suites, checkpoints, or secrets.
