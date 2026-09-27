# Setup

This guide covers setting up NetraVerse on a development machine (Windows or Linux) and on the Linux sensor laptop used for the live demo. Everything runs locally; nothing calls a cloud API at runtime (R10).

## 1. Requirements

| | Version used / notes |
|---|---|
| Python | 3.11+. We develop on Windows with 3.13 and run the sensor laptop on Ubuntu with 3.12. |
| GPU | Optional. CUDA is used only when the installed torch build supports the card. Otherwise it falls back to CPU (see [TROUBLESHOOTING](TROUBLESHOOTING.md)). |
| Ollama | Optional, for decision narration. Install from ollama.com, then run `ollama pull qwen2.5:3b` (any small model works). |
| Node.js | Only needed to rebuild the 3D topology bundle. The built file is committed. |
| Linux sensor only | `tcpdump`/libpcap, `nft`, capture rights (root, or `cap_net_raw` on the python binary). |

## 2. Get the code and install

```bash
git clone https://github.com/Xenoni234/NetraVerse.git
cd NetraVerse
git checkout rebuild
python -m venv .venv
# Windows
.venv\Scripts\python -m pip install -r requirements.txt
# Linux
.venv/bin/python -m pip install -r requirements.txt
```

- `requirements.txt` pins the exact versions the shipped model was trained and tested with.
- To use a GPU, install the torch wheel matching your CUDA from pytorch.org first, then the rest.
- Check the install with `python -m pytest -q`. Expect 18 passed, or a few skipped if the demo samples are missing.

## 3. Data

The trained model is already in the repo (`models/world_model.pt`). **You only need the raw datasets to retrain, or to regenerate the bundled replay samples.**

Put the datasets under `data/raw/`, which is gitignored. The folder names the loaders expect:

```
data/raw/
├── CIC-IDS2017/TrafficLabelling/*.pcap_ISCX.csv          (8 day files, with IPs + timestamps)
├── CIC-IDS2018/csv_features/Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv
├── CTU-13/_full/CTU-13-Dataset/<n>/*.binetflow          (scenarios 1,4,5,7,8,10,12)
├── UNSW-NB-15/unsw_nb15/UNSW-NB15_{1..4}.csv            (+ NUSW-NB15_features.csv)
└── lab/                                                  (your own captures, see LIVE_SENSOR.md)
```

The paths are defined in `src/training/build_dataset.py` (`DATASETS`) and `src/utils/config.py`. Then:

```bash
python -m demo.make_samples          # bundled replay CSVs -> demo/samples/ (~230 MB, gitignored)
python -m src.training.build_dataset # only needed before retraining, see TRAINING.md
```

## 4. Run it (one machine)

Use two terminals from the repo root:

```bash
python -m uvicorn src.api.main:app --host 127.0.0.1 --port 8000     # backend
python -m streamlit run dashboard/app.py                              # dashboard -> http://localhost:8501
```

- Check the backend with `curl localhost:8000/health`. It returns the checkpoint, device, threshold and live status.
- In the dashboard, pick **CSV Upload**, then a bundled sample (or upload any CSV/PCAP), then **Analyse**, then **▶ Play**. The full walkthrough is in [`demo/demo_script.md`](../demo/demo_script.md).
- If Ollama is running locally, decision points show an LLM narration. Otherwise they show a template text. Both are fine.

## 5. Run it split across machines (our demo layout)

| Machine | Runs |
|---|---|
| Sensor laptop (Ubuntu, `wlp0s20f3`, Tailscale `100.72.80.52`) | API + live sensor + its own Ollama |
| Dashboard PC (Windows, Tailscale `100.81.46.8`) | Streamlit only |

```bash
# dashboard PC
set NV_API_URL=http://100.72.80.52:8000          # PowerShell: $env:NV_API_URL="http://100.72.80.52:8000"
python -m streamlit run dashboard/app.py
```

The sensor side is described in [LIVE_SENSOR.md](LIVE_SENSOR.md).

## 6. Environment variables

| Variable | Where | Default | Meaning |
|---|---|---|---|
| `NV_API_URL` | dashboard | `http://127.0.0.1:8000` | Backend URL used by the Streamlit server |
| `NV_API_PUBLIC_URL` | dashboard | = `NV_API_URL` | Backend URL the **browser** uses to load the offline 3D bundle |
| `NV_DEVICE` | backend | auto | Force `cpu` or `cuda` |
| `NV_OLLAMA_URL` | backend | `http://127.0.0.1:11434` | Local Ollama |
| `NV_OLLAMA_MODEL` | backend | `qwen2.5:3b` | Narration model (laptop uses `qwen2.5-coder:3b`) |
| `NV_OLLAMA_TIMEOUT` | backend | `30` | Seconds before falling back to template narration |
| `NV_NARRATION` | backend | `1` | `0` disables the LLM entirely |
| `NV_LIVE_IFACE` | backend | - | Capture interface for Live Monitor |
| `NV_LIVE_BPF` | backend | `ip` | Capture filter |
| `NV_LIVE_TICK_S` | backend | `15` | Live inference period (sliding 60 s windows) |
| `NV_LIVE_REPLAY_PCAP` | backend | - | Feed a PCAP at wall-clock speed instead of sniffing (rehearsal) |
| `NV_ENFORCE` | backend | `0` | `1` = Accept/Modify in live mode really run `nft` (otherwise dry-run) |
| `NV_OPERATOR_TOKEN` | backend | - | If set, live decisions need this token (dashboard sidebar) |
| `NV_PROTECTED_IPS` | backend | see `action_executor.py` | Comma list that can never be blocked |
| `NV_NFT_TABLE` | backend | `netraverse` | nftables table used for rules |

`.env.example` lists them too.

## 7. Docker (optional, not maintained)

`Dockerfile.backend`, `Dockerfile.dashboard` and `docker-compose.yml` exist. The backend and dashboard images were built and run once successfully, but **the team does not use or maintain Docker**. Run everything natively as above.
