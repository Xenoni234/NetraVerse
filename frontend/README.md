# NetraVerse - Network Attack Forecasting (frontend)

Eight-page Stitch UI (Home, Simulate, Forecast, ATT&CK, Investigate, Network, Validate, Model),
served by Vite, connected live to the world-model backend in `../sih26153-world-model`.

## Run (two terminals)

1. Backend (the real model API), from the repo root (the parent of this folder):
   ```
   cd ..
   .\.venv\Scripts\python.exe -m uvicorn api.server:app --port 8000
   ```
2. Frontend:
   ```
   npm install        # first time
   npm run dev        # http://localhost:5173
   ```

Open `http://localhost:5173/forecast`. Each page loads `/api.js`, which fetches the backend
(`http://localhost:8000`, override with `window.NV_API_BASE`) and renders a live "world model"
panel using real model output, with the Stitch design preserved below.

## What is live (real model, not fixtures)
- **Simulate / Home** - upload a CICFlowMeter CSV or PCAP/PCAPNG; the file is cleaned and windowed
  locally and the pipeline shows real processing stages, then forecasts the capture.
- **Forecast** - per-host risk timeline + K-step forecast trajectory + lead time.
- **Network** - traffic volume and destination-port fan-out over time.
- **ATT&CK** - predicted stage progression per window.
- **Investigate** - SHAP feature contributions + temporal attention + plain-language summary
  (works for replay and for uploaded captures).
- **Validate** - benchmark (world model vs persistence vs logistic regression) + per-horizon
  metrics + generalization.
- **Model** - model card from the checkpoint.

## Honest gaps
- Packet-only features the UI mentions (TTL, retransmission, burstiness, periodicity) are not in the
  CSV-trained model; they are shown as unavailable rather than fabricated. Held-out-family and
  external cross-dataset metrics are marked "not yet measured".
- The live data is rendered in panels styled to the shared shell (`public/app-shell.css`); the full
  in-place rewrite of every Stitch page to one pixel-level design system is an ongoing polish pass.
