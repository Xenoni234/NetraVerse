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

Open `http://localhost:5173/forecast`. Every page is a shared shell (sidebar, header, live
context bar) with a single `#nv-root` mount. `/navigation.js` wires the shell and `/app-shell.css`
is the shared design system; `/api.js` fetches the backend (`http://localhost:8000`, override with
`window.NV_API_BASE`) and renders each page's content from real model output using that design
system. When the backend is unreachable, pages show an honest "backend offline" state.

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

## No hardcoded data
Every page's `<main>` is a single mount (`#nv-root`); `public/api.js` renders all content from the
backend (real world-model output). There are no fixtures in the rendered UI — numbers, tables,
charts, stages and the plain-language read-out all come from a model call. The Stitch shell (sidebar,
header, design tokens) is preserved; the header clock is a live UTC clock, not a baked-in timestamp.

## Honest gaps
- The model uses 9 **packet-derived** features (packet lengths, IATs, init windows, active/idle),
  computed by CICFlowMeter for both CSV and PCAP uploads — these appear in the Investigate SHAP view.
  Extra packet-only signals (TTL, retransmission, fragmentation, C2 beaconing) are **not** model
  inputs and are not displayed anywhere, so nothing is fabricated.
- Generalization (held-out attack family, flow-only ablation, shuffled-history control) is measured
  by `scripts/run_generalization.py`, which writes `models/wm_final/generalization.json`; the Validate
  page shows those real numbers when present and an honest "not yet measured" otherwise. External
  cross-dataset (e.g. UNSW-NB15) is still not run.
