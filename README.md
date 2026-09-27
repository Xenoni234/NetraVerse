# NetraVerse: World-Model Network Attack Forecasting

SIH 2026 · PS 26153 (NTRO).

NetraVerse is a latent **world model** that learns how per-host network state evolves, `P(s_t+1 | s_t)`. It imagines the next **300 s** to forecast which hosts will be involved in attack activity, and maps the forecast to **MITRE ATT&CK** stages. Every forecast comes with an explanation. The analyst can **Accept / Modify / Reject** a recommended containment and see the re-simulated future.

```
CSV ─┐                                  ┌─ Captum IG explanation (every forecast)
PCAP ┼─ fusion.windowize ─ WorldModel ──┼─ rollout(state, 300 s) ─ MITRE stage ─ rule engine ─ counterfactual re-rollout
Live ┘   (one 31-feature schema)        └─ GraphSAGE host context            (deterministic)   (same rollout, action applied)
```

## Quick start

```bash
git clone https://github.com/Xenoni234/NetraVerse.git && cd NetraVerse && git checkout rebuild
python -m venv .venv && .venv/Scripts/python -m pip install -r requirements.txt   # Linux: .venv/bin/python
python -m pytest -q                                           # sanity check
python -m uvicorn src.api.main:app --port 8000                # backend (loads models/world_model.pt)
python -m streamlit run dashboard/app.py                      # dashboard -> http://localhost:8501
```

- Pick **CSV Upload**, upload a CIC/CTU/UNSW flow CSV or a PCAP (or a bundled sample), then **Analyse** and **▶ Play**.
- Playback pauses at the first alert, where you choose Accept, Modify or Reject.
- Optional local narration: install Ollama and run `ollama pull qwen2.5:3b`.

## Documentation

| Doc | For |
|---|---|
| [docs/SETUP.md](docs/SETUP.md) | Install, data layout, running on one or two machines, all environment variables |
| [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) | Repo layout, the contracts you must not break, common tasks, tests, working rules |
| [docs/TRAINING.md](docs/TRAINING.md) | Model details, reproducing training, results, **tuning decisions (R20)**, limitations, lab retraining |
| [docs/API.md](docs/API.md) | Every backend endpoint |
| [docs/LIVE_SENSOR.md](docs/LIVE_SENSOR.md) | Live capture, enforcement, our laptop deployment, current live status |
| [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | Known problems and fixes |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | 2-page architecture document (PS deliverable) |
| [demo/demo_script.md](demo/demo_script.md) | The 2-minute demo walkthrough |
| [reports/benchmarks.md](reports/benchmarks.md) | All measured results (generated) |
| [models/README.md](models/README.md) | What each checkpoint is |
| `prd.md`, `architecture.md`, `rules.md`, `phases.md`, `design.md` | The project spec (authoritative) |

## Status

| Phase | State |
|---|---|
| 0–1 Data, unified schema, CSV/PCAP/live fusion | Done |
| 2 RSSM-lite world model + 300 s rollout, LogReg baseline | Done. Test F1 0.860 / PR-AUC 0.921 vs LogReg 0.543 / 0.766 |
| 3 MITRE mapping, Captum + SHAP | Done |
| 4 Rule engine, counterfactual Accept/Modify/Reject | Done |
| 5 GraphSAGE host layer | Done. Ablation PR-AUC 0.921 vs 0.904 |
| 6 Cross-dataset zero-shot | Done. **Fails** (CTU-13 0.006, UNSW 0.19), reported honestly |
| 7 FastAPI backend | Done |
| 8 Live capture + real nftables enforcement | Done, deployed on the sensor laptop |
| 9 Streamlit dashboard with the preserved 3D topology | Done |
| 10 Local-LLM narration | Done (Ollama, async, template fallback) |
| 11 Live home-network demo | Tooling done. **Next: record lab traffic and retrain.** The current model misses real scans on the home network. See docs/TRAINING.md. |
| 12 Docs | Done (this folder) |
| 13 Docker | Not pursued by the team. Unmaintained Dockerfiles remain in the repo. |
| 14 Demo video + slides | To do |

## Team workflow

- Work on branch `rebuild`. Keep `python -m pytest -q` green.
- Regenerate reports with the scripts; never hand-edit numbers (R1/R2).
- Log every tuning decision in docs/TRAINING.md (R20).
- Plain commit messages.
