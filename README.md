# SIH26153 — AI-Based Network Attack Forecasting (World Model)

Forecast network attacks **before they land**, instead of alerting after the fact.

This repository holds a sequential **world model** of network behaviour. It consumes a short history
of per-host traffic windows and predicts, for several horizons ahead: the next network state, the
probability of attack, and the MITRE ATT&CK stage that attack would belong to. Because the model
rolls its own predictions forward, it produces an inspectable *simulated future* — and a measurable
**lead time**.

> Smart India Hackathon 2026 — Problem Statement **SIH26153**.
> Design decisions and locked schemas live in [DESIGN.md](DESIGN.md). Read that first.

---

## Status

**Scaffold.** Every module is present with its docstring, public API signatures, type hints and a
`TODO` list. Nothing is implemented yet — function bodies raise `NotImplementedError`.

---

## Architecture at a glance

```
 PCAP / flow CSVs
        |
        v
 src/data      loaders -> unified_schema -> labeller -> windowing
        |                                                   |
        v                                                   v
 src/features  extractor, packet_features,          X: (N, L=10, F=32)
               baselines, trajectory                Y: state / risk / stage
        |
        v
 src/models    LSTM encoder -> decoder -> 3 heads (state, risk, stage)
        |
        v
 src/training  train_loop + scheduled_sampling + checkpointing
        |
        v
 src/inference forward_sim (K steps) -> uncertainty (MC-dropout)
                                     -> trajectory_match (known campaigns)
        |
        +--> src/explain  SHAP on the risk head -> human-readable sentences
        |
        +--> src/eval     harness, metrics (F1 / PR-AUC / lead time), splits, ablations
        |
        v
 demo/app.py   Streamlit replay dashboard
```

A longer write-up is in [docs/architecture.md](docs/architecture.md); the attack-family to ATT&CK
stage table is in [docs/attack_taxonomy.md](docs/attack_taxonomy.md).

---

## Install

Requires **Python 3.10+**. For packet-level features you also need the system `tshark` binary
(Wireshark) on `PATH` — everything else works without it.

```powershell
git clone <repo-url> sih26153-world-model
cd sih26153-world-model
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install -e .
```

On Linux / macOS use `source .venv/bin/activate` instead.

### GPU

`requirements.txt` pins `torch>=2.0` and installs the default (CPU) wheel. All model code selects
its device via `torch.cuda.is_available()` and **runs on CPU as a fallback**, so the repo is usable
on a laptop. For CUDA, install the matching wheel from <https://pytorch.org> before the other
requirements.

---

## Data layout

Datasets are never committed (see `.gitignore`). Drop them under `data/raw/` and let the loaders
build a parquet cache in `data/processed/`. Exact locations are defined in one place —
[`src/data/paths.py`](src/data/paths.py) — and can be overridden per-config.

```
data/
  raw/
    cicids2017/      # MachineLearningCSV/*.csv  + PCAPs
    cicids2018/
    unsw_nb15/
    ctu13/
  processed/         # unified parquet windows (generated)
  interim/           # scratch
models/              # checkpoints (generated)
```

---

## Run

Configs are [OmegaConf](https://omegaconf.readthedocs.io) / Hydra YAML in `configs/`:

| Config | Use |
|---|---|
| `configs/dev.yaml` | Fast loop — one capture day, tiny model, 2 epochs. Use this while coding. |
| `configs/train.yaml` | Full training run across all datasets. |
| `configs/eval.yaml` | Evaluation / ablations against a checkpoint. |

```powershell
# 1. Build the windowed feature cache
python scripts/extract_features.py --config configs/dev.yaml

# 2. Train
python scripts/train.py --config configs/dev.yaml
python scripts/train.py --config configs/train.yaml

# 3. Evaluate (writes metrics JSON + plots)
python scripts/evaluate.py --config configs/eval.yaml --checkpoint models/best.ckpt

# 4. Demo dashboard
streamlit run demo/app.py
```

Any config key can be overridden on the command line, e.g.
`python scripts/train.py --config configs/train.yaml training.lr=3e-4 model.hidden_size=256`.

---

## Tests

```powershell
pytest
```

`tests/` covers the three things most likely to break silently: loader schema conformance
(`test_loaders.py`), window construction and leakage (`test_windowing.py`), and model output shapes
and CPU/GPU parity (`test_model.py`).

---

## Notebooks

| Notebook | Purpose |
|---|---|
| `notebooks/01_data_exploration.ipynb` | Dataset sanity, class balance, attack timelines |
| `notebooks/02_baseline_lr.ipynb` | Logistic-regression and persistence baselines |
| `notebooks/03_lstm_prototype.ipynb` | Encoder-decoder prototype, overfit-one-batch check |
| `notebooks/04_evaluation.ipynb` | Metrics, lead-time distributions, ablation table |

Notebooks are for exploration only — anything worth keeping moves into `src/`.

---

## Conventions

- **Paths:** `pathlib.Path` everywhere, never string paths. All roots come from `src/data/paths.py`.
- **Tabular data:** `pandas` + `pyarrow` (parquet). CSV only at the raw-ingest boundary.
- **Models:** PyTorch >= 2.0, CPU fallback mandatory.
- **Configs:** `omegaconf` / `hydra` — no hard-coded hyperparameters in `src/`.
- **Type hints:** required on every public function.
- **Locked schemas:** the feature list, window parameters, labelling scheme and split policy are
  fixed in [DESIGN.md](DESIGN.md). Changing one is a team decision, not a commit.

---

## License

MIT (see `pyproject.toml`).
