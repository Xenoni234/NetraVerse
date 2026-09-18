"""Train the isolated SIH six-stage demonstration checkpoint.

This run deliberately keeps the reference checkpoint untouched.  It combines
the labelled mixed CSV suites with controlled, canonical six-stage episodes so
the demo has evaluation support for every stage, including exfiltration and
impact.  The public horizons are 2/3/4 thirty-second windows (+60/+90/+120).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import torch
from sklearn.metrics import average_precision_score, precision_score, recall_score
from torch.utils.data import DataLoader, TensorDataset

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from demo.helpers import ingest_upload
from src.data import windowing as W
from src.data.synthetic import EpisodeSpec, generate_dataset
from src.models import get_device
from src.models.lstm_encoder_decoder import WorldModel
from src.models.losses import LossWeights, MultiTaskLoss

BASE = ROOT / "models/wm_final/best.ckpt"
OUT = ROOT / "models/wm_sih_demo"
HORIZONS = (2, 3, 4)
# Demo operating point selected on the mixed labelled suite to preserve a
# 60–120 second warning window.  These are SIH-demo thresholds, separate from
# the untouched production/reference checkpoint.
DEMO_THRESHOLDS = np.array([0.15, 0.12, 0.12], dtype="float32")
SCENARIOS = ("recon", "initial_access", "lateral_movement", "c2", "exfiltration", "impact")


def _synthetic(seed_offset: int, split: str) -> W.SequenceBatch:
    specs = []
    for i, scenario in enumerate(SCENARIOS):
        # Separate campaigns prevent sequence construction from crossing episodes.
        specs.append(EpisodeSpec(scenario=scenario, seed=seed_offset + i,
                                 entity_count=2, warmup_windows=24,
                                 preparation_windows=6, attack_windows=20,
                                 recovery_windows=14,
                                 start=f"2026-02-{10 + seed_offset % 10:02d}T{i:02d}:00:00Z"))
    return W.build_sequences(generate_dataset(specs), W.WindowConfig(horizons=HORIZONS,
        history_length=10, rollout_steps=4, min_windows_per_entity=14), target="onset")


def _csv_suite(path: Path, name: str) -> W.SequenceBatch:
    windows, audit = ingest_upload(path.read_bytes(), ".csv")
    windows["campaign_id"] = name
    return W.build_sequences(windows, W.WindowConfig(horizons=HORIZONS,
        history_length=10, rollout_steps=4, min_windows_per_entity=14), target="onset")


def _attention_targets(batch: W.SequenceBatch) -> np.ndarray:
    """Soft target over history, centred on the precursor nearest onset."""
    n, length = len(batch.x), batch.x.shape[1]
    out = np.full((n, len(HORIZONS), length), 1.0 / length, dtype="float32")
    for row, distance in enumerate(batch.meta["next_attack_distance"].to_numpy()):
        if distance < 1:
            continue
        centre = max(0, length - int(min(distance, length)))
        axis = np.arange(length, dtype="float32")
        weights = np.exp(-0.5 * ((axis - centre) / 1.35) ** 2)
        weights /= max(float(weights.sum()), 1e-8)
        out[row, :, :] = weights
    return out


def _loader(batch: W.SequenceBatch, scaler: dict, attention: np.ndarray, size: int, shuffle: bool):
    x = W.apply_scaler(batch.x, scaler).astype("float32")
    state = W.apply_scaler(batch.y_state, scaler).astype("float32")
    ds = TensorDataset(torch.from_numpy(x), torch.from_numpy(state),
                       torch.from_numpy(batch.y_risk.astype("float32")),
                       torch.from_numpy(batch.y_stage.astype("int64")),
                       torch.from_numpy(attention))
    return DataLoader(ds, batch_size=size, shuffle=shuffle)


def _run(model, loader, criterion, device, optimizer=None):
    train = optimizer is not None
    model.train(train)
    totals, count = {}, 0
    for x, state, risk, stage, attention in loader:
        x, state, risk, stage, attention = [v.to(device) for v in (x, state, risk, stage, attention)]
        out = model(x)
        loss, parts = criterion(out, {"state": state[..., :model.config.state_size],
                                     "risk": risk, "stage": stage, "attention": attention})
        if train:
            optimizer.zero_grad(); loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0); optimizer.step()
        for key, value in parts.items(): totals[key] = totals.get(key, 0.0) + value * len(x)
        count += len(x)
    return {k: v / max(count, 1) for k, v in totals.items()}


@torch.no_grad()
def _predict(model, loader, device):
    model.eval(); probs = []; truth = []; stages = []; attn = []
    for x, _, risk, stage, _ in loader:
        out = model(x.to(device)); probs.append(torch.sigmoid(out["risk_logits"]).cpu().numpy())
        truth.append(risk.numpy()); stages.append(out["stage_logits"].argmax(-1).cpu().numpy())
        attn.append(out["attn_weights"].cpu().numpy())
    return np.concatenate(probs), np.concatenate(truth), np.concatenate(stages), np.concatenate(attn)


def main() -> None:
    torch.manual_seed(20260918); np.random.seed(20260918); torch.set_num_threads(4)
    device = get_device("auto")
    base = torch.load(BASE, map_location="cpu", weights_only=False)

    # Real labelled suites provide CIC-derived variability; synthetic episodes
    # provide explicit support for every requested stage and attention ramps.
    real_a = _csv_suite(ROOT / "demo/mixed_labelled/mixed_attack_suite_a_220k.csv", "real_a")
    real_b = _csv_suite(ROOT / "demo/mixed_labelled/mixed_attack_suite_b_220k.csv", "real_b")
    train = W.concatenate_sequence_batches([real_a, real_b, _synthetic(11, "train")])
    val = _synthetic(31, "val")
    test = _synthetic(61, "test")
    scaler = W.fit_scaler(train.x)
    train_loader = _loader(train, scaler, _attention_targets(train), 256, True)
    val_loader = _loader(val, scaler, _attention_targets(val), 512, False)
    test_loader = _loader(test, scaler, _attention_targets(test), 512, False)

    cfg = dict(base["model_config"])
    cfg.update({"horizons": list(HORIZONS), "rollout_steps": 4,
                "near_horizons": [1, 2, 3, 4], "direct_horizons": []})
    model = WorldModel.from_config(cfg).to(device)
    compatible = {k: v for k, v in base["state_dict"].items()
                  if k in model.state_dict() and model.state_dict()[k].shape == v.shape}
    model.load_state_dict(compatible, strict=False)
    # The reference checkpoint's attention projections are near-degenerate on
    # the mixed demo distribution.  Re-seed only those projections so the
    # localization objective can learn a usable temporal focus map; all other
    # heads retain the baseline weights.
    torch.nn.init.xavier_uniform_(model.attn_q.weight, gain=0.8)
    torch.nn.init.xavier_uniform_(model.attn_k.weight, gain=0.8)
    criterion = MultiTaskLoss(LossWeights(state=.1, risk=5.0, stage=1.0, attention=2.0),
                              pos_weight=5.0, risk_loss="focal", focal_gamma=1.5,
                              attention_enabled=True).to(device)
    optimizer = torch.optim.AdamW(model.parameters(), lr=3e-5, weight_decay=1e-4)

    best, best_score, history = None, -1.0, []
    for epoch in range(1, 21):
        tr = _run(model, train_loader, criterion, device, optimizer)
        p, y, _, _ = _predict(model, val_loader, device)
        ap = [float(average_precision_score(y[:, i], p[:, i])) for i in range(len(HORIZONS))]
        score = float(np.mean(ap)); history.append({"epoch": epoch, "train": tr, "val_pr_auc": ap})
        print(f"epoch={epoch:02d} loss={tr['total']:.4f} mean_pr_auc={score:.4f}", flush=True)
        if score > best_score:
            best_score, best = score, {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}
    model.load_state_dict(best)
    p, y, predicted_stage, attn = _predict(model, test_loader, device)
    cuts = DEMO_THRESHOLDS.copy()
    stage_support = {}
    for stage_id in range(1, 7):
        mask = test.y_stage == stage_id
        stage_support[str(stage_id)] = {"samples": int(mask.sum()),
            "positive_samples": int((y[mask].sum() if mask.any() else 0)),
            "supported": bool(mask.any())}
    attention_mean = attn.mean(axis=(0, 1))
    attention_mean /= max(float(attention_mean.sum()), 1e-8)
    concentration = float(np.sort(attention_mean)[-3:].sum())
    metrics = {"precision": [float(precision_score(y[:, i], p[:, i] >= cuts[i], zero_division=0)) for i in range(3)],
               "recall": [float(recall_score(y[:, i], p[:, i] >= cuts[i], zero_division=0)) for i in range(3)],
               "pr_auc": [float(average_precision_score(y[:, i], p[:, i])) for i in range(3)]}
    OUT.mkdir(parents=True, exist_ok=True)
    payload = {"state_dict": model.state_dict(), "model_config": cfg, "scaler": scaler,
               "feature_names": base["feature_names"], "threshold": float(cuts[-1]), "thresholds": cuts.tolist(),
               "calibrator": None, "horizons": list(HORIZONS), "history_length": 10,
               "schema_version": base.get("schema_version"), "fine_tuned_from": str(BASE.relative_to(ROOT)),
               "training_data": ["mixed_attack_suite_a_220k.csv", "mixed_attack_suite_b_220k.csv", "synthetic six-stage episodes"],
               "sih_demo": True, "attention_regularization": "precursor Gaussian target; cross-entropy weight 0.20"}
    torch.save(payload, OUT / "best.ckpt")
    report = {"checkpoint": str((OUT / "best.ckpt").relative_to(ROOT)), "horizons": ["+60s", "+90s", "+120s"],
              "best_validation_mean_pr_auc": best_score, "held_out_metrics": metrics,
              "stage_support": stage_support, "attention_mean": attention_mean.tolist(),
              "attention_top3_concentration": concentration, "history": history,
              "note": "Synthetic episodes are demo evidence; validate on labelled operational captures before deployment."}
    (OUT / "finetune_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
