"""Fine-tune the existing world model on the mixed labelled demo suites.

The base checkpoint is never overwritten. The run uses suites A+B for training,
suite C as a held-out evaluation, and saves a separate demo checkpoint.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import torch
from sklearn.metrics import average_precision_score

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from demo.helpers import ingest_upload
from scripts.improve_world_model import epoch, thresholds, warning_lead_times
from scripts.train_world_model import predict_probs, set_seed, to_loader
from src.data import windowing as W
from src.inference.engine import load_forecaster
from src.models import get_device
from src.models.lstm_encoder_decoder import WorldModel
from src.models.losses import LossWeights, MultiTaskLoss
from src.eval.calibration import fit_calibrator


DATA = ROOT / "demo/mixed_labelled"
BASE = ROOT / "models/wm_final/best.ckpt"
OUT = ROOT / "models/wm_mixed_demo"


def load_suite(path: Path, campaign: str) -> tuple[pd.DataFrame, W.SequenceBatch]:
    # ingest_upload already returns per-host 30-second windows (despite the
    # historical variable name in the demo helper).
    windows, audit = ingest_upload(path.read_bytes(), ".csv")
    windows["campaign_id"] = campaign
    sequences = W.build_sequences(windows, target="onset")
    print(f"{path.name}: windows={len(windows):,}, sequences={len(sequences.x):,}, "
          f"positives={sequences.y_risk.sum(0).tolist()}, ground_truth={audit['ground_truth']}")
    return windows, sequences


def main() -> None:
    set_seed(20260918)
    torch.set_num_threads(4)
    device = get_device("auto")
    base = torch.load(BASE, map_location="cpu", weights_only=False)
    suites = {}
    for name in ("a", "b", "c"):
        suites[name] = load_suite(DATA / f"mixed_attack_suite_{name}_220k.csv", f"mixed_suite_{name}")

    train_windows = pd.concat([suites["a"][0], suites["b"][0]], ignore_index=True)
    train_seq = W.concatenate_sequence_batches([suites["a"][1], suites["b"][1]])
    val_windows, val_seq = suites["c"]
    scaler = base["scaler"]
    train_loader = to_loader(train_seq, scaler, 128, True)
    val_loader = to_loader(val_seq, scaler, 256, False)

    model = WorldModel.from_config(base["model_config"]).to(device)
    model.load_state_dict(base["state_dict"])
    optimizer = torch.optim.AdamW(model.parameters(), lr=2e-5, weight_decay=1e-4)
    criterion = MultiTaskLoss(
        LossWeights(state=0.15, risk=5.0, stage=0.5),
        pos_weight=8.0,
        risk_loss="focal",
        focal_gamma=1.5,
    ).to(device)

    OUT.mkdir(parents=True, exist_ok=True)
    best_score = -np.inf
    best_state = None
    history = []
    for ep in range(1, 31):
        losses = epoch(model, train_loader, criterion, optimizer, device)
        probs, truth, _, _ = predict_probs(model, val_loader, device)
        ap = [float(average_precision_score(truth[:, i], probs[:, i]))
              if truth[:, i].sum() else 0.0 for i in range(truth.shape[1])]
        score = float(np.mean(ap))
        row = {"epoch": ep, "losses": losses, "val_pr_auc": ap, "mean_val_pr_auc": score}
        history.append(row)
        print(row, flush=True)
        if score > best_score:
            best_score = score
            best_state = {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}

    if best_state is None:
        raise RuntimeError("Fine-tuning produced no checkpoint")
    model.load_state_dict(best_state)
    val_probs, val_truth, _, _ = predict_probs(model, val_loader, device)
    cuts = thresholds(val_truth, val_probs)
    calibrator = fit_calibrator(val_truth, val_probs)

    payload = {
        "state_dict": model.state_dict(),
        "model_config": base["model_config"],
        "scaler": scaler,
        "feature_names": base["feature_names"],
        "threshold": float(cuts[0]),
        "thresholds": cuts.tolist(),
        "calibrator": calibrator.to_dict(),
        "horizons": base["horizons"],
        "history_length": base.get("history_length", W.HISTORY_LENGTH),
        "schema_version": base.get("schema_version"),
        "fine_tuned_from": str(BASE.relative_to(ROOT)),
        "training_data": ["mixed_attack_suite_a_220k.csv", "mixed_attack_suite_b_220k.csv"],
    }
    torch.save(payload, OUT / "best.ckpt")

    test_windows, test_seq = suites["c"]
    test_loader = to_loader(test_seq, scaler, 256, False)
    test_probs, test_truth, _, _ = predict_probs(model, test_loader, device)
    labels = test_windows.set_index(["campaign_id", "entity_id", "window_start"])["binary_label"]
    lead = warning_lead_times(test_seq.meta, test_probs, cuts, labels, np.asarray(base["horizons"]))
    report = {"base_checkpoint": str(BASE.relative_to(ROOT)), "best_epoch": int(np.argmax([h["mean_val_pr_auc"] for h in history]) + 1),
              "validation_mean_pr_auc": best_score, "thresholds": cuts.tolist(),
              "held_out_suite": "mixed_attack_suite_c_220k.csv", "held_out_lead_time": lead,
              "history": history}
    (OUT / "finetune_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
