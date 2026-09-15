"""Train the LSTM world model on CIC-IDS2017 (per-host) and evaluate per horizon.

End to end: load -> unify -> label -> build per-host 30s snapshots -> sequences ->
chronological split -> scale -> two-stage train (pretrain-normal, then fine-tune
with scheduled sampling) -> forecast -> per-horizon metrics vs the persistence
baseline. Runs on the GPU when available (CPU fallback intact).

Usage::

    python scripts/train_world_model.py --config configs/dev.yaml
    python scripts/train_world_model.py --config configs/dev.yaml --days all
    python scripts/train_world_model.py --config configs/dev.yaml --epochs-finetune 15
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path
from typing import Sequence

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import numpy as np
import pandas as pd
import torch
from torch.utils.data import DataLoader

from src.data import labeller, loaders, unified_schema
from src.data import windowing as W
from src.eval import metrics as M
from src.eval import splits as S
from src.models import get_device
from src.models.lstm_encoder_decoder import WorldModel, WorldModelConfig
from src.models.losses import LossWeights, MultiTaskLoss, pos_weight_from_labels

DEFAULT_DAYS = ("tuesday", "wednesday", "thursday", "friday")  # skip Monday (benign-only)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Train the world model on CIC-IDS2017 (per-host)")
    ap.add_argument("--config", type=Path, default=REPO_ROOT / "configs" / "dev.yaml")
    ap.add_argument("--days", nargs="*", default=list(DEFAULT_DAYS),
                    help="2017 weekdays, or 'all'")
    ap.add_argument("--max-rows-per-day", type=int, default=None)
    ap.add_argument("--epochs-pretrain", type=int, default=3)
    ap.add_argument("--epochs-finetune", type=int, default=10)
    ap.add_argument("--batch-size", type=int, default=256)
    ap.add_argument("--hidden-size", type=int, default=128)
    ap.add_argument("--lr", type=float, default=1e-3)
    ap.add_argument("--target", choices=["onset", "ongoing"], default="onset",
                    help="onset = forecast attack BEFORE it starts (PS goal); ongoing = detection")
    ap.add_argument("--pos-weight-cap", type=float, default=30.0)
    ap.add_argument("--risk-loss", choices=["bce", "focal"], default="bce")
    ap.add_argument("--focal-gamma", type=float, default=2.0)
    ap.add_argument("--entity-granularity", choices=["src_ip", "src_dst_pair"], default="src_ip")
    ap.add_argument("--add-2018", action="store_true",
                    help="also train on the CIC-IDS2018 IP-bearing day (Tue-20-02, DDoS)")
    ap.add_argument("--max-rows-2018", type=int, default=2_000_000,
                    help="row cap for the 3.9GB 2018 day (memory)")
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--run-name", type=str, default="wm_cicids2017")
    return ap.parse_args(argv)


def set_seed(seed: int) -> None:
    import random
    random.seed(seed); np.random.seed(seed); torch.manual_seed(seed)
    torch.cuda.manual_seed_all(seed)


def build_dataset(days, max_rows, *, add_2018=False, max_rows_2018=2_000_000, use_cache=True,
                  granularity="src_ip"):
    """Load -> unify -> label -> per-entity windows. 2017 (all/selected days),
    optionally + the CIC-IDS2018 IP-bearing day (the only 2018 day with Source IP).

    ``granularity`` = ``src_ip`` (per host) or ``src_dst_pair`` (per host-pair;
    many more benign->attack transitions, but fan-out features degenerate).
    Windows cached to data/processed/ so iteration skips the slow (~3 min) rebuild.
    """
    from src.data.paths import PROCESSED_DIR

    tag = (("all" if days == ["all"] else "-".join(days)) + ("_+2018" if add_2018 else "")
           + ("_pair" if granularity == "src_dst_pair" else ""))
    cache = PROCESSED_DIR / f"windows_cicids2017_{tag}.parquet"
    if use_cache and cache.exists():
        windows = pd.read_parquet(cache)
        print(f"[data] loaded {len(windows):,} cached host-windows from {cache.name}")
        return windows

    frames = []
    for day in (["all"] if days == ["all"] else days):
        raw = loaders.load_cicids2017(day, max_rows=max_rows, verbose=True)
        uni = unified_schema.to_unified(raw, "cicids2017")
        lab = labeller.label_frame(uni, dataset="cicids2017", verbose=False)
        frames.append(lab)
    if add_2018:
        raw = loaders.load_cicids2018("tue-20-02", max_rows=max_rows_2018, verbose=True)
        uni = unified_schema.to_unified(raw, "cicids2018")
        if "src_ip" in uni.columns:
            lab = labeller.label_frame(uni, dataset="cicids2018", verbose=False)
            frames.append(lab)
            print("  [data] added CIC-IDS2018 Tue-20-02 (DDoS, per-host)")
        else:
            print("  [data] WARNING: 2018 day lacks Source IP; skipped")
    flows = pd.concat(frames, ignore_index=True)
    print(f"\n[data] {len(flows):,} flows across {flows['campaign_id'].nunique()} campaign(s)")
    t = time.perf_counter()
    windows = W.build_windows(flows, W.WindowConfig(entity_granularity=granularity))
    print(f"[data] {len(windows):,} host-windows built in {time.perf_counter()-t:,.1f}s "
          f"| window attack rate {windows['binary_label'].mean():.2%}")
    cache.parent.mkdir(parents=True, exist_ok=True)
    windows.to_parquet(cache, index=False)
    print(f"[data] cached -> {cache.name}")
    return windows


def sequences_for_split(windows: pd.DataFrame, target: str) -> W.SequenceBatch | None:
    try:
        return W.build_sequences(windows, target=target)
    except ValueError:
        return None


def to_loader(batch: W.SequenceBatch, scaler, batch_size, shuffle):
    x = W.apply_scaler(batch.x, scaler)
    # Scale the STATE TARGETS with the same scaler (same F columns/order), else the
    # Gaussian NLL tries to predict raw byte-counts in the millions and explodes,
    # swamping the risk/stage heads.
    y_state = W.apply_scaler(batch.y_state, scaler)
    ds = torch.utils.data.TensorDataset(
        torch.from_numpy(x),
        torch.from_numpy(y_state.astype("float32")),
        torch.from_numpy(batch.y_risk.astype("float32")),
        torch.from_numpy(batch.y_stage.astype("int64")),
    )
    return DataLoader(ds, batch_size=batch_size, shuffle=shuffle, drop_last=False)


def run_epoch(model, loader, crit, opt, device, *, sampling_prob, state_size, train):
    model.train() if train else model.eval()
    total, n = 0.0, 0
    torch.set_grad_enabled(train)
    for x, y_state, y_risk, y_stage in loader:
        x = x.to(device); y_state = y_state.to(device)
        y_risk = y_risk.to(device); y_stage = y_stage.to(device)
        targets_full = y_state  # (B, K, F) — but decoder needs per-step frames
        # y_state holds the K future frames at horizons; for teacher forcing we
        # need the first `rollout` steps. Reuse y_state's K frames as the teacher
        # frames for the matching steps; steps not in K free-run.
        out = model(x, targets=None if not train else _teacher_frames(y_state, model.config),
                    sampling_prob=sampling_prob)
        tgt = {"state": y_state[..., :state_size], "risk": y_risk, "stage": y_stage}
        loss, parts = crit(out, tgt)
        if train:
            opt.zero_grad(); loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            opt.step()
        total += parts["total"] * x.size(0); n += x.size(0)
    torch.set_grad_enabled(True)
    return total / max(n, 1)


def _teacher_frames(y_state, cfg):
    """Expand the K horizon frames into `rollout_steps` teacher frames.

    We only have ground-truth frames at the K horizons; for intermediate steps we
    reuse the nearest available horizon frame as the teacher. Good enough for
    scheduled sampling (the loss is still only scored at K).
    """
    b, k, f = y_state.shape
    steps = cfg.rollout_steps
    horizons = list(cfg.horizons)
    frames = torch.zeros(b, steps, f, device=y_state.device, dtype=y_state.dtype)
    for step in range(steps):
        h = step + 1
        j = min(range(k), key=lambda i: abs(horizons[i] - h))
        frames[:, step, :] = y_state[:, j, :]
    return frames


@torch.no_grad()
def predict_probs(model, loader, device):
    model.eval()
    probs, risks, stages, stage_true = [], [], [], []
    for x, y_state, y_risk, y_stage in loader:
        out = model.rollout(x.to(device))
        probs.append(torch.sigmoid(out["risk_logits"]).cpu().numpy())
        risks.append(y_risk.numpy())
        stages.append(out["stage_logits"].argmax(-1).cpu().numpy())
        stage_true.append(y_stage.numpy())
    return (np.concatenate(probs), np.concatenate(risks),
            np.concatenate(stages), np.concatenate(stage_true))


def evaluate(name, y_prob, y_true, threshold, horizons):
    print(f"\n  {name}")
    print(f"  {'horizon':<10}{'P':>8}{'R':>8}{'F1':>8}{'PR-AUC':>9}{'FPR':>8}{'n_pos':>8}")
    rows = {}
    for i, k in enumerate(horizons):
        m = M.compute_all_metrics(y_true[:, i], (y_prob[:, i] >= threshold).astype(int),
                                  y_prob[:, i], threshold=threshold)
        rows[k] = m
        print(f"  +{k*30:<9}s{m['precision']:>8.3f}{m['recall']:>8.3f}{m['f1']:>8.3f}"
              f"{m['pr_auc']:>9.3f}{m['fpr']:>8.3f}{m['support']['n_positive']:>8}")
    return rows


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    set_seed(args.seed)
    device = get_device("auto")
    horizons = list(W.HORIZONS)
    state_size = len(W.STATE_FEATURE_COLUMNS)
    F = len(W.MODEL_COLUMNS)

    print("=" * 74)
    print(f"WORLD MODEL TRAINING — CIC-IDS2017 per-host | device={device} | target={args.target}")
    print("=" * 74)

    windows = build_dataset(args.days, args.max_rows_per_day,
                            add_2018=args.add_2018, max_rows_2018=args.max_rows_2018,
                            granularity=args.entity_granularity)

    # Chronological split on the WINDOWS (per campaign), then sequence each split
    # separately so no sequence crosses a split boundary.
    cfg = S.SplitConfig(time_col="window_start", family_col="attack_family")
    parts = S.chronological_split(windows, config=cfg, verbose=True)

    seq = {name: sequences_for_split(fr, args.target) for name, fr in parts.items()}
    for name in ("train", "val", "test"):
        b = seq[name]
        print(f"  {name}: {0 if b is None else b.x.shape[0]:,} sequences")
    if seq["train"] is None or seq["test"] is None:
        print("Not enough data to form train/test sequences — try --days all or more rows.")
        return 1

    scaler = W.fit_scaler(seq["train"].x)
    pw_raw = pos_weight_from_labels(seq["train"].y_risk)
    pw = min(pw_raw, args.pos_weight_cap)
    n_pos = int((seq["train"].y_risk[:, 0] > 0.5).sum())
    print(f"\n[train] onset positives @k=1: {n_pos:,} | pos_weight={pw:,.1f} "
          f"(raw {pw_raw:,.1f}, cap {args.pos_weight_cap:g}) | F={F} | state_size={state_size}")

    train_loader = to_loader(seq["train"], scaler, args.batch_size, shuffle=True)
    val_loader = to_loader(seq["val"], scaler, args.batch_size, False) if seq["val"] else None
    test_loader = to_loader(seq["test"], scaler, args.batch_size, False)

    model = WorldModel(WorldModelConfig(
        input_size=F, state_size=state_size, hidden_size=args.hidden_size,
        num_layers=2, dropout=0.2, horizons=tuple(horizons), rollout_steps=W.ROLLOUT_STEPS,
        n_stages=6,
    )).to(device)
    print(f"[model] {model.num_parameters():,} params")
    opt = torch.optim.Adam(model.parameters(), lr=args.lr, weight_decay=1e-4)

    # ---- Stage A: pretrain the dynamics (state head only) on normal-heavy data
    crit_pre = MultiTaskLoss(LossWeights(), risk_enabled=False, stage_enabled=False).to(device)
    print(f"\n[pretrain] {args.epochs_pretrain} epochs, state head only (learn normal dynamics)")
    for ep in range(args.epochs_pretrain):
        tr = run_epoch(model, train_loader, crit_pre, opt, device,
                       sampling_prob=0.0, state_size=state_size, train=True)
        print(f"  epoch {ep+1}/{args.epochs_pretrain}  state-NLL {tr:.4f}")

    # ---- Stage B: fine-tune all heads with scheduled sampling
    crit = MultiTaskLoss(LossWeights(), pos_weight=pw,
                         risk_loss=args.risk_loss, focal_gamma=args.focal_gamma).to(device)
    print(f"\n[finetune] {args.epochs_finetune} epochs, all heads, scheduled sampling 0.0->0.9")
    best_f1, best_state = -1.0, None
    for ep in range(args.epochs_finetune):
        sp = 0.9 * ep / max(args.epochs_finetune - 1, 1)  # ramp P(use own prediction)
        tr = run_epoch(model, train_loader, crit, opt, device,
                       sampling_prob=sp, state_size=state_size, train=True)
        msg = f"  epoch {ep+1}/{args.epochs_finetune}  loss {tr:.4f}  samp {sp:.2f}"
        if val_loader is not None:
            vp, vt, _, _ = predict_probs(model, val_loader, device)
            # PR-AUC is threshold-free and stable under rare positives -> use it to
            # pick the best epoch (F1@0.5 is noisy when positives are <1%).
            pra_k1 = M.compute_all_metrics(vt[:, 0], (vp[:, 0] >= 0.5).astype(int), vp[:, 0])["pr_auc"]
            msg += f"  val_PRAUC@k1 {pra_k1:.3f}"
            if pra_k1 >= best_f1:
                best_f1 = pra_k1
                best_state = {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}
        print(msg)
    if best_state is not None:
        model.load_state_dict(best_state)

    # ---- Threshold on val, evaluate on test
    threshold = 0.5
    if val_loader is not None:
        vp, vt, _, _ = predict_probs(model, val_loader, device)
        threshold = M.select_threshold(vt[:, 0], vp[:, 0], objective="f1")
    print(f"\n[eval] threshold={threshold:.4f} (val-selected) — TEST results:")

    tp, tt, _, _ = predict_probs(model, test_loader, device)
    evaluate("WORLD MODEL", tp, tt, threshold, horizons)

    # Persistence baseline: future risk = last observed window's label. For the
    # onset task this is ~all-zero (benign origins) -> it structurally cannot
    # forecast onset, which is exactly the point.
    origin = seq["test"].meta["origin_risk"].to_numpy(dtype="float32")
    persist = np.repeat(origin[:, None], len(horizons), axis=1)
    evaluate("PERSISTENCE (next = current)", persist, tt, 0.5, horizons)

    # Logistic-regression baseline: flattened L x F history -> per-horizon onset.
    # The fair classical-ML bar the world model must beat (CLAUDE.md rule 2).
    try:
        from sklearn.linear_model import LogisticRegression
        Xtr = W.apply_scaler(seq["train"].x, scaler).reshape(len(seq["train"].x), -1)
        Xte = W.apply_scaler(seq["test"].x, scaler).reshape(len(seq["test"].x), -1)
        lr_prob = np.zeros_like(tt, dtype="float64")
        for i in range(len(horizons)):
            ytr = seq["train"].y_risk[:, i]
            if len(np.unique(ytr)) < 2:
                continue
            lr = LogisticRegression(max_iter=2000, class_weight="balanced")
            lr.fit(Xtr, ytr)
            lr_prob[:, i] = lr.predict_proba(Xte)[:, 1]
        evaluate("LOGISTIC REGRESSION (flattened history)", lr_prob, tt, 0.5, horizons)
    except Exception as exc:  # noqa: BLE001
        print(f"  (LR baseline skipped: {exc})")

    # ---- Save checkpoint (weights + scaler + feature names + config + threshold)
    out_dir = REPO_ROOT / "models" / args.run_name
    out_dir.mkdir(parents=True, exist_ok=True)
    ckpt = out_dir / "best.ckpt"
    torch.save({
        "state_dict": model.state_dict(),
        "model_config": vars(model.get_config()),
        "scaler": scaler,
        "feature_names": list(W.MODEL_COLUMNS),
        "threshold": float(threshold),
        "horizons": horizons,
        "schema_version": unified_schema.SCHEMA_VERSION,
    }, ckpt)
    print(f"\n[save] checkpoint -> {ckpt}")
    print("\nDone.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
