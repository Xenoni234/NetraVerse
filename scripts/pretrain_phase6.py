"""Self-supervised temporal pretraining for Phase 6."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np
import torch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.data.windowing import STATE_FEATURE_COLUMNS, apply_scaler, fit_scaler, load_sequences
from src.models.self_supervised import (SelfSupervisedConfig, TemporalPretrainer,
                                        masked_temporal_batch, self_supervised_loss)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sequence", type=Path, default=Path("data/processed/repaired_train_masked_v2.npz"))
    parser.add_argument("--output", type=Path, default=Path("models/wm_phase6/self_supervised_encoder.pt"))
    parser.add_argument("--epochs", type=int, default=10)
    parser.add_argument("--batch-size", type=int, default=256)
    parser.add_argument("--lr", type=float, default=3e-4)
    parser.add_argument("--seed", type=int, default=1337)
    args = parser.parse_args(argv)
    torch.manual_seed(args.seed)
    np.random.seed(args.seed)
    batch = load_sequences(args.sequence)
    scaler = fit_scaler(batch.x, method="signed_log",
                        mask_tail=batch.x.shape[-1] - len(STATE_FEATURE_COLUMNS))
    x = torch.from_numpy(apply_scaler(batch.x, scaler))
    model = TemporalPretrainer(SelfSupervisedConfig(input_size=x.shape[-1]))
    optimizer = torch.optim.AdamW(model.parameters(), lr=args.lr, weight_decay=1e-4)
    model.train()
    for epoch in range(args.epochs):
        order = torch.randperm(len(x))
        losses = []
        for indices in order.split(args.batch_size):
            target = x[indices]
            masked_x, mask = masked_temporal_batch(target, model.config.mask_probability)
            output = model(masked_x)
            loss, parts = self_supervised_loss(output, target, mask)
            optimizer.zero_grad(set_to_none=True)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            losses.append(parts["total"])
        print(f"[phase6] epoch {epoch + 1}/{args.epochs} loss={sum(losses) / len(losses):.5f}")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    torch.save({"state_dict": model.state_dict(), "encoder_state_dict": model.encoder.state_dict(),
                "config": model.config.__dict__,
                "input_features": list(batch.feature_names), "scaler": scaler,
                "seed": args.seed}, args.output)
    print(f"[phase6] saved {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
