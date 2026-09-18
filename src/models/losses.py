"""The combined multitask loss over the state, risk and stage heads.

``L = λ_state · L_state + λ_risk · L_risk + λ_stage · L_stage`` (CLAUDE.md §8),
summed over the horizons ``K``.

- ``L_state`` — Gaussian negative log-likelihood over the predicted future feature
  vectors. Rewards honest uncertainty, not just accurate means (Member 4 §4.2).
- ``L_risk`` — ``BCEWithLogits`` with a positive-class weight, because attack
  windows are a tiny minority.
- ``L_stage`` — cross-entropy over the 6 stages, **masking** windows whose stage
  is ``STAGE_MASKED`` (-1) — DoS/DDoS attacks that have no stage but are still
  real attacks (CLAUDE.md §10-E).
"""

from __future__ import annotations

from dataclasses import dataclass

import torch
from torch import Tensor, nn
import torch.nn.functional as F

from src.mitre.stage_mapping import STAGE_MASKED


@dataclass(frozen=True)
class LossWeights:
    """Fixed task weights (CLAUDE.md §8: 1.0 / 2.0 / 1.0)."""

    state: float = 1.0
    risk: float = 2.0
    stage: float = 1.0
    attention: float = 0.0


def gaussian_nll(mean: Tensor, logvar: Tensor, target: Tensor) -> Tensor:
    """Mean Gaussian NLL: 0.5 · [logσ² + (y−μ)²/σ²]. Shapes broadcast, mean-reduced."""
    inv_var = torch.exp(-logvar)
    return 0.5 * (logvar + (target - mean) ** 2 * inv_var).mean()


def _focal_bce(logits: Tensor, target: Tensor, *, gamma: float = 2.0,
               pos_weight: Tensor | None = None) -> Tensor:
    """Focal binary loss (Lin et al.): down-weights easy examples so the rare
    positive class isn't drowned out. ``gamma=0`` reduces to weighted BCE."""
    bce = F.binary_cross_entropy_with_logits(logits, target, pos_weight=pos_weight, reduction="none")
    p = torch.sigmoid(logits)
    p_t = p * target + (1 - p) * (1 - target)          # prob of the true class
    return ((1 - p_t) ** gamma * bce).mean()


class MultiTaskLoss(nn.Module):
    """Weighted sum of state (Gaussian NLL), risk (BCE) and stage (masked CE) losses.

    Args:
        weights: Per-task weights.
        pos_weight: Positive-class weight for the risk BCE (fit on train).
        stage_class_weights: Optional ``(n_stages,)`` weights for the stage CE.
        stage_enabled: When False (e.g. the benign-only pretrain), the stage term
            is skipped entirely.
    """

    def __init__(
        self,
        weights: LossWeights | None = None,
        *,
        pos_weight: float | None = None,
        stage_class_weights: Tensor | None = None,
        state_enabled: bool = True,
        risk_enabled: bool = True,
        stage_enabled: bool = True,
        risk_loss: str = "bce",
        focal_gamma: float = 2.0,
        attention_enabled: bool = False,
    ) -> None:
        super().__init__()
        self.w = weights or LossWeights()
        self.state_enabled = state_enabled
        self.risk_enabled = risk_enabled
        self.stage_enabled = stage_enabled
        if risk_loss not in ("bce", "focal"):
            raise ValueError(f"risk_loss must be 'bce' or 'focal', got {risk_loss!r}")
        self.risk_loss = risk_loss
        self.focal_gamma = focal_gamma
        self.attention_enabled = attention_enabled
        self.register_buffer(
            "pos_weight",
            torch.tensor(float(pos_weight)) if pos_weight is not None else None,
            persistent=False,
        )
        if stage_class_weights is not None:
            self.register_buffer("stage_class_weights", stage_class_weights, persistent=False)
        else:
            self.stage_class_weights = None

    def forward(
        self,
        predictions: dict[str, Tensor],
        targets: dict[str, Tensor],
    ) -> tuple[Tensor, dict[str, float]]:
        """Compute total loss + per-component floats for logging.

        Expected shapes (B, K, ...):
            predictions: ``state_mean``/``state_logvar`` (B,K,S),
                ``risk_logits`` (B,K), ``stage_logits`` (B,K,C).
            targets: ``state`` (B,K,S), ``risk`` (B,K), ``stage`` (B,K) int64.
        """
        device = predictions["risk_logits"].device
        total = torch.zeros((), device=device)
        parts: dict[str, float] = {}

        if self.state_enabled and "state_mean" in predictions:
            l_state = gaussian_nll(
                predictions["state_mean"], predictions["state_logvar"], targets["state"]
            )
            total = total + self.w.state * l_state
            parts["state"] = float(l_state.detach())

        if self.risk_enabled:
            logits, tgt = predictions["risk_logits"], targets["risk"].float()
            if self.risk_loss == "focal":
                l_risk = _focal_bce(logits, tgt, gamma=self.focal_gamma, pos_weight=self.pos_weight)
            else:
                l_risk = F.binary_cross_entropy_with_logits(logits, tgt, pos_weight=self.pos_weight)
            total = total + self.w.risk * l_risk
            parts["risk"] = float(l_risk.detach())

        if self.stage_enabled:
            logits = predictions["stage_logits"]
            b, k, c = logits.shape
            flat_logits = logits.reshape(b * k, c)
            flat_tgt = targets["stage"].reshape(b * k).long()
            valid = flat_tgt != STAGE_MASKED
            if valid.any():
                l_stage = F.cross_entropy(
                    flat_logits[valid], flat_tgt[valid],
                    weight=self.stage_class_weights,
                )
                total = total + self.w.stage * l_stage
                parts["stage"] = float(l_stage.detach())
            else:
                parts["stage"] = 0.0

        # Optional temporal-focus supervision.  Targets are distributions over
        # the history axis (B, K, L), normally centred on the precursor/ramp
        # window.  This is deliberately a small regulariser: attention remains
        # an explanation signal, never a causal label.
        if self.attention_enabled and self.w.attention > 0 and "attn_weights" in predictions and "attention" in targets:
            attn = predictions["attn_weights"].clamp_min(1e-8)
            target = targets["attention"].to(device=device, dtype=attn.dtype)
            l_attention = -(target * attn.log()).sum(dim=-1).mean()
            total = total + self.w.attention * l_attention
            parts["attention"] = float(l_attention.detach())

        parts["total"] = float(total.detach())
        return total, parts


def pos_weight_from_labels(y_risk) -> float:
    """``n_negative / n_positive`` for the risk BCE, computed on train labels."""
    import numpy as np

    y = np.asarray(y_risk).ravel()
    n_pos = float((y > 0.5).sum())
    n_neg = float(y.size - n_pos)
    return (n_neg / n_pos) if n_pos > 0 else 1.0


__all__ = ["LossWeights", "MultiTaskLoss", "gaussian_nll", "pos_weight_from_labels"]
