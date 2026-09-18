"""Self-supervised temporal pretraining for the world-model encoder."""

from __future__ import annotations

from dataclasses import dataclass

import torch
from torch import Tensor, nn
import torch.nn.functional as F


@dataclass(frozen=True)
class SelfSupervisedConfig:
    input_size: int
    hidden_size: int = 128
    num_layers: int = 2
    dropout: float = 0.2
    mask_probability: float = 0.15


class TemporalPretrainer(nn.Module):
    """LSTM encoder with masked reconstruction and next-state objectives."""

    def __init__(self, config: SelfSupervisedConfig) -> None:
        super().__init__()
        self.config = config
        drop = config.dropout if config.num_layers > 1 else 0.0
        self.encoder = nn.LSTM(config.input_size, config.hidden_size, config.num_layers,
                               batch_first=True, dropout=drop)
        self.reconstruction = nn.Linear(config.hidden_size, config.input_size)
        self.next_state = nn.Linear(config.hidden_size, config.input_size)
        self.projection = nn.Sequential(nn.Linear(config.hidden_size, config.hidden_size),
                                        nn.ReLU(), nn.Linear(config.hidden_size, 64))

    def forward(self, x: Tensor) -> dict[str, Tensor]:
        encoded, _ = self.encoder(x)
        return {
            "encoded": encoded,
            "reconstruction": self.reconstruction(encoded),
            "next_state": self.next_state(encoded[:, -1]),
            "projection": F.normalize(self.projection(encoded[:, -1]), dim=-1),
        }

    def encoder_state_dict(self) -> dict[str, Tensor]:
        return {k.removeprefix("encoder."): v for k, v in self.state_dict().items()
                if k.startswith("encoder.")}


def masked_temporal_batch(x: Tensor, probability: float = 0.15, *, generator=None) -> tuple[Tensor, Tensor]:
    """Mask feature values while preserving observation-mask columns supplied by callers."""
    if not 0.0 < probability < 1.0:
        raise ValueError("mask probability must be in (0, 1)")
    mask = torch.rand(x.shape, device=x.device, generator=generator) < probability
    masked = x.clone()
    masked[mask] = 0.0
    return masked, mask


def self_supervised_loss(output: dict[str, Tensor], target: Tensor, masked: Tensor,
                         *, reconstruction_weight: float = 1.0,
                         next_weight: float = 1.0,
                         temporal_weight: float = 0.25) -> tuple[Tensor, dict[str, float]]:
    """Calculate masked reconstruction, next-window and temporal-difference loss."""
    mask = masked.bool()
    recon_error = (output["reconstruction"] - target).pow(2)
    reconstruction = recon_error[mask].mean() if mask.any() else recon_error.mean()
    next_target = target[:, -1, :]
    next_loss = F.smooth_l1_loss(output["next_state"], next_target)
    if target.shape[1] > 1:
        target_delta = target[:, 1:, :] - target[:, :-1, :]
        pred_delta = output["reconstruction"][:, 1:, :] - output["reconstruction"][:, :-1, :]
        temporal = F.smooth_l1_loss(pred_delta, target_delta)
    else:
        temporal = torch.zeros((), device=target.device)
    total = reconstruction_weight * reconstruction + next_weight * next_loss + temporal_weight * temporal
    return total, {"reconstruction": float(reconstruction.detach()),
                   "next_state": float(next_loss.detach()), "temporal": float(temporal.detach()),
                   "total": float(total.detach())}


__all__ = ["SelfSupervisedConfig", "TemporalPretrainer", "masked_temporal_batch", "self_supervised_loss"]
