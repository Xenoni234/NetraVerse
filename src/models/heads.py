"""The three output heads on top of the decoder hidden state.

- :class:`StateHead` predicts the next feature vector as ``(mean, log_variance)``
  per feature → trained with Gaussian NLL (the world-model dynamics head).
- :class:`RiskHead` predicts attack probability → a single **logit** (BCE).
- :class:`StageHead` predicts the ATT&CK stage → logits over 6 classes (CE).

Heads emit **logits / raw parameters**, never squashed probabilities — sigmoid
and softmax live in the loss (for numerical stability) and the inference layer
(for display). See CLAUDE.md §8.
"""

from __future__ import annotations

import torch
from torch import Tensor, nn


class StateHead(nn.Module):
    """Predicts the next state as a per-feature Gaussian ``(mean, log_variance)``.

    Args:
        hidden_size: Decoder hidden width ``H``.
        state_size: Number of continuous features to predict (excludes masks).
        dropout: Dropout probability (also used for MC-dropout at inference).
        logvar_min/logvar_max: Clamp bounds on log-variance, so NLL cannot blow up
            on a near-constant feature.
    """

    def __init__(
        self,
        hidden_size: int,
        state_size: int,
        *,
        dropout: float = 0.1,
        logvar_min: float = -8.0,
        logvar_max: float = 8.0,
    ) -> None:
        super().__init__()
        self.state_size = state_size
        self.logvar_min = logvar_min
        self.logvar_max = logvar_max
        self.body = nn.Sequential(
            nn.Linear(hidden_size, hidden_size),
            nn.GELU(),
            nn.Dropout(dropout),
        )
        self.mean = nn.Linear(hidden_size, state_size)
        self.logvar = nn.Linear(hidden_size, state_size)

    def forward(self, hidden: Tensor) -> tuple[Tensor, Tensor]:
        """Return ``(mean, log_variance)``, each ``(B, state_size)``."""
        h = self.body(hidden)
        logvar = self.logvar(h).clamp(self.logvar_min, self.logvar_max)
        return self.mean(h), logvar


class RiskHead(nn.Module):
    """Predicts attack probability — a single logit per sample."""

    def __init__(self, hidden_size: int, *, dropout: float = 0.1) -> None:
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(hidden_size, hidden_size),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_size, 1),
        )

    def forward(self, hidden: Tensor) -> Tensor:
        """Return ``(B,)`` risk logits."""
        return self.net(hidden).squeeze(-1)

    @staticmethod
    def to_probability(logits: Tensor) -> Tensor:
        return torch.sigmoid(logits)


class StageHead(nn.Module):
    """Predicts the MITRE ATT&CK stage — logits over ``n_stages`` classes."""

    def __init__(self, hidden_size: int, n_stages: int = 6, *, dropout: float = 0.1) -> None:
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(hidden_size, hidden_size),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_size, n_stages),
        )

    def forward(self, hidden: Tensor) -> Tensor:
        """Return ``(B, n_stages)`` stage logits."""
        return self.net(hidden)

    @staticmethod
    def to_probability(logits: Tensor) -> Tensor:
        return torch.softmax(logits, dim=-1)


__all__ = ["StateHead", "RiskHead", "StageHead"]
