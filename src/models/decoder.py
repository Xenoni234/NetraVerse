"""Decoder heads on the latent state s_t = [h_t, z_t].

* observation head: reconstructs/predicts the window feature vector x_t
* risk head:        P(host is in attacker-involved activity at step t)
* stage head:       MITRE ATT&CK stage distribution (7 classes)

Every probability shown to the analyst is decoded from a latent state - for the
forecast, from an imagined (prior-only) future state.
"""
from __future__ import annotations

import torch
from torch import nn


class Decoder(nn.Module):
    def __init__(self, feat_dim: int, n_features: int, n_stages: int = 7, hidden: int = 192):
        super().__init__()
        self.trunk = nn.Sequential(nn.Linear(feat_dim, hidden), nn.LayerNorm(hidden), nn.SiLU(),
                                   nn.Linear(hidden, hidden), nn.SiLU())
        self.obs = nn.Linear(hidden, n_features)
        self.risk = nn.Linear(hidden, 1)
        self.stage = nn.Linear(hidden, n_stages)

    def forward(self, feat: torch.Tensor) -> dict[str, torch.Tensor]:
        t = self.trunk(feat)
        return {"obs": self.obs(t), "risk_logit": self.risk(t).squeeze(-1), "stage_logit": self.stage(t)}
