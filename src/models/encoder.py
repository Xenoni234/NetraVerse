"""Observation encoder: window features (+ GraphSAGE context) -> embedding e_t."""
from __future__ import annotations

import torch
from torch import nn

from src.models.gnn import HostSAGE


class Encoder(nn.Module):
    def __init__(self, n_features: int, embed: int = 128, hidden: int = 192,
                 use_gnn: bool = True, gnn_dim: int = 32):
        super().__init__()
        self.use_gnn = use_gnn
        self.gnn = HostSAGE(n_features, gnn_dim) if use_gnn else None
        inp = n_features + (gnn_dim if use_gnn else 0)
        self.net = nn.Sequential(
            nn.Linear(inp, hidden), nn.LayerNorm(hidden), nn.SiLU(),
            nn.Linear(hidden, embed), nn.LayerNorm(embed), nn.SiLU(),
        )

    def forward(self, x: torch.Tensor, nb: torch.Tensor | None = None) -> torch.Tensor:
        if self.use_gnn:
            if nb is None:
                nb = torch.zeros(*x.shape[:-1], 2 * x.shape[-1] + 1, device=x.device)
            x = torch.cat([x, self.gnn(x, nb)], dim=-1)
        return self.net(x)
