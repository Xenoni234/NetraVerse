"""GraphSAGE host-graph layer (Phase 5).

h_i = ReLU( W_self x_i + W_mean mean_{j in N(i)} x_j + W_max max_{j in N(i)} x_j + w_deg log(1+|N(i)|) )

Neighbourhoods are the hosts a host exchanged flows with in the same 60 s
window (``graph.graph_utils.neighbor_aggregate``). The embedding is concatenated
into the world-model encoder input so multi-host context (who is talking to a
compromised host, lateral spread) reaches the latent dynamics.
"""
from __future__ import annotations

import torch
from torch import nn


class HostSAGE(nn.Module):
    def __init__(self, n_features: int, dim: int = 32):
        super().__init__()
        self.self_lin = nn.Linear(n_features, dim)
        self.mean_lin = nn.Linear(n_features, dim, bias=False)
        self.max_lin = nn.Linear(n_features, dim, bias=False)
        self.deg_lin = nn.Linear(1, dim, bias=False)
        self.norm = nn.LayerNorm(dim)
        self.n_features = n_features

    def forward(self, x: torch.Tensor, nb: torch.Tensor) -> torch.Tensor:
        f = self.n_features
        h = (self.self_lin(x) + self.mean_lin(nb[..., :f]) + self.max_lin(nb[..., f:2 * f])
             + self.deg_lin(nb[..., -1:]))
        return torch.relu(self.norm(h))
