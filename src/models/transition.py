"""RSSM-lite latent transition: P(s_t+1 | s_t) with s = (h deterministic, z stochastic).

    h_t   = GRUCell([z_{t-1}], h_{t-1})              deterministic path
    prior      p(z_t | h_t)        = N(mu_p, sigma_p)  used for imagination / rollout
    posterior  q(z_t | h_t, e_t)   = N(mu_q, sigma_q)  used when an observation exists

Training minimises KL(q || p) so the prior alone can carry the state forward -
this is what makes the rollout a learned transition model rather than a
regression from features to probability (rules.md R8).
"""
from __future__ import annotations

from dataclasses import dataclass

import torch
import torch.nn.functional as F
from torch import nn


@dataclass
class LatentState:
    h: torch.Tensor   # [B, deter]
    z: torch.Tensor   # [B, stoch]

    def feat(self) -> torch.Tensor:
        return torch.cat([self.h, self.z], dim=-1)

    def detach(self) -> "LatentState":
        return LatentState(self.h.detach(), self.z.detach())

    def repeat(self, n: int) -> "LatentState":
        return LatentState(self.h.repeat_interleave(n, 0), self.z.repeat_interleave(n, 0))


class Transition(nn.Module):
    def __init__(self, embed: int = 128, deter: int = 192, stoch: int = 32, hidden: int = 192,
                 min_std: float = 0.1):
        super().__init__()
        self.deter, self.stoch, self.min_std = deter, stoch, min_std
        self.inp = nn.Sequential(nn.Linear(stoch, hidden), nn.SiLU())
        self.gru = nn.GRUCell(hidden, deter)
        self.prior_net = nn.Sequential(nn.Linear(deter, hidden), nn.SiLU(), nn.Linear(hidden, 2 * stoch))
        self.post_net = nn.Sequential(nn.Linear(deter + embed, hidden), nn.SiLU(),
                                      nn.Linear(hidden, 2 * stoch))

    def initial(self, batch: int, device) -> LatentState:
        return LatentState(torch.zeros(batch, self.deter, device=device),
                           torch.zeros(batch, self.stoch, device=device))

    def _dist(self, out: torch.Tensor) -> tuple[torch.Tensor, torch.Tensor]:
        mu, s = out.chunk(2, dim=-1)
        return mu, F.softplus(s) + self.min_std

    def step_h(self, prev: LatentState) -> torch.Tensor:
        return self.gru(self.inp(prev.z), prev.h)

    def prior(self, h: torch.Tensor):
        return self._dist(self.prior_net(h))

    def posterior(self, h: torch.Tensor, e: torch.Tensor):
        return self._dist(self.post_net(torch.cat([h, e], dim=-1)))

    def observe(self, prev: LatentState, e: torch.Tensor, sample: bool = True):
        """One filtering step with an observation. Returns state, (prior), (posterior)."""
        h = self.step_h(prev)
        pm, ps = self.prior(h)
        qm, qs = self.posterior(h, e)
        z = qm + qs * torch.randn_like(qs) if sample else qm
        return LatentState(h, z), (pm, ps), (qm, qs)

    def imagine(self, prev: LatentState, sample: bool = True) -> LatentState:
        """One transition with no observation - the world model's own prediction."""
        h = self.step_h(prev)
        pm, ps = self.prior(h)
        z = pm + ps * torch.randn_like(ps) if sample else pm
        return LatentState(h, z)
