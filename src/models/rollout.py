"""K-step latent rollout - the one forecasting function every input mode uses (R7).

    rollout(model, state, horizon, intervention=None) -> RolloutResult

``state`` is the current latent state from ``WorldModel.encode``. The rollout
never looks at observations: it only runs the learned prior transition
P(s_t+1 | s_t) forward and decodes each imagined state (FR8/FR9).
"""
from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np
import torch

from src.features.schema import WINDOW_S
from src.models.transition import LatentState
from src.models.world_model import WorldModel


@dataclass
class Intervention:
    """A defender action already applied to the latent state by decision.counterfactual."""
    action_id: str
    state: LatentState


@dataclass
class RolloutResult:
    probs: list[float]                  # P(attack) at t+1..t+K (mean over MC samples)
    lo: list[float]                     # 10th percentile band
    hi: list[float]                     # 90th percentile band
    stages: list[int]                   # argmax stage per step
    stage_probs: list[list[float]]
    horizon_s: list[int]                # seconds ahead of each step
    peak: float
    intervention: str | None = None
    driving_features: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@torch.no_grad()
def rollout(model: WorldModel, state: LatentState, horizon: int, intervention: Intervention | None = None,
            mc: int = 16, window_s: int = WINDOW_S) -> RolloutResult:
    """Imagine ``horizon`` steps from a single latent state (batch of 1)."""
    if intervention is not None:
        state = intervention.state
    rep = state.repeat(mc)
    imag = model.imagine(rep, horizon, sample=True)
    dec = model.decode(imag)
    p = torch.sigmoid(dec["risk_logit"]).cpu().numpy()          # [mc, K]
    sp = torch.softmax(dec["stage_logit"], -1).mean(0).cpu().numpy()   # [K, S]
    mean = p.mean(0)
    return RolloutResult(
        probs=[round(float(v), 4) for v in mean],
        lo=[round(float(v), 4) for v in np.percentile(p, 10, axis=0)],
        hi=[round(float(v), 4) for v in np.percentile(p, 90, axis=0)],
        stages=[int(v) for v in sp.argmax(-1)],
        stage_probs=[[round(float(u), 4) for u in row] for row in sp],
        horizon_s=[window_s * (k + 1) for k in range(horizon)],
        peak=round(float(mean.max()), 4),
        intervention=intervention.action_id if intervention else None,
    )


@torch.no_grad()
def batch_forecast(model: WorldModel, x: torch.Tensor, nb: torch.Tensor | None, history: int,
                   horizon: int, mc: int = 1) -> dict[str, np.ndarray]:
    """Vectorised forecast for many histories at once. x: [N, L, F].

    Returns ``future`` [N, K] risk, ``now`` [N] posterior risk at the last
    observed step, ``stage_future`` [N, K] and ``stage_now`` [N].
    """
    states, _, _ = model.filter(x[:, :history], None if nb is None else nb[:, :history], sample=False)
    now = model.decode([states[-1]])
    s = states[-1]
    if mc > 1:
        s = s.repeat(mc)
    imag = model.imagine(s, horizon, sample=mc > 1)
    dec = model.decode(imag)
    p = torch.sigmoid(dec["risk_logit"])
    sp = torch.softmax(dec["stage_logit"], -1)
    lo = hi = None
    if mc > 1:
        pm = p.view(-1, mc, horizon)
        lo = torch.quantile(pm, 0.1, dim=1).cpu().numpy()
        hi = torch.quantile(pm, 0.9, dim=1).cpu().numpy()
        p = pm.mean(1)
        sp = sp.view(-1, mc, horizon, sp.shape[-1]).mean(1)
    return {
        "future": p.cpu().numpy(), "lo": lo, "hi": hi,
        "now": torch.sigmoid(now["risk_logit"][:, 0]).cpu().numpy(),
        "stage_future": sp.argmax(-1).cpu().numpy(),
        "stage_future_probs": sp.cpu().numpy(),
        "stage_now": now["stage_logit"][:, 0].argmax(-1).cpu().numpy(),
    }
