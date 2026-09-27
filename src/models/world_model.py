"""World model = Encoder (+GraphSAGE) -> RSSM-lite Transition -> Decoder.

Training objective per sequence of T = L + K windows:

1. *Filtering* over all T observed steps (posterior): reconstruct x_t, KL(q||p),
   risk_t and stage_t on the current step.
2. *Imagination* from step L with the prior only for K steps (no observations):
   predict x_{L+k}, risk_{L+k}, stage_{L+k}. This is the supervised dynamics
   signal that trains the 300 s rollout directly (latent overshooting).
"""
from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import torch
import torch.nn.functional as F
from torch import nn

from src.features.schema import FEATURE_COLUMNS, LOG_FEATURES, N_FEATURES
from src.models.decoder import Decoder
from src.models.encoder import Encoder
from src.models.transition import LatentState, Transition


# ---------------------------------------------------------------- feature scaling
@dataclass
class FeatureScaler:
    """log1p on heavy-tailed counts, optional per-capture robust normalisation, then z-score.

    ``capture_norm`` (R4 experiment): each capture/file/live buffer is first centred on its
    own median and scaled by its own IQR (computed on active windows, no labels), so the
    model sees "how unusual is this host for THIS network" rather than absolute volumes
    that differ between lab testbeds.
    """
    mean: np.ndarray
    std: np.ndarray
    capture_norm: bool = False

    LOG_IDX = np.array([i for i, c in enumerate(FEATURE_COLUMNS) if c in LOG_FEATURES])
    MASK_IDX = np.array([i for i, c in enumerate(FEATURE_COLUMNS) if c.endswith("_mask")])
    VAL_IDX = np.array([i for i, c in enumerate(FEATURE_COLUMNS) if not c.endswith("_mask")])
    ACT_IDX = np.array([FEATURE_COLUMNS.index("out_flows"), FEATURE_COLUMNS.index("in_flows")])

    @classmethod
    def _pre(cls, x: np.ndarray, groups: np.ndarray | None = None, capture_norm: bool = False) -> np.ndarray:
        t = np.array(x, dtype=np.float32, copy=True)
        t[:, cls.LOG_IDX] = np.log1p(np.clip(t[:, cls.LOG_IDX], 0, None))
        if capture_norm:
            g = np.zeros(len(t), dtype=np.int64) if groups is None else np.asarray(groups)
            active = x[:, cls.ACT_IDX].sum(1) > 0
            for k in np.unique(g):
                m = g == k
                ref = t[m & active][:, cls.VAL_IDX]
                if len(ref) < 5:
                    ref = t[m][:, cls.VAL_IDX]
                med = np.median(ref, axis=0)
                iqr = np.subtract(*np.percentile(ref, [75, 25], axis=0))
                t[np.ix_(m, cls.VAL_IDX)] = (t[np.ix_(m, cls.VAL_IDX)] - med) / np.maximum(iqr, 0.25)
        return t

    @classmethod
    def fit(cls, x: np.ndarray, groups: np.ndarray | None = None, capture_norm: bool = False) -> "FeatureScaler":
        t = cls._pre(x, groups, capture_norm)
        mean, std = t.mean(0), t.std(0) + 1e-6
        mean[cls.MASK_IDX] = 0.0
        std[cls.MASK_IDX] = 1.0
        return cls(mean.astype(np.float32), std.astype(np.float32), capture_norm)

    def transform(self, x: np.ndarray, groups: np.ndarray | None = None) -> np.ndarray:
        t = self._pre(x, groups, self.capture_norm)
        return np.clip((t - self.mean) / self.std, -10, 10).astype(np.float32)

    def to_dict(self) -> dict:
        return {"mean": self.mean.tolist(), "std": self.std.tolist(), "capture_norm": self.capture_norm}

    @classmethod
    def from_dict(cls, d: dict) -> "FeatureScaler":
        return cls(np.asarray(d["mean"], np.float32), np.asarray(d["std"], np.float32),
                   bool(d.get("capture_norm", False)))


# ---------------------------------------------------------------- model
class WorldModel(nn.Module):
    def __init__(self, cfg: dict):
        super().__init__()
        m = cfg["model"]
        self.cfg = cfg
        self.encoder = Encoder(N_FEATURES, m["embed"], m["hidden"], m["gnn"], m["gnn_dim"])
        self.transition = Transition(m["embed"], m["deter"], m["stoch"], m["hidden"], m["min_std"])
        self.decoder = Decoder(m["deter"] + m["stoch"], N_FEATURES, m["n_stages"], m["hidden"])

    # -- filtering -----------------------------------------------------------
    def filter(self, x: torch.Tensor, nb: torch.Tensor | None, sample: bool = True):
        """x: [B, T, F]. Returns per-step states and prior/posterior params."""
        b, t, _ = x.shape
        e = self.encoder(x, nb)
        state = self.transition.initial(b, x.device)
        states, priors, posts = [], [], []
        for i in range(t):
            state, pr, po = self.transition.observe(state, e[:, i], sample=sample)
            states.append(state); priors.append(pr); posts.append(po)
        return states, priors, posts

    @torch.no_grad()
    def encode(self, x: torch.Tensor, nb: torch.Tensor | None = None) -> LatentState:
        """Filter the history (posterior means) and return the current latent state."""
        states, _, _ = self.filter(x, nb, sample=False)
        return states[-1]

    def imagine(self, state: LatentState, horizon: int, sample: bool = True) -> list[LatentState]:
        out = []
        for _ in range(horizon):
            state = self.transition.imagine(state, sample=sample)
            out.append(state)
        return out

    def decode(self, states: list[LatentState]) -> dict[str, torch.Tensor]:
        feat = torch.stack([s.feat() for s in states], dim=1)
        return self.decoder(feat)

    # -- training loss ---------------------------------------------------------
    def loss(self, x, nb, risk_y, stage_y, history: int, horizon: int, pos_weight: float,
             sample_w: torch.Tensor | None = None) -> dict:
        tr = self.cfg["train"]
        states, priors, posts = self.filter(x, nb, sample=True)
        dec = self.decode(states)
        pw = torch.tensor(pos_weight, device=x.device)

        # 1) filtering losses on every observed step
        recon = F.mse_loss(dec["obs"], x)
        pm = torch.stack([p[0] for p in priors], 1); ps = torch.stack([p[1] for p in priors], 1)
        qm = torch.stack([q[0] for q in posts], 1); qs = torch.stack([q[1] for q in posts], 1)
        kl = (torch.log(ps / qs) + (qs ** 2 + (qm - pm) ** 2) / (2 * ps ** 2) - 0.5).sum(-1)
        kl = torch.clamp(kl.mean(), min=tr["free_nats"])
        risk_now = F.binary_cross_entropy_with_logits(dec["risk_logit"], risk_y, pos_weight=pw)
        stage_now = F.cross_entropy(dec["stage_logit"].reshape(-1, dec["stage_logit"].shape[-1]),
                                    stage_y.reshape(-1))

        # 2) imagination: prior-only rollout from the end of history
        imag = self.imagine(states[history - 1], horizon, sample=True)
        di = self.decode(imag)
        fut = slice(history, history + horizon)
        recon_f = F.mse_loss(di["obs"], x[:, fut])
        risk_f = F.binary_cross_entropy_with_logits(di["risk_logit"], risk_y[:, fut], pos_weight=pw,
                                                    reduction="none").mean(1)
        risk_f = (risk_f * sample_w).sum() / sample_w.sum() if sample_w is not None else risk_f.mean()
        stage_f = F.cross_entropy(di["stage_logit"].reshape(-1, di["stage_logit"].shape[-1]),
                                  stage_y[:, fut].reshape(-1))

        total = (tr["recon_weight"] * (recon + recon_f) + tr["kl_weight"] * kl
                 + tr["risk_weight"] * (0.5 * risk_now + risk_f)
                 + tr["stage_weight"] * (0.5 * stage_now + stage_f))
        return {"total": total, "recon": recon.detach(), "recon_f": recon_f.detach(), "kl": kl.detach(),
                "risk_now": risk_now.detach(), "risk_f": risk_f.detach(), "stage_f": stage_f.detach()}


# ---------------------------------------------------------------- persistence
def save_checkpoint(path, model: WorldModel, scaler: FeatureScaler, extra: dict) -> None:
    torch.save({"state_dict": model.state_dict(), "config": model.cfg, "scaler": scaler.to_dict(),
                "feature_columns": FEATURE_COLUMNS, **extra}, path)


def load_checkpoint(path, device: str | torch.device = "cpu") -> tuple[WorldModel, FeatureScaler, dict]:
    ck = torch.load(path, map_location=device, weights_only=False)
    if ck["feature_columns"] != FEATURE_COLUMNS:
        raise RuntimeError("Checkpoint feature schema does not match src/features/schema.py")
    model = WorldModel(ck["config"]).to(device)
    model.load_state_dict(ck["state_dict"])
    model.eval()
    return model, FeatureScaler.from_dict(ck["scaler"]), ck
