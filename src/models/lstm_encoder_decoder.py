"""The world model: LSTM encoder-decoder with three heads and K-step rollout.

Encoder reads ``L`` past state vectors into a context; the decoder unrolls
``rollout_steps`` future steps autoregressively, feeding each predicted state
back in as the next input. Scheduled sampling (during training) mixes the model's
own prediction with the ground-truth next state so it learns to recover from its
own errors (Member 4 §3.5).

Feedback detail: the state head predicts the ``state_size`` continuous features
(``STATE_FEATURE_COLUMNS``); the decoder input is the full ``input_size`` vector
(features + mask flags). On autoregressive steps the predicted means fill the
feature slots and the previous step's mask flags are carried forward.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Sequence

import torch
from torch import Tensor, nn

from src.models.heads import RiskHead, StageHead, StateHead


@dataclass(frozen=True)
class WorldModelConfig:
    """Hyperparameters for :class:`WorldModel`."""

    input_size: int          # F — full state vector width (features + masks)
    state_size: int          # continuous features the state head predicts
    hidden_size: int = 128
    num_layers: int = 2
    dropout: float = 0.2
    horizons: tuple[int, ...] = (1, 2, 4)
    rollout_steps: int = 4
    n_stages: int = 7
    use_attention: bool = True   # temporal attention over encoder states (explainability)
    residual_state: bool = False
    temporal_deltas: bool = False
    cumulative_risk: bool = False
    near_horizons: tuple[int, ...] = (1, 2, 4, 8)
    direct_horizons: tuple[int, ...] = (16, 30, 60)

    @property
    def n_mask(self) -> int:
        return self.input_size - self.state_size


class WorldModel(nn.Module):
    """Encoder-decoder world model with state, risk and stage heads."""

    def __init__(self, config: WorldModelConfig) -> None:
        super().__init__()
        self.config = config
        drop = config.dropout if config.num_layers > 1 else 0.0
        self.encoder = nn.LSTM(
            config.input_size * (2 if config.temporal_deltas else 1), config.hidden_size, config.num_layers,
            batch_first=True, dropout=drop,
        )
        self.decoder = nn.LSTM(
            config.input_size, config.hidden_size, config.num_layers,
            batch_first=True, dropout=drop,
        )
        # Temporal attention: at each decoder step, attend over the encoder's
        # per-window hidden states so the heads (and explanations) can point at
        # WHICH history windows drove the forecast (PS: attention-based explainability).
        self.use_attention = config.use_attention
        if self.use_attention:
            self.attn_q = nn.Linear(config.hidden_size, config.hidden_size, bias=False)
            self.attn_k = nn.Linear(config.hidden_size, config.hidden_size, bias=False)
            self.attn_combine = nn.Linear(config.hidden_size * 2, config.hidden_size)

        self.state_head = StateHead(config.hidden_size, config.state_size, dropout=config.dropout)
        self.risk_head = RiskHead(config.hidden_size, dropout=config.dropout)
        self.stage_head = StageHead(config.hidden_size, config.n_stages, dropout=config.dropout)
        self.direct_horizons = tuple(k for k in config.direct_horizons if k in config.horizons)
        self.near_horizons = tuple(k for k in config.near_horizons if k in config.horizons)
        if self.direct_horizons:
            self.direct_query = nn.Embedding(max(self.direct_horizons) + 1, config.hidden_size)
            self.direct_fuse = nn.Sequential(
                nn.Linear(config.hidden_size * 3, config.hidden_size), nn.Tanh(),
                nn.Dropout(config.dropout),
            )
            self.direct_state_head = StateHead(config.hidden_size, config.state_size, dropout=config.dropout)
            self.direct_risk_head = RiskHead(config.hidden_size, dropout=config.dropout)
            self.direct_stage_head = StageHead(config.hidden_size, config.n_stages, dropout=config.dropout)
        if config.residual_state:
            nn.init.zeros_(self.state_head.mean.weight)
            nn.init.zeros_(self.state_head.mean.bias)
        if config.cumulative_risk:
            nn.init.constant_(self.risk_head.net[-1].bias, -5.0)

    # -- construction helpers ------------------------------------------------ #

    @classmethod
    def from_config(cls, config: Mapping[str, object] | WorldModelConfig) -> "WorldModel":
        if isinstance(config, WorldModelConfig):
            return cls(config)
        known = WorldModelConfig.__dataclass_fields__
        kw = {k: v for k, v in dict(config).items() if k in known}
        if "horizons" in kw and kw["horizons"] is not None:
            kw["horizons"] = tuple(kw["horizons"])
        return cls(WorldModelConfig(**kw))  # type: ignore[arg-type]

    def get_config(self) -> WorldModelConfig:
        return self.config

    def load_pretrained_encoder(self, state_dict: Mapping[str, Tensor], *, strict: bool = True) -> None:
        """Load encoder-only weights produced by Phase 6 self-supervised pretraining."""
        current = self.encoder.state_dict()
        compatible = {k: v for k, v in state_dict.items()
                      if k in current and tuple(v.shape) == tuple(current[k].shape)}
        missing = [key for key in current if key not in compatible]
        unexpected = [key for key in state_dict if key not in current or key not in compatible]
        if strict and (missing or unexpected):
            raise RuntimeError(f"encoder checkpoint mismatch: missing={missing}, unexpected={unexpected}")
        self.encoder.load_state_dict(compatible, strict=False)

    # -- forward ------------------------------------------------------------- #

    def forward(
        self,
        x: Tensor,
        *,
        targets: Tensor | None = None,
        sampling_prob: float = 1.0,
        n_steps: int | None = None,
    ) -> dict[str, Tensor]:
        """Encode ``x`` and decode the future.

        Args:
            x: ``(B, L, F)`` history.
            targets: ``(B, n_steps, F)`` ground-truth future frames, used for
                teacher forcing during training. Ignored in ``eval()``.
            sampling_prob: probability of feeding the model's **own** prediction
                back (scheduled sampling). 1.0 = fully free-running. In ``eval()``
                the model always free-runs regardless.
            n_steps: steps to unroll; defaults to ``rollout_steps``.

        Returns:
            ``state_mean``/``state_logvar`` ``(B, |K|, state_size)``,
            ``risk_logits`` ``(B, |K|)``, ``stage_logits`` ``(B, |K|, n_stages)``.
            (Sliced to the LOCKED horizons ``K``.)
        """
        cfg = self.config
        steps = n_steps or max(cfg.rollout_steps, max(cfg.near_horizons, default=0))
        enc_input = x
        if cfg.temporal_deltas:
            delta = torch.cat([torch.zeros_like(x[:, :1]), x[:, 1:] - x[:, :-1]], dim=1)
            enc_input = torch.cat([x, delta], dim=-1)
        enc_out, (h, c) = self.encoder(enc_input)

        prev = x[:, -1, :]                     # (B, F) last observed frame
        free_run = (not self.training) or (targets is None)

        attn_keys = self.attn_k(enc_out) if self.use_attention else None  # (B, L, H)
        scale = cfg.hidden_size ** 0.5

        means, logvars, risks, stages, attns = [], [], [], [], []
        log_survival = torch.zeros(x.size(0), device=x.device, dtype=x.dtype)
        for step in range(steps):
            out, (h, c) = self.decoder(prev.unsqueeze(1), (h, c))
            hidden = out[:, -1, :]             # (B, H)
            if self.use_attention:
                q = self.attn_q(hidden).unsqueeze(1)               # (B, 1, H)
                scores = torch.bmm(q, attn_keys.transpose(1, 2)).squeeze(1) / scale  # (B, L)
                weights = torch.softmax(scores, dim=-1)            # (B, L)
                context = torch.bmm(weights.unsqueeze(1), enc_out).squeeze(1)  # (B, H)
                hidden = torch.tanh(self.attn_combine(torch.cat([hidden, context], dim=-1)))
                attns.append(weights)
            mean, logvar = self.state_head(hidden)
            if cfg.residual_state:
                mean = prev[:, :cfg.state_size] + mean
            means.append(mean)
            logvars.append(logvar)
            risk_logit = self.risk_head(hidden)
            if cfg.cumulative_risk:
                log_survival = log_survival + torch.nn.functional.logsigmoid(-risk_logit)
                risk_logit = torch.log((-torch.expm1(log_survival)).clamp_min(1e-12)) - log_survival
            risks.append(risk_logit)
            stages.append(self.stage_head(hidden))

            # Build the next decoder input.
            masks = prev[:, cfg.state_size:]   # carry previous mask flags
            pred_frame = torch.cat([mean, masks], dim=-1)
            if free_run:
                prev = pred_frame
            else:
                gt_frame = targets[:, step, :]
                use_own = (torch.rand(x.size(0), 1, device=x.device) < sampling_prob).float()
                prev = use_own * pred_frame + (1.0 - use_own) * gt_frame

        near = {
            "state_mean": torch.stack(means, dim=1),
            "state_logvar": torch.stack(logvars, dim=1),
            "risk_logits": torch.stack(risks, dim=1),
            "stage_logits": torch.stack(stages, dim=1),
        }
        if self.direct_horizons:
            # Direct heads use the complete encoder context and a horizon query.
            # They avoid accumulating 60 autoregressive state errors while still
            # sharing the temporal representation learned by the near-term path.
            context = torch.cat([h[-1], enc_out.mean(dim=1)], dim=-1)
            d_states, d_logvars, d_risks, d_stages = [], [], [], []
            for horizon in self.direct_horizons:
                q = self.direct_query.weight[horizon].unsqueeze(0).expand(x.size(0), -1)
                hidden = self.direct_fuse(torch.cat([context, q], dim=-1))
                mean, logvar = self.direct_state_head(hidden)
                d_states.append(mean); d_logvars.append(logvar)
                d_risks.append(self.direct_risk_head(hidden))
                d_stages.append(self.direct_stage_head(hidden))
            direct = {
                "state_mean": torch.stack(d_states, dim=1),
                "state_logvar": torch.stack(d_logvars, dim=1),
                "risk_logits": torch.stack(d_risks, dim=1),
                "stage_logits": torch.stack(d_stages, dim=1),
            }
        else:
            direct = {}
        # Reassemble outputs in the configured public horizon order.
        result = {}
        near_index = {k: i for i, k in enumerate(range(1, near["risk_logits"].shape[1] + 1))}
        direct_index = {k: i for i, k in enumerate(self.direct_horizons)}
        for name in ("state_mean", "state_logvar", "risk_logits", "stage_logits"):
            chunks = []
            for k in cfg.horizons:
                if k in direct_index:
                    chunks.append(direct[name][:, direct_index[k]:direct_index[k] + 1])
                elif k in near_index:
                    chunks.append(near[name][:, near_index[k]:near_index[k] + 1])
                else:
                    raise ValueError(f"horizon {k} is neither near nor direct")
            result[name] = torch.cat(chunks, dim=1)
        out = result
        if self.use_attention:
            out["attn_weights"] = torch.stack(attns, dim=1)   # (B, steps, L)
        if self.use_attention:
            # Attention is only defined for decoder-produced near horizons. Keep
            # the nearest available attention map for direct long horizons so
            # existing explanation consumers retain a stable tensor shape.
            attn_by_step = {k: attns[k - 1] for k in range(1, len(attns) + 1)}
            fallback = attns[-1]
            out["attn_weights"] = torch.stack(
                [attn_by_step.get(k, fallback) for k in cfg.horizons], dim=1
            )
        return out

    def select_horizons(
        self, outputs: Mapping[str, Tensor], horizons: Sequence[int] | None = None
    ) -> dict[str, Tensor]:
        """Slice per-step decoder outputs to the LOCKED horizons (step k-1 → horizon k)."""
        ks = list(horizons or self.config.horizons)
        idx = torch.tensor([k - 1 for k in ks], device=outputs["risk_logits"].device)
        return {name: t.index_select(1, idx) for name, t in outputs.items()}

    @torch.no_grad()
    def rollout(self, x: Tensor, n_steps: int | None = None) -> dict[str, Tensor]:
        """Free-running simulation (no teacher forcing). Inference path."""
        self.eval()
        return self.forward(x, targets=None, sampling_prob=1.0, n_steps=n_steps)

    def enable_mc_dropout(self) -> None:
        """Keep dropout active while otherwise in eval mode (MC-dropout)."""
        for m in self.modules():
            if isinstance(m, nn.Dropout):
                m.train()

    def num_parameters(self, trainable_only: bool = True) -> int:
        return sum(p.numel() for p in self.parameters() if p.requires_grad or not trainable_only)


def build_model(config: Mapping[str, object] | WorldModelConfig, device: str = "auto") -> WorldModel:
    """Construct a :class:`WorldModel` and move it to the resolved device."""
    from src.models import get_device

    model = WorldModel.from_config(config)
    return model.to(get_device(device))


__all__ = ["WorldModelConfig", "WorldModel", "build_model"]
