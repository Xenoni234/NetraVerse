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
            config.input_size, config.hidden_size, config.num_layers,
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
        steps = n_steps or cfg.rollout_steps
        enc_out, (h, c) = self.encoder(x)      # enc_out (B, L, H) — per-window states

        prev = x[:, -1, :]                     # (B, F) last observed frame
        free_run = (not self.training) or (targets is None)

        attn_keys = self.attn_k(enc_out) if self.use_attention else None  # (B, L, H)
        scale = cfg.hidden_size ** 0.5

        means, logvars, risks, stages, attns = [], [], [], [], []
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
            means.append(mean)
            logvars.append(logvar)
            risks.append(self.risk_head(hidden))
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

        out = {
            "state_mean": torch.stack(means, dim=1),
            "state_logvar": torch.stack(logvars, dim=1),
            "risk_logits": torch.stack(risks, dim=1),
            "stage_logits": torch.stack(stages, dim=1),
        }
        if self.use_attention:
            out["attn_weights"] = torch.stack(attns, dim=1)   # (B, steps, L)
        return self.select_horizons(out)

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
