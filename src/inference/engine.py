"""Inference engine — load a trained checkpoint and forecast attack onset.

The single entry point the demo and the live loop share. Loads a checkpoint
saved by ``scripts/train_world_model.py`` (state_dict + model_config + scaler +
feature_names + threshold + horizons), rebuilds the world model, and forecasts
per host from windowed snapshots.

Everything runs offline, CPU or GPU. No cloud calls.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import numpy as np
import pandas as pd
import torch

from src.data import windowing as W
from src.models import get_device
from src.models.lstm_encoder_decoder import WorldModel, WorldModelConfig


@dataclass
class Forecaster:
    """A loaded world model ready to forecast. Built by :func:`load_forecaster`."""

    model: WorldModel
    scaler: dict
    feature_names: list[str]
    threshold: float
    horizons: list[int]
    device: torch.device
    stride_seconds: int = W.STRIDE_SECONDS
    history_length: int = W.HISTORY_LENGTH
    thresholds: list[float] | None = None
    sequence_policy: str = "strict_30s"
    min_observed_history: int = 3

    def threshold_for_horizon(self, horizon: int) -> float:
        """Use the validation-selected cutoff for this forecast horizon."""
        return float(self.thresholds[self.horizons.index(horizon)]) if self.thresholds else self.threshold

    # -- core forecast ------------------------------------------------------- #

    @torch.no_grad()
    def forecast_batch(self, x: np.ndarray, *, mc_samples: int = 0):
        """Forecast from a batch of histories ``x`` = (N, L, F) (unscaled).

        Returns a dict with ``risk`` (N, K), ``stage`` (N, K), and — when
        ``mc_samples > 0`` — ``risk_lo``/``risk_hi`` (N, K) MC-dropout band.
        """
        xs = W.apply_scaler(np.asarray(x, dtype="float32"), self.scaler)
        xt = torch.from_numpy(xs).to(self.device)

        self.model.eval()
        out = self.model.rollout(xt)
        risk = torch.sigmoid(out["risk_logits"]).cpu().numpy()
        stage = out["stage_logits"].argmax(-1).cpu().numpy()

        result = {"risk": risk, "stage": stage}
        # temporal attention over the L history windows (explainability): (N, K, L)
        if "attn_weights" in out:
            result["attn"] = out["attn_weights"].cpu().numpy()

        if mc_samples and mc_samples > 0:
            self.model.enable_mc_dropout()
            samples = np.stack([
                torch.sigmoid(self.model(xt)["risk_logits"]).cpu().numpy()
                for _ in range(mc_samples)
            ])  # (T, N, K)
            self.model.eval()
            lo, hi = np.percentile(samples, [5, 95], axis=0)
            result["risk_lo"], result["risk_hi"] = lo, hi
            result["risk"] = samples.mean(axis=0)
        return result

    def forecast_host_timeline(
        self, host_windows: pd.DataFrame, *, mc_samples: int = 0
    ) -> pd.DataFrame:
        """Rolling forecast for ONE host over its ordered windows.

        At each origin window ``t`` (with L history), forecast risk at the LOCKED
        horizons. Returns one row per origin window with the forecast risk (per
        horizon), the model's argmax stage, the true label at the origin, and the
        window start — everything the dashboard needs to draw the risk timeline.
        """
        g = host_windows.sort_values("window_start").reset_index(drop=True)
        if self.sequence_policy == 'masked_history_30s':
            return self._forecast_masked_timeline(g,mc_samples=mc_samples)
        feat = [c for c in self.feature_names if c in g.columns]
        fmat = g[feat].to_numpy(dtype="float32")
        n, L = len(g), self.history_length
        if n < L:
            return pd.DataFrame()

        origins = np.arange(L - 1, n)
        times = pd.to_datetime(g["window_start"], utc=True).astype("datetime64[ns, UTC]").astype("int64").to_numpy()
        breaks = np.r_[0, np.cumsum(np.diff(times) != self.stride_seconds * 1_000_000_000)]
        origins = origins[breaks[origins] == breaks[origins - L + 1]]
        if not len(origins):
            return pd.DataFrame()
        X = np.stack([fmat[t - L + 1 : t + 1] for t in origins])  # (M, L, F)
        out = self.forecast_batch(X, mc_samples=mc_samples)

        rows = pd.DataFrame({
            "window_start": g["window_start"].to_numpy()[origins],
            "true_label": g["binary_label"].to_numpy()[origins] if "binary_label" in g else 0,
        })
        for i, k in enumerate(self.horizons):
            rows[f"risk_k{k}"] = out["risk"][:, i]
            rows[f"stage_k{k}"] = out["stage"][:, i]
            if "risk_lo" in out:
                rows[f"risk_lo_k{k}"] = out["risk_lo"][:, i]
                rows[f"risk_hi_k{k}"] = out["risk_hi"][:, i]
            if "attn" in out:   # per-row (L,) attention over history windows
                rows[f"attn_k{k}"] = list(out["attn"][:, i, :])
        return rows

    def _forecast_masked_timeline(self, g: pd.DataFrame, *, mc_samples: int = 0) -> pd.DataFrame:
        """Use the same missing-history representation as repaired training."""
        if g.empty:
            return pd.DataFrame()
        base = [c for c in self.feature_names if c != 'mask_observed']
        observed = g.set_index('window_start')[base]
        xs, origins = [], []
        for t in range(len(g)):
            wanted = pd.date_range(end=g.window_start.iloc[t],periods=self.history_length,
                                   freq=f'{self.stride_seconds}s')
            available = wanted.isin(observed.index)
            if available.sum() < self.min_observed_history:
                continue
            frame = observed.reindex(wanted).fillna(0).to_numpy(dtype='float32')
            xs.append(np.c_[frame,available.astype('float32')]); origins.append(t)
        if not xs:
            return pd.DataFrame()
        out = self.forecast_batch(np.stack(xs),mc_samples=mc_samples)
        rows = pd.DataFrame({'window_start':g.window_start.iloc[origins].to_numpy(),
                             'true_label':g.binary_label.iloc[origins].to_numpy() if 'binary_label' in g else 0})
        for i,k in enumerate(self.horizons):
            rows[f'risk_k{k}'] = out['risk'][:,i]
            rows[f'stage_k{k}'] = out['stage'][:,i]
            if 'risk_lo' in out:
                rows[f'risk_lo_k{k}'], rows[f'risk_hi_k{k}'] = out['risk_lo'][:,i],out['risk_hi'][:,i]
        return rows


def load_forecaster(ckpt_path: Path | str, *, device: str = "auto") -> Forecaster:
    """Rebuild a :class:`Forecaster` from a training checkpoint (map_location=cpu-safe)."""
    dev = get_device(device)
    payload = torch.load(Path(ckpt_path), map_location="cpu", weights_only=False)
    cfg = payload["model_config"]
    model = WorldModel(WorldModelConfig(**{k: (tuple(v) if k == "horizons" else v)
                                           for k, v in cfg.items()}))
    model.load_state_dict(payload["state_dict"])
    model.to(dev).eval()
    return Forecaster(
        model=model,
        scaler=payload["scaler"],
        feature_names=list(payload["feature_names"]),
        threshold=float(payload.get("threshold", 0.5)),
        horizons=list(payload.get("horizons", W.HORIZONS)),
        device=dev,
        history_length=int(payload.get("history_length", W.HISTORY_LENGTH)),
        thresholds=payload.get("thresholds"),
        sequence_policy=payload.get('sequence_policy','strict_30s'),
        min_observed_history=int(payload.get('min_observed_history',3)),
    )


def lead_time_seconds(
    timeline: pd.DataFrame,
    *,
    horizon_key: str,
    threshold: float,
    sustain: int = 2,
    stride_seconds: int = W.STRIDE_SECONDS,
) -> float | None:
    """Seconds between the first sustained alert and the first true-attack window.

    Positive = warned early (good). ``None`` if never alerted or no attack.
    Sustained = ``sustain`` consecutive windows with risk >= threshold.
    """
    risk = timeline[horizon_key].to_numpy()
    over = risk >= threshold
    true = timeline["true_label"].to_numpy().astype(bool)
    if not true.any():
        return None
    attack_idx = int(np.argmax(true))
    try:
        horizon_steps = int(horizon_key.rsplit('k',1)[1])
    except (IndexError, ValueError):
        horizon_steps = None
    alert_idx = None
    times = pd.to_datetime(timeline['window_start'], utc=True) if 'window_start' in timeline else None
    for i in range(len(over) - sustain + 1):
        if over[i : i + sustain].all():
            if times is not None and sustain > 1:
                differences = times.iloc[i:i+sustain].diff().dropna().dt.total_seconds()
                if not (differences == stride_seconds).all():
                    continue
            # A sustained alert is available only when its last window closes.
            candidate = i + sustain - 1
            lead = ((times.iloc[attack_idx]-times.iloc[candidate]).total_seconds()-stride_seconds
                    if times is not None else (attack_idx-candidate-1)*stride_seconds)
            if horizon_steps is not None and lead > (horizon_steps-1)*stride_seconds:
                continue  # an unrelated, much earlier false alarm is not warning lead
            alert_idx = candidate
            break
    if alert_idx is None or not true.any():
        return None
    attack_idx = int(np.argmax(true))
    if times is not None:
        return float((times.iloc[attack_idx] - times.iloc[alert_idx]).total_seconds() - stride_seconds)
    return float((attack_idx - alert_idx - 1) * stride_seconds)


# --------------------------------------------------------------------------- #
# Lightweight explanation (cite observed numbers vs a benign baseline)
# --------------------------------------------------------------------------- #

#: Human-readable phrasing for the features that carry the recon-ramp signal.
FEATURE_LABELS: dict[str, str] = {
    "dst_port_entropy": "spread of destination ports contacted",
    "n_distinct_dst_port": "number of distinct destination ports",
    "n_distinct_dst_ip": "number of distinct destinations (fan-out)",
    "new_peer_count": "never-before-seen destinations",
    "flows_per_sec": "connection rate",
    "failed_conn_ratio": "share of failed connections",
    "syn_count": "SYN (connection-attempt) count",
    "rst_count": "RST (reset) count",
    "bytes_per_sec": "outbound throughput",
    "baseline_deviation": "deviation from this host's normal rate",
    "trajectory_velocity": "rate of change in port-scanning behaviour",
    "pkts_per_sec": "packet rate",
    "fin_count": "FIN (connection-close) count",
    "ack_count": "ACK count",
    "psh_count": "PSH count",
    "urg_count": "URG (urgent) count",
    "mean_pkt_len": "mean packet size",
    "mean_iat_s": "mean inter-arrival time",
    "n_flows": "number of flows",
    "bytes_total": "total bytes",
    "frac_tcp": "TCP fraction", "frac_udp": "UDP fraction", "frac_icmp": "ICMP fraction",
}


def explain_window(
    current: pd.Series, baseline: pd.Series, feature_names: list[str], *, top_k: int = 3
) -> tuple[str, list[tuple[str, float, float]]]:
    """Explain why a window looks risky: the top features most elevated vs benign.

    Returns a plain-English sentence and the ``(feature, current, baseline)``
    triples behind it. Deliberately template-based (auditable, offline, cannot
    hallucinate) and always cites the observed numbers.
    """
    scored = []
    for f in feature_names:
        if f.startswith("mask_") or f not in current or f not in baseline:
            continue
        cur, base = float(current[f]), float(baseline[f])
        denom = abs(base) + 1e-6
        rel = (cur - base) / denom
        scored.append((f, cur, base, rel))
    scored.sort(key=lambda r: r[3], reverse=True)
    top = [(f, c, b) for f, c, b, r in scored[:top_k] if r > 0.1]
    if not top:
        return "No feature is notably elevated above this host's normal.", []

    clauses = []
    for f, c, b in top:
        label = FEATURE_LABELS.get(f, f)
        clauses.append(f"{label} is {c:.2f} vs a normal ~{b:.2f}")
    sentence = "Elevated: " + "; ".join(clauses) + "."
    return sentence, top


__all__ = ["Forecaster", "load_forecaster", "lead_time_seconds",
           "explain_window", "FEATURE_LABELS"]
