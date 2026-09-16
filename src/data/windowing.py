"""State-builder: per-flow records -> per-host 30-second state snapshots -> sequences.

Implements Phase 2 of the plan. This is the module everything downstream depends
on, and the one where the leakage rules live, so it is written to be correct
first and fast second.

Pipeline
--------
1. :func:`build_windows` — group unified flow rows into **per-host, per-30s-window
   state vectors**. A "host" is the source IP (a pseudonymous key, never fed to
   the model). Each flow is assigned to the window containing its **end time**,
   not its start time, so a snapshot never contains a byte that had not yet been
   observed when the snapshot closed (leakage rule D, CLAUDE.md §10).
2. :func:`build_sequences` — stack each host's ordered snapshots into supervised
   samples: 10 past snapshots (``L``) -> the next 4 (``max(K)``), with the
   forecast read off at horizons ``K = (1, 2, 4)`` = +30 / +60 / +120 s.

Locked window parameters (CLAUDE.md §5): 30 s window, **30 s disjoint stride**,
``L = 10`` (5 min history), rollout 4 (2 min), report K = 1/2/4.

State vector
------------
The model input is derived, not decreed (CLAUDE.md §4): :data:`STATE_FEATURE_COLUMNS`
are the numeric features, :data:`MASK_COLUMNS` are the "was this observable?"
flags for the history-dependent features (a 0 must never be confused with "not
observed" — M3 §12). ``input_size`` is ``len(MODEL_COLUMNS)``, whatever that is.

Units note: CICFlowMeter ``Flow Duration`` and IAT columns are **microseconds**;
they are converted to seconds here.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Sequence

import numpy as np
import pandas as pd

from src.data import labeller as _lab
from src.data.unified_schema import FLOW_FEATURE_COLUMNS

log = logging.getLogger(__name__)

# ---- LOCKED window parameters (CLAUDE.md §5) ----------------------------- #
WINDOW_SECONDS: Final[int] = 30
STRIDE_SECONDS: Final[int] = 30          # disjoint, back-to-back
HISTORY_LENGTH: Final[int] = 10          # L — 5 minutes
HORIZONS: Final[tuple[int, ...]] = (1, 2, 4)   # +30 / +60 / +120 s
ROLLOUT_STEPS: Final[int] = max(HORIZONS)      # decoder unrolls 4 steps
MIN_WINDOWS_PER_ENTITY: Final[int] = HISTORY_LENGTH + ROLLOUT_STEPS  # 14

#: Microsecond→second divisor for CICFlowMeter duration/IAT columns.
_US_PER_S: Final[float] = 1_000_000.0

# --------------------------------------------------------------------------- #
# State feature schema (derived F)
# --------------------------------------------------------------------------- #

#: Numeric per-host-window features the model consumes.
STATE_FEATURE_COLUMNS: Final[tuple[str, ...]] = (
    # volume (6)
    "n_flows", "n_pkts_fwd", "n_pkts_bwd", "bytes_fwd", "bytes_bwd", "bytes_total",
    # rate over the 30 s window (3)
    "flows_per_sec", "pkts_per_sec", "bytes_per_sec",
    # TCP flag sums (6)
    "syn_count", "ack_count", "fin_count", "rst_count", "psh_count", "urg_count",
    # flag-derived (1)
    "failed_conn_ratio",
    # protocol mix (3)
    "frac_tcp", "frac_udp", "frac_icmp",
    # shape / timing (4)
    "mean_flow_duration_s", "mean_iat_s", "mean_pkt_len", "fwd_bwd_ratio",
    # packet-level aggregates from CSV CICFlowMeter stats (12): packet shape per
    # direction, TCP window size, directional IAT timing, active/idle session
    # timing, segment/header sizes — the timing & sequencing the PS wants.
    "mean_fwd_pkt_len", "mean_bwd_pkt_len", "pkt_len_var",
    "mean_fwd_iat_s", "mean_bwd_iat_s",
    "mean_init_win_fwd", "mean_init_win_bwd",
    "active_s", "idle_s",
    # fan-out / topology — the attacker-footprint signals (4)
    "n_distinct_dst_ip", "n_distinct_dst_port", "dst_port_entropy", "dst_ip_entropy",
    # behavioural / history-dependent (4)
    "new_peer_count", "off_hours_ratio", "baseline_deviation", "trajectory_velocity",
)

#: "Was this observable?" flags for the history-dependent features. 1 = valid,
#: 0 = warmup / undefined (the feature itself is then 0, not a real measurement).
MASK_COLUMNS: Final[tuple[str, ...]] = (
    "mask_new_peer_count", "mask_baseline_deviation", "mask_trajectory_velocity",
)

#: The full model input, in fixed order. ``input_size = len(MODEL_COLUMNS)``.
MODEL_COLUMNS: Final[tuple[str, ...]] = STATE_FEATURE_COLUMNS + MASK_COLUMNS

#: Index columns carried with every snapshot (never fed to the model).
STATE_INDEX_COLUMNS: Final[tuple[str, ...]] = (
    "entity_id", "campaign_id", "dataset", "window_start",
)

#: Business-hours bounds (local capture time) for ``off_hours_ratio``.
_BUSINESS_START_HOUR: Final[int] = 9
_BUSINESS_END_HOUR: Final[int] = 18

#: Max trailing windows used for the per-host baseline (open item C: a literal
#: 7-day baseline is impossible on a 5-day capture; use a capped trailing window).
_BASELINE_TRAILING_WINDOWS: Final[int] = 20
_BASELINE_MIN_WINDOWS: Final[int] = 3


@dataclass(frozen=True)
class WindowConfig:
    """Window parameters, normally built from a config YAML.

    Defaults are the LOCKED values; overriding them is only valid for deliberate
    ablations, never a reported run.
    """

    window_seconds: int = WINDOW_SECONDS
    stride_seconds: int = STRIDE_SECONDS
    history_length: int = HISTORY_LENGTH
    horizons: tuple[int, ...] = HORIZONS
    rollout_steps: int = ROLLOUT_STEPS
    min_windows_per_entity: int = MIN_WINDOWS_PER_ENTITY
    entity_granularity: str = "src_ip"   # src_ip | src_dst_pair


@dataclass(frozen=True)
class SequenceBatch:
    """A materialised set of supervised samples.

    Attributes:
        x: ``(N, L, F)`` float32 history (features + masks).
        y_state: ``(N, |K|, F)`` float32 future feature vectors.
        y_risk: ``(N, |K|)`` float32 future binary attack labels.
        y_stage: ``(N, |K|)`` int64 future ATT&CK stage ids (``-1`` = masked).
        meta: ``(N,)``-row frame of ``entity_id`` / ``campaign_id`` /
            ``window_start`` (the forecast-issue window), for lead-time and
            per-campaign reporting.
        feature_names: The ``F`` column names, in order (``MODEL_COLUMNS``).
    """

    x: np.ndarray
    y_state: np.ndarray
    y_risk: np.ndarray
    y_stage: np.ndarray
    meta: pd.DataFrame
    feature_names: tuple[str, ...] = MODEL_COLUMNS

    @property
    def n_features(self) -> int:
        return self.x.shape[-1]


# --------------------------------------------------------------------------- #
# Entity + window assignment
# --------------------------------------------------------------------------- #


def entity_key(flows: pd.DataFrame, granularity: str = "src_ip") -> pd.Series:
    """Derive ``entity_id`` from flow records.

    ``src_ip`` -> the source host; ``src_dst_pair`` -> ``"<src>><dst>"``.
    """
    if granularity == "src_ip":
        if "src_ip" not in flows.columns:
            raise ValueError(
                "Per-host state needs a 'src_ip' column, but this frame has none. "
                "CIC-IDS2018's 80-column days are IP-stripped — use CIC-IDS2017 "
                "(TrafficLabelling) or the one 2018 day that carries IPs."
            )
        return flows["src_ip"].astype("string")
    if granularity == "src_dst_pair":
        return (flows["src_ip"].astype("string") + ">" + flows["dst_ip"].astype("string"))
    raise ValueError(f"Unknown entity_granularity {granularity!r}")


def _window_start(end_ts: pd.Series, window_seconds: int) -> pd.Series:
    """Floor each flow's **end** timestamp to the disjoint window grid."""
    return end_ts.dt.floor(f"{window_seconds}s")


# --------------------------------------------------------------------------- #
# Per-window aggregation
# --------------------------------------------------------------------------- #


def _shannon_entropy(values) -> float:
    """Attempt-weighted Shannon entropy (bits) of a categorical column.

    Uses pandas value_counts so mixed types (CTU-13 ports can be hex strings,
    decimals, or NaN) don't trip numpy's typed sort.
    """
    # factorize handles mixed types (CTU-13 hex/decimal/NaN ports) and is fast.
    codes, _ = pd.factorize(pd.Series(values), use_na_sentinel=True)
    codes = codes[codes >= 0]
    if codes.size == 0:
        return 0.0
    counts = np.bincount(codes).astype("float64")
    prob = counts[counts > 0] / codes.size
    return float(-(prob * np.log2(prob)).sum())


def build_windows(flows: pd.DataFrame, config: WindowConfig | None = None) -> pd.DataFrame:
    """Aggregate unified flow rows into per-host, per-30s-window state snapshots.

    Args:
        flows: Unified, labelled flow records (output of ``labeller.label_frame``
            over ``unified_schema.to_unified``). Must carry ``timestamp``,
            ``flow_duration`` (microseconds), ``src_ip``, ``dst_ip``, ``dst_port``,
            ``protocol``, ``campaign_id`` and the label columns.
        config: Window parameters.

    Returns:
        One row per ``(campaign_id, entity_id, window_start)`` with
        :data:`STATE_INDEX_COLUMNS` + :data:`MODEL_COLUMNS` + window labels
        (``binary_label``, ``attt_stage``).
    """
    cfg = config or WindowConfig()
    df = flows.copy()

    df["entity_id"] = entity_key(df, cfg.entity_granularity)

    # Assign by END time (leakage rule): end = start + duration(µs). Clock-aligned
    # disjoint 30 s grid.
    dur_s = pd.to_numeric(df["flow_duration"], errors="coerce").fillna(0.0) / _US_PER_S
    end_ts = df["timestamp"] + pd.to_timedelta(dur_s.clip(lower=0), unit="s")
    df["window_start"] = _window_start(end_ts, cfg.window_seconds)

    proto_num = pd.to_numeric(df.get("protocol"), errors="coerce")
    proto_str = df.get("protocol").astype("string").str.lower()
    df["_is_tcp"] = ((proto_num == 6) | (proto_str == "tcp")).astype("float32")
    df["_is_udp"] = ((proto_num == 17) | (proto_str == "udp")).astype("float32")
    df["_is_icmp"] = ((proto_num == 1) | (proto_str == "icmp")).astype("float32")
    df["_hour"] = df["timestamp"].dt.hour
    df["_off_hours"] = (
        (df["_hour"] < _BUSINESS_START_HOUR) | (df["_hour"] >= _BUSINESS_END_HOUR)
    ).astype("float32")
    # A crude per-flow "failed connection" proxy: reset seen, or SYN without ACK.
    df["_failed"] = (
        (pd.to_numeric(df["rst_count"], errors="coerce").fillna(0) > 0)
        | (
            (pd.to_numeric(df["syn_count"], errors="coerce").fillna(0) > 0)
            & (pd.to_numeric(df["ack_count"], errors="coerce").fillna(0) == 0)
        )
    ).astype("float32")

    gkeys = ["campaign_id", "entity_id", "window_start"]
    g = df.groupby(gkeys, sort=True)

    agg = g.agg(
        n_flows=("entity_id", "size"),
        n_pkts_fwd=("fwd_packets", "sum"),
        n_pkts_bwd=("bwd_packets", "sum"),
        bytes_fwd=("fwd_bytes", "sum"),
        bytes_bwd=("bwd_bytes", "sum"),
        syn_count=("syn_count", "sum"),
        ack_count=("ack_count", "sum"),
        fin_count=("fin_count", "sum"),
        rst_count=("rst_count", "sum"),
        psh_count=("psh_count", "sum"),
        urg_count=("urg_count", "sum"),
        failed_conn_ratio=("_failed", "mean"),
        frac_tcp=("_is_tcp", "mean"),
        frac_udp=("_is_udp", "mean"),
        frac_icmp=("_is_icmp", "mean"),
        mean_flow_duration_us=("flow_duration", "mean"),
        mean_iat_us=("iat_mean", "mean"),
        mean_pkt_len=("pkt_len_mean", "mean"),
        fwd_bwd_ratio=("fwd_bwd_ratio", "mean"),
        # packet-level aggregates (mean over the window's flows)
        mean_fwd_pkt_len=("fwd_pkt_len_mean", "mean"),
        mean_bwd_pkt_len=("bwd_pkt_len_mean", "mean"),
        pkt_len_var=("pkt_len_var", "mean"),
        mean_fwd_iat_us=("fwd_iat_mean", "mean"),
        mean_bwd_iat_us=("bwd_iat_mean", "mean"),
        mean_init_win_fwd=("init_win_fwd", "mean"),
        mean_init_win_bwd=("init_win_bwd", "mean"),
        mean_active_us=("active_mean", "mean"),
        mean_idle_us=("idle_mean", "mean"),
        n_distinct_dst_ip=("dst_ip", "nunique"),
        n_distinct_dst_port=("dst_port", "nunique"),
        off_hours_ratio=("_off_hours", "mean"),
        binary_label=("binary_label", "max"),          # attack if any flow is
        attt_stage=("attt_stage", _window_stage),
        label_flows_attack=("binary_label", "sum"),
    )

    # Entropies (need the raw arrays per group).
    ent = g.agg(
        dst_port_entropy=("dst_port", lambda s: _shannon_entropy(s.to_numpy())),
        dst_ip_entropy=("dst_ip", lambda s: _shannon_entropy(s.to_numpy())),
    )
    windows = agg.join(ent).reset_index()

    # new_peer_count (vectorised): count destination IPs whose FIRST appearance for
    # this host is in this window -> genuine "never-contacted-before" peers. This is
    # the recon-scan signal, computed without per-window Python sets (scales to millions).
    npdf = df[["campaign_id", "entity_id", "dst_ip", "window_start"]].dropna(subset=["dst_ip"])
    first_win = npdf.groupby(["campaign_id", "entity_id", "dst_ip"])["window_start"].transform("min")
    new_only = npdf[npdf["window_start"] == first_win].drop_duplicates(
        ["campaign_id", "entity_id", "dst_ip"]
    )
    np_counts = (
        new_only.groupby(["campaign_id", "entity_id", "window_start"]).size()
        .rename("new_peer_count").reset_index()
    )
    windows = windows.merge(np_counts, on=["campaign_id", "entity_id", "window_start"], how="left")
    windows["new_peer_count"] = windows["new_peer_count"].fillna(0.0)

    # Derived fields.
    w = cfg.window_seconds
    windows["bytes_total"] = windows["bytes_fwd"] + windows["bytes_bwd"]
    windows["flows_per_sec"] = windows["n_flows"] / w
    windows["pkts_per_sec"] = (windows["n_pkts_fwd"] + windows["n_pkts_bwd"]) / w
    windows["bytes_per_sec"] = windows["bytes_total"] / w
    windows["mean_flow_duration_s"] = windows.pop("mean_flow_duration_us") / _US_PER_S
    windows["mean_iat_s"] = windows.pop("mean_iat_us") / _US_PER_S
    # packet-level timing: microseconds -> seconds
    windows["mean_fwd_iat_s"] = windows.pop("mean_fwd_iat_us") / _US_PER_S
    windows["mean_bwd_iat_s"] = windows.pop("mean_bwd_iat_us") / _US_PER_S
    windows["active_s"] = windows.pop("mean_active_us") / _US_PER_S
    windows["idle_s"] = windows.pop("mean_idle_us") / _US_PER_S
    windows["dataset"] = df["dataset"].iloc[0] if "dataset" in df.columns else "unknown"

    # Behavioural, history-dependent features (per host, in time order) + masks.
    windows = _add_behavioural_features(windows, cfg)

    # Finalise: fill non-finite, cast, order columns.
    for col in STATE_FEATURE_COLUMNS:
        windows[col] = pd.to_numeric(windows[col], errors="coerce").astype("float32")
    windows[list(STATE_FEATURE_COLUMNS)] = (
        windows[list(STATE_FEATURE_COLUMNS)].replace([np.inf, -np.inf], np.nan).fillna(0.0)
    )
    ordered = list(STATE_INDEX_COLUMNS) + list(MODEL_COLUMNS) + ["binary_label", "attt_stage"]
    windows = windows.sort_values(["campaign_id", "entity_id", "window_start"], kind="mergesort")
    return windows.loc[:, ordered].reset_index(drop=True)


def _window_stage(stage_series: pd.Series) -> int:
    """Window stage = the max non-masked flow stage, else masked if any attack."""
    from src.mitre.stage_mapping import STAGE_MASKED

    vals = pd.to_numeric(stage_series, errors="coerce").dropna().astype(int)
    valid = vals[vals >= 0]
    if not valid.empty:
        return int(valid.max())
    if (vals == STAGE_MASKED).any():
        return STAGE_MASKED
    return 0


def _add_behavioural_features(windows: pd.DataFrame, cfg: WindowConfig) -> pd.DataFrame:
    """Add new_peer_count / baseline_deviation / trajectory_velocity + masks.

    All are trailing-only (never look ahead) and per (campaign, entity). The
    first window(s) of a host have no history -> feature 0, mask 0 (open item C).
    """
    windows = windows.sort_values(
        ["campaign_id", "entity_id", "window_start"], kind="mergesort"
    ).reset_index(drop=True)

    base_dev = np.zeros(len(windows), dtype="float32")
    traj = np.zeros(len(windows), dtype="float32")
    m_new = np.zeros(len(windows), dtype="float32")
    m_base = np.zeros(len(windows), dtype="float32")
    m_traj = np.zeros(len(windows), dtype="float32")

    # The ramp diagnostic showed the real pre-attack signal lives in port-entropy
    # climb, fan-out and flow-rate — so the derived behavioural features target
    # those (not bytes/s, which was flat before onset).
    for _, idx in windows.groupby(["campaign_id", "entity_id"], sort=False).groups.items():
        rows = np.asarray(idx)
        if rows.size == 0:
            continue
        fps = windows.loc[rows, "flows_per_sec"].to_numpy(dtype="float64")
        ent = windows.loc[rows, "dst_port_entropy"].to_numpy(dtype="float64")

        # new_peer_count already computed vectorised in build_windows; set its mask.
        if rows.size > 1:
            m_new[rows[1:]] = 1.0

        # trajectory_velocity: backward difference of dst_port_entropy (the ramp).
        if rows.size > 1:
            traj[rows] = np.diff(ent, prepend=ent[0]).astype("float32")
            m_traj[rows[1:]] = 1.0

        # baseline_deviation: robust z of flows_per_sec vs the host's trailing window.
        for i in range(rows.size):
            lo = max(0, i - _BASELINE_TRAILING_WINDOWS)
            hist = fps[lo:i]
            if hist.size >= _BASELINE_MIN_WINDOWS:
                med = np.median(hist)
                iqr = np.subtract(*np.percentile(hist, [75, 25]))
                # Floor the scale so a near-constant history can't produce a huge z.
                scale = max(iqr, float(np.std(hist)), 1e-3)
                z = (fps[i] - med) / scale
                base_dev[rows[i]] = np.float32(np.clip(z, -10.0, 10.0))
                m_base[rows[i]] = 1.0

    windows["baseline_deviation"] = base_dev
    windows["trajectory_velocity"] = traj
    windows["mask_new_peer_count"] = m_new
    windows["mask_baseline_deviation"] = m_base
    windows["mask_trajectory_velocity"] = m_traj
    return windows


# --------------------------------------------------------------------------- #
# Sequence construction
# --------------------------------------------------------------------------- #


def build_sequences(
    windows: pd.DataFrame,
    config: WindowConfig | None = None,
    *,
    target: str = "onset",
    exclude_ongoing: bool = True,
) -> SequenceBatch:
    """Turn per-host snapshots into ``(N, L, F)`` supervised samples.

    Slides over each host's **consecutive observed snapshots** (silent gaps
    skipped, not zero-filled). Never crosses an entity/campaign boundary.

    Target modes (``target=``):
        ``"onset"`` (default, the PS objective) — forecast the **onset** of an
            attack. At origin window ``t`` (currently benign),
            ``y_risk[k] = 1`` iff an attack begins within ``k`` windows
            (``1 <= dist_to_next_attack(t) <= k``). Persistence cannot win this:
            a benign-looking host gives persistence "benign", so it misses every
            onset. ``y_stage[k]`` is the imminent attack's stage (else BENIGN).
            With ``exclude_ongoing`` (default), origins already under attack are
            dropped — we forecast *for currently-benign hosts*.
        ``"ongoing"`` — the detection-style target (future ``binary_label`` at
            ``t+k``). Kept for the ablation; persistence dominates it.

    ``origin_risk`` in meta is the last observed window's label (0 for every kept
    onset sample) — the persistence baseline's prediction.
    """
    cfg = config or WindowConfig()
    L, ksteps = cfg.history_length, cfg.rollout_steps
    horizons = np.asarray(cfg.horizons)
    feat = list(MODEL_COLUMNS)
    if target not in ("onset", "ongoing"):
        raise ValueError(f"target must be 'onset' or 'ongoing', got {target!r}")

    xs, ys, yr, ystg, meta_rows = [], [], [], [], []
    for (campaign, entity), grp in windows.groupby(["campaign_id", "entity_id"], sort=True):
        grp = grp.sort_values("window_start", kind="mergesort")
        n = len(grp)
        if n < cfg.min_windows_per_entity:
            continue
        fmat = grp[feat].to_numpy(dtype="float32")
        risk = grp["binary_label"].to_numpy(dtype="float32")
        stage = grp["attt_stage"].to_numpy(dtype="int64")
        starts = grp["window_start"].to_numpy()

        # Windows until the next attack, over consecutive rows (trailing-safe).
        attack_pos = np.flatnonzero(risk > 0.5)
        dist = np.full(n, np.inf)
        if attack_pos.size:
            nxt = np.searchsorted(attack_pos, np.arange(n), side="left")
            has = nxt < attack_pos.size
            dist[has] = attack_pos[nxt[has]] - np.arange(n)[has]

        last_origin = n - ksteps
        for t in range(L - 1, last_origin):
            if target == "onset":
                if exclude_ongoing and risk[t] > 0.5:
                    continue                                   # forecast for benign hosts
                d = dist[t]
                y = np.array([1.0 if 1 <= d <= k else 0.0 for k in horizons], dtype="float32")
                if np.isfinite(d):
                    onset_row = t + int(d)
                    st = int(stage[onset_row]) if onset_row < n else 0
                    stg = np.array([st if 1 <= d <= k else 0 for k in horizons], dtype="int64")
                else:
                    stg = np.zeros(len(horizons), dtype="int64")
            else:  # ongoing (detection-style)
                fut = t + horizons
                y = risk[fut].astype("float32")
                stg = stage[fut].astype("int64")

            xs.append(fmat[t - L + 1 : t + 1])                 # (L, F)
            ys.append(fmat[t + horizons])                       # (|K|, F) future state
            yr.append(y)
            ystg.append(stg)
            meta_rows.append((entity, campaign, starts[t], float(risk[t]), int(stage[t])))

    if not xs:
        raise ValueError(
            "No sequences built. Every host had fewer than "
            f"{cfg.min_windows_per_entity} consecutive windows, or all origins were "
            "excluded. Try more data / a busier day."
        )

    meta = pd.DataFrame(meta_rows, columns=["entity_id", "campaign_id", "window_start",
                                          "origin_risk", "origin_stage"])
    return SequenceBatch(
        x=np.stack(xs), y_state=np.stack(ys), y_risk=np.stack(yr),
        y_stage=np.stack(ystg), meta=meta, feature_names=tuple(feat),
    )


# --------------------------------------------------------------------------- #
# Scaling (train-only fit)
# --------------------------------------------------------------------------- #


def fit_scaler(x: np.ndarray, method: str = "robust", *, mask_tail: int = len(MASK_COLUMNS)) -> dict:
    """Fit a per-feature scaler on TRAIN sequences only.

    Mask columns (the final ``mask_tail`` features) are left unscaled — they are
    already 0/1 flags. ``x`` is ``(N, L, F)``; stats are over N·L.
    """
    flat = x.reshape(-1, x.shape[-1]).astype("float64")
    f = flat.shape[1]
    n_feat = f - mask_tail
    if method == "robust":
        center = np.median(flat[:, :n_feat], axis=0)
        q75, q25 = np.percentile(flat[:, :n_feat], [75, 25], axis=0)
        scale = q75 - q25
    elif method == "standard":
        center = flat[:, :n_feat].mean(axis=0)
        scale = flat[:, :n_feat].std(axis=0)
    else:
        raise ValueError(f"Unknown scaler {method!r}")
    scale = np.where(scale < 1e-9, 1.0, scale)
    return {"method": method, "center": center, "scale": scale, "n_feat": int(n_feat),
            "mask_tail": int(mask_tail)}


def apply_scaler(x: np.ndarray, state: dict) -> np.ndarray:
    """Apply a fitted scaler; mask columns pass through; result is finite float32."""
    out = x.astype("float32").copy()
    n = state["n_feat"]
    center = state["center"].astype("float32")
    scale = state["scale"].astype("float32")
    out[..., :n] = (out[..., :n] - center) / scale
    return np.nan_to_num(out, nan=0.0, posinf=0.0, neginf=0.0).astype("float32")


# --------------------------------------------------------------------------- #
# Persistence
# --------------------------------------------------------------------------- #


def save_sequences(batch: SequenceBatch, path: Path) -> Path:
    """Persist a :class:`SequenceBatch` (npz arrays + parquet meta sidecar)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(
        path, x=batch.x, y_state=batch.y_state, y_risk=batch.y_risk,
        y_stage=batch.y_stage, feature_names=np.array(batch.feature_names),
    )
    batch.meta.to_parquet(path.with_suffix(".meta.parquet"), index=False)
    return path


def load_sequences(path: Path) -> SequenceBatch:
    """Load a :class:`SequenceBatch` written by :func:`save_sequences`."""
    path = Path(path)
    npz_path = path if path.suffix == ".npz" else path.with_suffix(".npz")
    d = np.load(npz_path, allow_pickle=True)
    meta = pd.read_parquet(npz_path.with_suffix("").with_suffix(".meta.parquet"))
    return SequenceBatch(
        x=d["x"], y_state=d["y_state"], y_risk=d["y_risk"], y_stage=d["y_stage"],
        meta=meta, feature_names=tuple(str(s) for s in d["feature_names"]),
    )


def train_val_test_slices(windows: pd.DataFrame, **split_kwargs: object) -> dict[str, pd.DataFrame]:
    """Convenience wrapper over :mod:`src.eval.splits` for the data pipeline."""
    from src.eval.splits import chronological_split

    return chronological_split(windows, **split_kwargs)  # type: ignore[arg-type]


class WindowedDataset:
    """``torch.utils.data.Dataset`` over a :class:`SequenceBatch`.

    Kept torch-free at import; becomes a real ``Dataset`` subclass at first use so
    the data team can import this module without torch installed.
    """

    def __init__(self, batch: SequenceBatch):
        self._b = batch

    def __len__(self) -> int:
        return int(self._b.x.shape[0])

    def __getitem__(self, i: int):
        import torch

        return (
            torch.from_numpy(self._b.x[i]),
            torch.from_numpy(self._b.y_state[i]),
            torch.from_numpy(self._b.y_risk[i]),
            torch.from_numpy(self._b.y_stage[i]),
        )


__all__ = [
    "WINDOW_SECONDS", "STRIDE_SECONDS", "HISTORY_LENGTH", "HORIZONS", "ROLLOUT_STEPS",
    "MIN_WINDOWS_PER_ENTITY", "STATE_FEATURE_COLUMNS", "MASK_COLUMNS", "MODEL_COLUMNS",
    "STATE_INDEX_COLUMNS", "WindowConfig", "SequenceBatch", "entity_key", "build_windows",
    "build_sequences", "fit_scaler", "apply_scaler", "save_sequences", "load_sequences",
    "train_val_test_slices", "WindowedDataset",
]
