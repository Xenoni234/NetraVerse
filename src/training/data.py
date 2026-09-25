"""Sequence dataset construction shared by world-model training, baseline and evaluation.

Split policy (documented, R20): *blocked temporal split*. Every capture is cut
into 1-hour blocks; blocks are assigned train/val/test in a fixed 3:1:1 cycle
(offset per capture). A sequence (L history + K future windows) is only used if
it lies entirely inside one block, so no window is ever shared between splits
and there is no look-ahead leakage. Never a random row shuffle (R1).
"""
from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd

from src.features.schema import FEATURE_COLUMNS, MASK_FEATURES, PACKET_FEATURES
from src.graph.graph_utils import neighbor_aggregate
from src.models.world_model import FeatureScaler
from src.utils.config import PROCESSED

BLOCK_WINDOWS = 60
CYCLE = np.array([0, 0, 1, 0, 2])          # 0 train, 1 val, 2 test -> 60/20/20
PACKET_IDX = np.array([FEATURE_COLUMNS.index(c) for c in PACKET_FEATURES + MASK_FEATURES])


@dataclass
class SeqData:
    frame: pd.DataFrame        # row metadata (dataset, capture, host, window, stage, ...)
    x: np.ndarray              # [N, F] scaled features
    nb: np.ndarray             # [N, 2F+1] neighbour aggregates
    risk: np.ndarray           # [N] 0/1
    stage: np.ndarray          # [N] int
    starts: dict[str, np.ndarray]   # split -> sequence start row indices
    scaler: FeatureScaler
    T: int


def load_windows(datasets: list[str]) -> tuple[pd.DataFrame, pd.DataFrame]:
    fr, ed = [], []
    for d in datasets:
        fr.append(pd.read_parquet(PROCESSED / f"{d}.windows.parquet"))
        ed.append(pd.read_parquet(PROCESSED / f"{d}.edges.parquet"))
    frame = pd.concat(fr, ignore_index=True)
    frame = frame.sort_values(["dataset", "capture", "host", "segment", "window"]).reset_index(drop=True)
    return frame, pd.concat(ed, ignore_index=True)


def fill_episode_gaps(frame: pd.DataFrame, max_gap: int) -> np.ndarray:
    """Attack episodes: attack windows of one host separated by <= max_gap quiet windows are
    one campaign (a bot-infected host is still compromised between beacons). Returns stage[]."""
    stage = frame["stage"].to_numpy().astype(np.int64).copy()
    if max_gap <= 0:
        return stage
    g = frame.groupby(["dataset", "capture", "host", "segment"], sort=False).ngroup().to_numpy()
    idx = np.flatnonzero(stage > 0)
    for a, b in zip(idx[:-1], idx[1:]):
        if g[a] == g[b] and 1 < b - a <= max_gap + 1:
            stage[a + 1:b] = stage[a]
    return stage


def sequence_starts(frame: pd.DataFrame, T: int) -> tuple[np.ndarray, np.ndarray]:
    """Valid sequence starts and their split id (-1 if the sequence crosses a block)."""
    g = frame.groupby(["dataset", "capture", "host", "segment"], sort=False).ngroup().to_numpy()
    n = len(frame)
    idx = np.arange(n - T + 1)
    same = g[idx] == g[idx + T - 1]
    cap_code = frame.groupby(["dataset", "capture"], sort=False).ngroup().to_numpy()
    wmin = frame.groupby(["dataset", "capture"])["window"].transform("min").to_numpy()
    block = (frame["window"].to_numpy() - wmin) // BLOCK_WINDOWS
    split = CYCLE[(block + cap_code) % len(CYCLE)]
    same_block = block[idx] == block[idx + T - 1]
    ok = same & same_block
    return idx[ok], split[idx[ok]]


def build(datasets: list[str], history: int, horizon: int, scaler: FeatureScaler | None = None,
          all_as: str | None = None, episode_gap: int | None = None,
          capture_norm: bool | None = None) -> SeqData:
    """``all_as='test'`` puts every valid sequence in one split (zero-shot evaluation)."""
    frame, edges = load_windows(datasets)
    T = history + horizon
    starts, split = sequence_starts(frame, T)
    raw = frame[FEATURE_COLUMNS].to_numpy(np.float32)
    groups = frame.groupby(["dataset", "capture"], sort=False).ngroup().to_numpy()
    if scaler is None:
        if capture_norm is None:
            from src.utils.config import world_model_config
            capture_norm = bool(world_model_config()["data"].get("capture_norm", False))
        train_rows = np.unique((starts[split == 0][:, None] + np.arange(T)).ravel())
        scaler = FeatureScaler.fit(raw[train_rows], groups[train_rows], capture_norm)
    x = scaler.transform(raw, groups)
    nb = neighbor_aggregate(frame, x, edges, group_cols=("dataset", "capture"))
    if all_as:
        parts = {all_as: starts}
    else:
        parts = {name: starts[split == k] for k, name in enumerate(["train", "val", "test"])}
    if episode_gap is None:
        from src.utils.config import world_model_config
        episode_gap = world_model_config()["data"].get("episode_gap", 0)
    stage = fill_episode_gaps(frame, episode_gap)
    frame = frame.assign(stage=stage)
    meta = frame[["dataset", "capture", "host", "segment", "window", "t", "stage", "attack_out"]]
    return SeqData(meta, x, nb, (stage > 0).astype(np.float32), stage, parts, scaler, T)


def gather(data: SeqData, starts: np.ndarray, mask_dropout: float = 0.0,
           rng: np.random.Generator | None = None):
    rows = starts[:, None] + np.arange(data.T)
    x = data.x[rows].copy()
    nb = data.nb[rows]
    if mask_dropout > 0 and rng is not None:
        drop = rng.random(len(starts)) < mask_dropout
        x[np.ix_(drop, np.arange(data.T), PACKET_IDX)] = 0.0
    return x, nb, data.risk[rows], data.stage[rows]


def future_target(data: SeqData, starts: np.ndarray, history: int) -> tuple[np.ndarray, np.ndarray]:
    """(attack within the forecast horizon, attack at the current step)."""
    rows = starts[:, None] + np.arange(data.T)
    r = data.risk[rows]
    return r[:, history:].max(1), r[:, history - 1]


def balance_train(data: SeqData, starts: np.ndarray, keep: float, seed: int) -> np.ndarray:
    """Keep every sequence touching an attack; subsample all-benign ones (class balancing)."""
    rows = starts[:, None] + np.arange(data.T)
    has_attack = data.risk[rows].max(1) > 0
    rng = np.random.default_rng(seed)
    keep_mask = has_attack | (rng.random(len(starts)) < keep)
    return starts[keep_mask]
