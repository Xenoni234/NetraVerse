"""Neighbourhood aggregation over the per-window host graph (GraphSAGE message passing).

For every (host, window) row we aggregate the scaled feature vectors of the hosts
it exchanged flows with in that same window - mean and max aggregators plus the
log-degree - using torch_geometric's scatter. ``models.gnn.HostSAGE`` consumes
these aggregates; this is exactly one GraphSAGE hop, precomputed so the RSSM can
batch over time.
"""
from __future__ import annotations

import numpy as np
import pandas as pd
import torch
from torch_geometric.utils import scatter


def neighbor_aggregate(frame: pd.DataFrame, x_scaled: np.ndarray, edges: pd.DataFrame | None,
                       group_cols: tuple[str, ...] = ()) -> np.ndarray:
    """Return [N, 2F+1] = [mean_nb(x), max_nb(x), log1p(degree)] aligned with ``frame`` rows."""
    n, f = x_scaled.shape
    out = np.zeros((n, 2 * f + 1), dtype=np.float32)
    if edges is None or len(edges) == 0:
        return out
    keys = list(group_cols) + ["host", "window"]
    pos = pd.Series(np.arange(n), index=pd.MultiIndex.from_frame(frame[keys]))
    e = edges[list(group_cols) + ["a", "b", "window"]]
    und = pd.concat([e, e.rename(columns={"a": "b", "b": "a"})], ignore_index=True).drop_duplicates()
    ia = pos.reindex(pd.MultiIndex.from_frame(und[list(group_cols) + ["a", "window"]]
                                              .rename(columns={"a": "host"}))).to_numpy()
    ib = pos.reindex(pd.MultiIndex.from_frame(und[list(group_cols) + ["b", "window"]]
                                              .rename(columns={"b": "host"}))).to_numpy()
    ok = ~(np.isnan(ia) | np.isnan(ib))
    if not ok.any():
        return out
    ia = torch.as_tensor(ia[ok].astype(np.int64))
    ib = torch.as_tensor(ib[ok].astype(np.int64))
    xb = torch.as_tensor(x_scaled)[ib]
    mean = scatter(xb, ia, dim=0, dim_size=n, reduce="mean")
    mx = scatter(xb, ia, dim=0, dim_size=n, reduce="max")
    deg = scatter(torch.ones_like(ia, dtype=torch.float32), ia, dim=0, dim_size=n, reduce="sum")
    out[:, :f] = mean.numpy()
    out[:, f:2 * f] = mx.numpy()
    out[:, -1] = np.log1p(deg.numpy())
    return out
