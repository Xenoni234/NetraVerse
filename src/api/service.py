"""Analysis service: FeatureMatrix -> forecasts, MITRE stages, explanations, roles, decisions.

This is the only code path the API uses for CSV, PCAP and live input alike: the
same fusion output, the same trained weights, the same ``rollout`` (R7, R22).
"""
from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field

import numpy as np
import pandas as pd
import torch

from src.decision import counterfactual as CF
from src.decision.rule_engine import Action, all_actions, recommend
from src.explainability.captum_explainer import explain
from src.features import schema as S
from src.features.fusion import windowize
from src.graph.graph_utils import neighbor_aggregate
from src.graph.host_graph_builder import roles_at, topology_snapshot
from src.live import action_executor
from src.mitre.mitre_lookup import stage_info, stage_names
from src.mitre.stage_mapper import map_sequence, map_stage
from src.models.rollout import Intervention, batch_forecast, rollout
from src.models.world_model import load_checkpoint
from src.utils.config import MODELS, world_model_config


# ---------------------------------------------------------------- model holder
class Engine:
    def __init__(self, ckpt: str | None = None):
        dev = "cuda" if torch.cuda.is_available() else "cpu"
        self.device = torch.device(dev)
        path = ckpt or str(MODELS / "world_model.pt")
        self.model, self.scaler, ck = load_checkpoint(path, self.device)
        self.cfg = ck["config"]
        self.calib = ck.get("calibration")
        self.threshold = float(self.cal(ck["threshold"]))           # operating point, calibrated scale
        self.L = self.cfg["windowing"]["history"]
        self.K = self.cfg["windowing"]["horizon"]
        self.window_s = self.cfg["windowing"]["window_s"]
        self.mc = self.cfg.get("eval", {}).get("mc_samples", 16)
        self.alert_n = self.cfg.get("eval", {}).get("alert_consecutive", 2)
        m = self.scaler.mean.copy()
        m[self.scaler.LOG_IDX] = np.expm1(m[self.scaler.LOG_IDX])
        self.typical = m                                    # unscaled "average window"
        self.idle_scaled = self.scaler.transform(np.zeros((1, S.N_FEATURES), np.float32))[0]
        self.lock = threading.Lock()
        self.checkpoint = path
        self.trained_on = ck.get("trained_on")
        self.metrics = ck.get("metrics", {})

    def cal(self, p):
        """Platt calibration fitted on validation (monotone; see train_world_model.fit_calibration)."""
        if not self.calib or p is None:
            return p
        q = np.clip(np.asarray(p, dtype=np.float64), 1e-6, 1 - 1e-6)
        return 1 / (1 + np.exp(-(self.calib["a"] * np.log(q / (1 - q)) + self.calib["b"])))

    # -- tensors -------------------------------------------------------------
    def prepare(self, fm: S.FeatureMatrix):
        frame = fm.frame.sort_values(["host", "segment", "window"]).reset_index(drop=True)
        fm.frame = frame
        x = self.scaler.transform(frame[S.FEATURE_COLUMNS].to_numpy(np.float32))
        nb = neighbor_aggregate(frame, x, fm.edges)
        return frame, x, nb

    def histories(self, frame: pd.DataFrame, x: np.ndarray, nb: np.ndarray, rows: np.ndarray | None = None):
        """[N, L, *] history ending at each row; windows before a host's first one = idle traffic."""
        g = frame.groupby(["host", "segment"], sort=False).cumcount().to_numpy()
        rows = np.arange(len(frame)) if rows is None else rows
        offs = np.arange(self.L - 1, -1, -1)
        idx = rows[:, None] - offs[None, :]
        valid = offs[None, :] <= g[rows][:, None]
        xp = np.vstack([x, self.idle_scaled[None]])
        nbp = np.vstack([nb, np.zeros((1, nb.shape[1]), np.float32)])
        idx = np.where(valid, idx, len(x))
        return xp[idx], nbp[idx]

    @torch.no_grad()
    def forecast_rows(self, xh: np.ndarray, nbh: np.ndarray, mc: int | None = None, batch: int = 4096):
        mc = self.mc if mc is None else mc
        outs = []
        with self.lock:
            for i in range(0, len(xh), batch):
                o = batch_forecast(self.model, torch.as_tensor(xh[i:i + batch], device=self.device),
                                   torch.as_tensor(nbh[i:i + batch], device=self.device),
                                   self.L, self.K, mc=mc)
                outs.append(o)
        keys = outs[0].keys()
        res = {k: (np.concatenate([o[k] for o in outs]) if outs[0][k] is not None else None) for k in keys}
        for k in ("future", "lo", "hi", "now"):
            if res.get(k) is not None:
                res[k] = self.cal(res[k])
        return res

    def state_at(self, xh: np.ndarray, nbh: np.ndarray):
        with self.lock:
            return self.model.encode(torch.as_tensor(xh, device=self.device),
                                     torch.as_tensor(nbh, device=self.device))

    def rollout_at(self, xh, nbh, action_id: str | None = None) -> dict:
        st = self.state_at(xh, nbh)
        with self.lock:
            r = rollout(self.model, st, self.K,
                        Intervention(action_id, st) if action_id else None, mc=self.mc,
                        window_s=self.window_s)
        d = r.to_dict()
        for k in ("probs", "lo", "hi"):
            d[k] = [round(float(v), 4) for v in self.cal(d[k])]
        d["peak"] = round(float(max(d["probs"])), 4)
        return d

    def explain_rows(self, xh, nbh, raw_last) -> list[list[dict]]:
        with self.lock:
            return explain(self.model, xh, nbh, raw_last, self.typical, self.K)


# ---------------------------------------------------------------- analysis
@dataclass
class Analysis:
    id: str
    source: str
    filename: str
    fm: S.FeatureMatrix
    frame: pd.DataFrame
    x: np.ndarray
    nb: np.ndarray
    fc: dict                                   # per-row forecast arrays
    steps: np.ndarray                          # global window indices
    created: float = field(default_factory=time.time)
    explain_cache: dict = field(default_factory=dict)
    branches: dict = field(default_factory=dict)
    decisions: list = field(default_factory=list)


def _alert_step(series: np.ndarray, thr: float, n: int) -> int | None:
    run = 0
    for i, v in enumerate(series):
        run = run + 1 if v >= thr else 0
        if run >= n:
            return i
    return None


class Service:
    def __init__(self, engine: Engine):
        self.E = engine
        self.analyses: dict[str, Analysis] = {}

    # -- build -----------------------------------------------------------------
    def analyze(self, fm: S.FeatureMatrix, filename: str = "", aid: str | None = None) -> Analysis:
        frame, x, nb = self.E.prepare(fm)
        xh, nbh = self.E.histories(frame, x, nb)
        fc = self.E.forecast_rows(xh, nbh)
        steps = np.arange(frame["window"].min(), frame["window"].max() + 1)
        a = Analysis(aid or uuid.uuid4().hex[:12], fm.source, filename, fm, frame, x, nb, fc, steps)
        self.analyses[a.id] = a
        return a

    # -- per-host series aligned to global steps --------------------------------
    def host_series(self, a: Analysis, host: str, fc: dict | None = None, frame: pd.DataFrame | None = None):
        frame = a.frame if frame is None else frame
        fc = a.fc if fc is None else fc
        rows = np.flatnonzero((frame["host"] == host).to_numpy())
        pos = frame["window"].to_numpy()[rows] - a.steps[0]
        n = len(a.steps)
        def blank(fill=0.0, shape=()):
            return np.full((n, *shape), fill, dtype=float)
        fut = blank(shape=(self.E.K,)); lo = blank(shape=(self.E.K,)); hi = blank(shape=(self.E.K,))
        now = blank(); sp = blank(shape=(self.E.K, 7)); sp[..., 0] = 1.0
        fut[pos] = fc["future"][rows]; now[pos] = fc["now"][rows]
        if fc.get("lo") is not None:
            lo[pos] = fc["lo"][rows]; hi[pos] = fc["hi"][rows]
        sp[pos] = fc["stage_future_probs"][rows]
        present = np.zeros(n, bool); present[pos] = True
        traffic = {c: blank() for c in ("out_flows", "in_flows", "out_distinct_dst", "out_distinct_dport",
                                        "in_distinct_src")}
        for c in traffic:
            traffic[c][pos] = frame[c].to_numpy()[rows]
        truth = None
        if a.fm.labelled and "stage" in frame:
            truth = np.zeros(n, int); truth[pos] = frame["stage"].to_numpy()[rows]
        return {"rows": rows, "pos": pos, "future": fut, "lo": lo, "hi": hi, "now": now,
                "stage_probs": sp, "present": present, "traffic": traffic, "truth": truth}

    def overview(self, a: Analysis) -> dict:
        thr = self.E.threshold
        hosts = []
        for h in a.frame["host"].unique():
            s = self.host_series(a, h)
            peak_curve = s["future"].max(1)
            al = _alert_step(peak_curve, thr, self.E.alert_n)
            i_peak = int(np.argmax(peak_curve))
            stg = map_stage(peak_curve[i_peak], s["stage_probs"][i_peak].max(0), thr)
            hosts.append({"host": h, "peak": round(float(peak_curve.max()), 4),
                          "first_alert_step": al, "stage": stg, "stage_name": stage_names()[stg],
                          "flows": int(s["traffic"]["out_flows"].sum() + s["traffic"]["in_flows"].sum()),
                          "truth_attack_steps": int((s["truth"] > 0).sum()) if s["truth"] is not None else None})
        hosts.sort(key=lambda h: (h["first_alert_step"] is None, h["first_alert_step"] or 0, -h["peak"]))
        alerting = [h for h in hosts if h["first_alert_step"] is not None]
        focus = alerting[0]["host"] if alerting else (max(hosts, key=lambda h: h["peak"])["host"] if hosts else None)
        return {
            "id": a.id, "source": a.source, "filename": a.filename, "labelled": a.fm.labelled,
            "n_flows": a.fm.meta.get("n_flows"), "n_hosts": len(hosts), "n_steps": len(a.steps),
            "t0": float(a.fm.meta["t0"] + a.steps[0] * self.E.window_s), "window_s": self.E.window_s,
            "horizon_s": self.E.K * self.E.window_s, "threshold": round(thr, 4),
            "focus_host": focus, "decision_step": alerting[0]["first_alert_step"] if alerting else None,
            "hosts": hosts, "model": {"checkpoint": self.E.checkpoint, "trained_on": self.E.trained_on},
        }

    def timeline(self, a: Analysis, host: str) -> dict:
        thr = self.E.threshold
        s = self.host_series(a, host)
        peak_curve = s["future"].max(1)
        stage_seq = map_sequence(peak_curve, s["stage_probs"].max(1), thr)
        stage_now = [map_stage(r, sp[0], thr) for r, sp in zip(s["now"], s["stage_probs"])]
        al = _alert_step(peak_curve, thr, self.E.alert_n)
        t0 = a.fm.meta["t0"]
        res = {
            "host": host, "threshold": round(thr, 4), "window_s": self.E.window_s, "horizon_s": self.E.K * self.E.window_s,
            "t": [float(t0 + w * self.E.window_s) for w in a.steps],
            "risk": [round(float(v), 4) for v in peak_curve],           # P(attack within 300 s)
            "risk_now": [round(float(v), 4) for v in s["now"]],
            "future": np.round(s["future"], 4).tolist(), "lo": np.round(s["lo"], 4).tolist(),
            "hi": np.round(s["hi"], 4).tolist(),
            "stage": stage_seq, "stage_now": stage_now, "stage_names": stage_names(),
            "present": s["present"].tolist(),
            "traffic": {k: v.astype(int).tolist() for k, v in s["traffic"].items()},
            "truth_stage": s["truth"].tolist() if s["truth"] is not None else None,
            "first_alert_step": al,
        }
        # FR11 early-warning margin: alert time vs predicted (and, if labelled, actual) compromise
        if al is not None:
            fut = s["future"][al]
            k_hit = next((k for k, v in enumerate(fut) if v >= max(thr, 0.5)), int(np.argmax(fut)))
            res["predicted_compromise_s_after_alert"] = (k_hit + 1) * self.E.window_s
            if s["truth"] is not None:
                first_truth = next((i for i, v in enumerate(s["truth"]) if v > 0), None)
                res["actual_first_attack_step"] = first_truth
                res["lead_time_s"] = (first_truth - al) * self.E.window_s if first_truth is not None else None
        return res

    # -- explanations (every forecast shown can be explained, R5) ----------------
    def explain_step(self, a: Analysis, host: str, step: int) -> list[dict]:
        key = (host, step)
        if key in a.explain_cache:
            return a.explain_cache[key]
        s = self.host_series(a, host)
        pos = np.flatnonzero(s["pos"] == step)
        if len(pos) == 0:
            return []
        row = s["rows"][pos[0]]
        xh, nbh = self.E.histories(a.frame, a.x, a.nb, np.array([row]))
        raw = a.frame[S.FEATURE_COLUMNS].to_numpy(np.float32)[[row]]
        items = self.E.explain_rows(xh, nbh, raw)[0]
        a.explain_cache[key] = items
        return items

    # -- topology ------------------------------------------------------------------
    def topology(self, a: Analysis, step: int, max_nodes: int = 60) -> dict:
        branch = self._active_branch(a, step)
        frame = branch["frame"] if branch else a.frame
        fc = branch["fc"] if branch else a.fc
        edges = branch["edges"] if branch else a.fm.edges
        rows = frame["window"].to_numpy() == a.steps[0] + step
        risk = dict(zip(frame["host"].to_numpy()[rows], fc["future"][rows].max(1)))
        stage_p = dict(zip(frame["host"].to_numpy()[rows], fc["stage_future_probs"][rows].max(1)))
        roles = roles_at(edges, a.steps[0] + step, risk, self.E.threshold)
        mitigated = set()
        if branch:
            act: Action = branch["action"]
            mitigated = {h for h in [act.peer, *act.peers] if h} if act.kind in (
                "block_source", "block_pair", "rate_limit") else {act.target}
            if act.kind == "block_source":
                mitigated = set(roles.get("_victims_of", {}).get(act.target, [])) or mitigated
        snap = topology_snapshot(frame, edges, a.steps[0] + step, risk, stage_p, roles,
                                 self.E.threshold, mitigated, max_nodes)
        snap["step"] = step
        snap["branch"] = branch["action"].id if branch else None
        return snap

    # -- decision point ------------------------------------------------------------
    def decision_context(self, a: Analysis, host: str, step: int) -> dict:
        thr = self.E.threshold
        s = self.host_series(a, host)
        pos = np.flatnonzero(s["pos"] == step)
        peak = float(s["future"][step].max())
        stage = map_stage(peak, s["stage_probs"][step].max(0), thr)
        w = a.steps[0] + step
        risk_all = {}
        rows = a.frame["window"].to_numpy() == w
        risk_all = dict(zip(a.frame["host"].to_numpy()[rows], a.fc["future"][rows].max(1)))
        roles = roles_at(a.fm.edges, w, risk_all, thr, focus=host)
        info = roles.get(host, {})
        role = info.get("role", "attacker")
        attacker = host if role == "attacker" else info.get("attacker", host)
        victims = roles.get("_victims_of", {}).get(attacker, []) or ([host] if role == "victim" else [])
        # service port and egress peers from the raw flows of the last 3 windows
        fl = a.fm.flows
        t_hi = a.fm.meta["t0"] + (w + 1) * self.E.window_s
        recent = fl[(fl["ts_end"] >= t_hi - 3 * self.E.window_s) & (fl["ts_end"] < t_hi)]
        pair = recent[(recent["src_ip"] == attacker) & (recent["dst_ip"].isin(victims or [host]))]
        top_port = int(pair["dport"].mode().iloc[0]) if len(pair) else None
        egress = recent[recent["src_ip"] == host]["dst_ip"].value_counts().head(5).index.tolist()
        drivers = self.explain_step(a, host, step) if len(pos) else []
        ctx = {"host": host, "role": role, "attacker": attacker, "victims": victims,
               "c2_peers": egress, "top_port": top_port}
        rec = recommend(stage, drivers, ctx)
        narration = None
        return {"host": host, "step": step, "stage": stage_info(stage), "risk": round(peak, 4),
                "context": ctx, "recommended": rec.to_dict(), "driving_features": drivers,
                "narration": narration}

    def decide(self, a: Analysis, host: str, step: int, choice: str, action: dict | None,
               live: bool = False) -> dict:
        ctx = self.decision_context(a, host, step)
        rec = Action.from_dict(ctx["recommended"])
        options = {x.id: x for x in all_actions(rec)}
        if choice == "reject":
            act = next(x for x in all_actions(rec) if x.kind == "monitor")
        elif choice == "accept":
            act = rec
        else:
            act = Action.from_dict(action) if isinstance(action, dict) else options.get(str(action))
            if act is None or act.id not in options:
                raise ValueError("Modify must pick one of the rule-engine alternatives.")
        w = a.steps[0] + step
        t_from = a.fm.meta["t0"] + w * self.E.window_s
        before = self._rollout_row(a, a.frame, a.x, a.nb, host, w)
        enforcement = action_executor.apply(act, live=live).to_dict()
        if act.kind == "monitor":
            after, branch = before, None
        else:
            flows2 = CF.apply_to_flows(a.fm.flows, act, t_from)
            fm2 = windowize(flows2, window_s=self.E.window_s, hosts=a.fm.meta["hosts"],
                            t0=a.fm.meta["t0"], source=a.source)
            frame2, x2, nb2 = self.E.prepare(fm2)
            xh2, nbh2 = self.E.histories(frame2, x2, nb2)
            fc2 = self.E.forecast_rows(xh2, nbh2)
            after = self._rollout_row(a, frame2, x2, nb2, host, w, act.id)
            branch = {"action": act, "step": step, "frame": frame2, "fc": fc2, "edges": fm2.edges,
                      "fm": fm2}
        a.branches = {"active": branch} if branch else {}
        rec_d = {"choice": choice, "action": act.to_dict(), "host": host, "step": step,
                 "enforcement": enforcement, "at": time.time()}
        a.decisions.append(rec_d)
        cont = None
        if branch:
            ts = self.host_series(a, host, branch["fc"], branch["frame"])
            cont = {"risk": [round(float(v), 4) for v in ts["future"].max(1)],
                    "future": np.round(ts["future"], 4).tolist()}
        return {**rec_d, "before": before, "after": after, "delta": CF.delta(before["probs"], after["probs"]),
                "continuation": cont, "decision_context": ctx}

    def _rollout_row(self, a, frame, x, nb, host, w, action_id=None) -> dict:
        rows = np.flatnonzero(((frame["host"] == host) & (frame["window"] == w)).to_numpy())
        if len(rows) == 0:
            return {"probs": [0.0] * self.E.K, "lo": [0.0] * self.E.K, "hi": [0.0] * self.E.K, "peak": 0.0,
                    "stages": [0] * self.E.K, "horizon_s": [self.E.window_s * (k + 1) for k in range(self.E.K)]}
        xh, nbh = self.E.histories(frame, x, nb, rows)
        return self.E.rollout_at(xh, nbh, action_id)

    def _active_branch(self, a: Analysis, step: int):
        b = a.branches.get("active")
        return b if b and step >= b["step"] else None

    def reset_branch(self, a: Analysis) -> None:
        a.branches = {}

    def branch_timeline(self, a: Analysis, host: str) -> dict | None:
        b = a.branches.get("active")
        if not b:
            return None
        s = self.host_series(a, host, b["fc"], b["frame"])
        return {"from_step": b["step"], "action": b["action"].to_dict(),
                "risk": [round(float(v), 4) for v in s["future"].max(1)],
                "future": np.round(s["future"], 4).tolist(), "lo": np.round(s["lo"], 4).tolist(),
                "hi": np.round(s["hi"], 4).tolist()}


_SERVICE: Service | None = None


def get_service() -> Service:
    global _SERVICE
    if _SERVICE is None:
        _SERVICE = Service(Engine())
    return _SERVICE


def default_config() -> dict:
    return world_model_config()
