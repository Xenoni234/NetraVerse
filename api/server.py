"""FastAPI backend for the Network Attack Forecasting frontend.

Wraps the real world model (src.inference.engine) and the demo helpers so the
Stitch HTML frontend can render live forecasts, explanations, network trends,
benchmarks, the model card, and an uploaded-capture pipeline with visible
processing stages. Offline, CPU. No model/pipeline semantics are changed here.

Run:  uvicorn api.server:app --port 8000       (from the repo root, in the venv)
"""
from __future__ import annotations

import json
import os
import threading
import time
import uuid
from pathlib import Path

import numpy as np
import pandas as pd
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

ROOT = Path(__file__).resolve().parents[1]
import sys
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.data.windowing import apply_scaler
from src.inference.engine import FEATURE_LABELS, load_forecaster, lead_time_seconds, explain_window
from src.explain.shap_wrapper import RiskExplainer
from src.mitre.stage_mapping import STAGE_NAMES, STAGE_TACTICS, STAGE_DESCRIPTIONS, stage_defence
from demo.helpers import (PACKET_FEATURES, attack_intervals, benign_references,
    campaign_label, first_sustained, host_catalog, ingest_upload)

# Serve wm_final: the only checkpoint that discriminates on real data.
# wm_phase6 collapsed to a constant (val/test had zero positive onsets at the long
# horizons -> threshold calibrated to 1.0, risk head always ~benign), so it returned
# the same forecast for every host. Re-enable a phase6/long-horizon checkpoint here
# ONLY once its calibration split contains real positive onsets. See metrics.json.
_SIH_DEFAULT = ROOT / "models/wm_sih_demo/best.ckpt"
CKPT = Path(os.environ.get("NETRAVERSE_CHECKPOINT", _SIH_DEFAULT if _SIH_DEFAULT.exists() else ROOT / "models/wm_final/best.ckpt"))
BENCH = ROOT / "models/wm_final/benchmark.json"
GENERALIZATION = ROOT / "models/wm_final/generalization.json"
LIVE_PRED = ROOT / "reports/live/predictions.parquet"  # written by scripts/live_forecast.py

# our stage id -> frontend stage label
STAGE_UI = {0: "BENIGN", 1: "RECONNAISSANCE", 2: "INITIAL ACCESS", 3: "LATERAL MOVEMENT",
            4: "COMMAND AND CONTROL", 5: "EXFILTRATION", 6: "IMPACT"}
STAGE_UI_TO_ID = {v: k for k, v in STAGE_UI.items()}

app = FastAPI(title="Network Attack Forecasting API")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

_STATE = {"forecaster": None, "explainer": None, "baseline": None, "gallery": None,
          "gallery_path": None, "endpoint_frames": {}, "lock": threading.RLock()}
_UPLOADS: dict[str, dict] = {}


def _forecaster():
    if _STATE["forecaster"] is None:
        _STATE["forecaster"] = load_forecaster(str(CKPT), device="cpu")
    return _STATE["forecaster"]


def _gallery():
    if _STATE["gallery"] is None:
        cands = sorted((ROOT / "data/processed").glob("windows_cicids2017_all_+2018_+ctu13_*.parquet"),
                       key=lambda p: p.stat().st_mtime_ns)
        if not cands:
            raise HTTPException(500, "No gallery parquet found under data/processed.")
        _STATE["gallery_path"] = cands[-1]
        _STATE["gallery"] = pd.read_parquet(cands[-1])
    return _STATE["gallery"]


def _explainer():
    if _STATE["explainer"] is None:
        fc = _forecaster()
        raw = benign_references(_gallery(), fc.feature_names, fc.history_length)
        _STATE["explainer"] = RiskExplainer(fc.model, apply_scaler(raw, fc.scaler),
                                            feature_names=fc.feature_names, horizon=4, device="cpu")
        _STATE["baseline"] = pd.Series(np.median(raw.reshape(-1, raw.shape[-1]), axis=0),
                                       index=fc.feature_names)
    return _STATE["explainer"], _STATE["baseline"]


def _iso(ts) -> str:
    return pd.Timestamp(ts).strftime("%Y-%m-%dT%H:%M:%SZ")


def _alert_events(host: pd.DataFrame, timeline: pd.DataFrame, *, horizon: int,
                  threshold: float, min_lead: int = 60, max_lead: int = 300) -> list[dict]:
    """Match sustained alert decisions to individual labelled attack onsets.

    A threshold crossing far before an onset is not allowed to masquerade as a
    warning for that onset.  The event log therefore searches the requested
    60--300 second decision window first, then records an at-onset/late event
    only when the model failed to warn early.
    """
    if "binary_label" not in host:
        return []
    intervals = attack_intervals(host)
    if not intervals or timeline.empty:
        return []
    key = f"risk_k{horizon}"
    rows = timeline.sort_values("window_start").reset_index(drop=True)
    events = []
    for onset, _ in intervals:
        candidates = []
        for i in range(1, len(rows)):
            prev, cur = rows.iloc[i - 1], rows.iloc[i]
            if (cur.window_start - prev.window_start).total_seconds() != 30:
                continue
            if float(prev[key]) < threshold or float(cur[key]) < threshold:
                continue
            alert_at = pd.Timestamp(cur.window_start) + pd.Timedelta(seconds=30)
            lead = (pd.Timestamp(onset) - alert_at).total_seconds()
            candidates.append((alert_at, lead, cur))
        early = [x for x in candidates if min_lead <= x[1] <= max_lead]
        if early:
            alert_at, lead, row = early[0]
            status = "early_warning"
        else:
            after = [x for x in candidates if x[1] < min_lead]
            if after:
                alert_at, lead, row = after[0]
                status = "at_onset" if lead >= -30 else "late"
            else:
                alert_at, lead, row = None, None, None
                status = "missed"
        onset_rows = host.loc[pd.to_datetime(host["window_start"], utc=True) == pd.Timestamp(onset)] if "window_start" in host else pd.DataFrame()
        onset_stage = int(onset_rows.iloc[0].get("attt_stage", 0)) if not onset_rows.empty else 0
        event_stage = STAGE_UI.get(onset_stage, "BENIGN")
        events.append({"onset_at": _iso(onset), "alert_at": _iso(alert_at) if alert_at is not None else None,
                       "lead_time_s": round(float(lead), 0) if lead is not None else None,
                       "status": status,
                       "stage": event_stage,
                       "action": dict(stage_defence(STAGE_UI_TO_ID.get(event_stage, 0)))})
    return events


def _prediction_decision_log(timeline: pd.DataFrame, *, horizon: int, threshold: float,
                             labelled_events: list[dict] | None = None) -> list[dict]:
    """Return one decision record for each sustained threshold alert episode."""
    if timeline.empty:
        return []
    key = f"risk_k{horizon}"
    rows = timeline.sort_values("window_start").reset_index(drop=True)
    labelled_events = labelled_events or []
    records = []
    in_episode = False
    for i in range(1, len(rows)):
        prev, cur = rows.iloc[i - 1], rows.iloc[i]
        sustained = float(prev[key]) >= threshold and float(cur[key]) >= threshold
        if not sustained:
            if float(cur[key]) < threshold:
                in_episode = False
            continue
        if in_episode:
            continue
        in_episode = True
        alert_at = pd.Timestamp(cur.window_start) + pd.Timedelta(seconds=30)
        match = next((event for event in labelled_events
                      if event.get("alert_at") and abs((pd.Timestamp(event["alert_at"]) - alert_at).total_seconds()) <= 31), None)
        stage = (match or {}).get("stage") or STAGE_UI.get(int(cur[f"stage_k{horizon}"]), "UNMAPPED")
        records.append({
            "window_at": _iso(cur.window_start),
            "alert_at": _iso(alert_at),
            "onset_at": (match or {}).get("onset_at"),
            "lead_time_s": (match or {}).get("lead_time_s"),
            "status": (match or {}).get("status", "threshold_crossing"),
            "stage": stage,
            "risk": round(float(cur[key]), 4),
            "action": dict((match or {}).get("action") or stage_defence(STAGE_UI_TO_ID.get(stage, 0))),
        })
    return records


def _timeline_payload(host: pd.DataFrame, *, known: bool, mc: int = 0) -> dict:
    """Build the full per-host forecast payload the frontend pages consume."""
    fc = _forecaster()
    with _STATE["lock"]:
        tl = fc.forecast_host_timeline(host, mc_samples=mc)
    if tl.empty:
        raise HTTPException(422, "Host has fewer than 10 consecutive 30-second windows.")
    # Horizon values are decoder steps: SIH uses 2/3/4 windows (+60/+90/+120s).
    primary_horizon = max(fc.horizons)
    thr = fc.threshold_for_horizon(primary_horizon)
    merged = host.merge(tl, on="window_start", how="right").sort_values("window_start")

    observed = []
    for _, r in merged.iterrows():
        horizon_data = {}
        for k in fc.horizons:
            risk = float(r[f"risk_k{k}"])
            horizon_data[f"+{k * 30}s"] = {
                "risk": round(risk, 4),
                "stage": STAGE_UI.get(int(r[f"stage_k{k}"]), "UNMAPPED"),
                "tactic": STAGE_TACTICS.get(int(r[f"stage_k{k}"]), ""),
                "confidence": "High" if risk >= 0.6 else "Medium" if risk >= fc.threshold_for_horizon(k) else "Low",
                "utc": _iso(pd.Timestamp(r.window_start) + pd.Timedelta(seconds=30 * k)),
                "uncertainty": (round(float(r.get(f"risk_hi_k{k}", risk)) - float(r.get(f"risk_lo_k{k}", risk)), 4)
                                if mc else None),
            }
        observed.append({
            "t": _iso(r.window_start),
            "risk": round(float(r[f"risk_k{primary_horizon}"]), 4),
            "stage": STAGE_UI.get(int(r[f"stage_k{primary_horizon}"]), "UNMAPPED"),
            "observed_stage": (STAGE_UI.get(int(r.get("attt_stage", 0)), "UNMAPPED") if known else None),
            "attack_family": (str(r.get("attack_family", "BENIGN")) if known else None),
            "attention": round(float(np.asarray(r.get(f"attn_k{primary_horizon}", 0.0)).max()), 4),
            "attention_weights": [round(float(x), 5) for x in np.asarray(r.get(f"attn_k{primary_horizon}", []), dtype=float).reshape(-1)],
            "horizons": horizon_data,
            "flows": int(r.get("n_flows", 0)),
            "pktRate": round(float(r.get("pkts_per_sec", 0.0)), 2),
            "byteRate": round(float(r.get("bytes_per_sec", 0.0)), 1),
            "synCount": int(r.get("syn_count", 0)),
            "distinctPorts": int(r.get("n_distinct_dst_port", 0)),
            "portEntropy": round(float(r.get("dst_port_entropy", 0.0)), 3),
            "uniqueDsts": int(r.get("n_distinct_dst_ip", 0)),
            "failedConns": round(float(r.get("failed_conn_ratio", 0.0)), 3),
            "iat": round(float(r.get("mean_iat_s", 0.0)), 4),
        })

    # per-horizon forecast (the K-step trajectory) from the highest-risk window,
    # so the forecast shows the meaningful rising path rather than a quiet tail.
    focus = tl.loc[tl[f"risk_k{primary_horizon}"].idxmax()]
    steps = []
    for k in fc.horizons:
        rk = float(focus[f"risk_k{k}"])
        band = (round(float(focus.get(f"risk_hi_k{k}", rk)) - float(focus.get(f"risk_lo_k{k}", rk)), 4)
                if mc else None)
        steps.append({"horizon": f"+{k*30}s", "utc": _iso(pd.Timestamp(focus.window_start)+pd.Timedelta(seconds=30*k)),
                      "risk": round(rk, 4), "uncertainty": band,
                      "stage": STAGE_UI.get(int(focus[f"stage_k{k}"]), "UNMAPPED"),
                      "tactic": STAGE_TACTICS.get(int(focus[f"stage_k{k}"]), ""),
                      "confidence": "High" if rk >= 0.6 else "Medium" if rk >= thr else "Low"})

    alert = first_sustained(tl, f"risk_k{primary_horizon}", thr)
    lead = lead_time_seconds(tl, horizon_key=f"risk_k{primary_horizon}", threshold=thr) if known else None
    alert_events = _alert_events(host, tl, horizon=primary_horizon, threshold=thr) if known else []
    decision_log = _prediction_decision_log(tl, horizon=primary_horizon, threshold=thr,
                                            labelled_events=alert_events)
    valid_event = next((e for e in alert_events if e["status"] == "early_warning"), None)
    if valid_event is None and alert_events:
        valid_event = next((e for e in alert_events if e["status"] != "missed"), alert_events[0])
    if valid_event is not None:
        alert = (pd.Timestamp(valid_event["alert_at"]), 0.0) if valid_event["alert_at"] else None
        lead = valid_event["lead_time_s"]
    peak = tl.loc[tl[f"risk_k{primary_horizon}"].idxmax()]

    # Plain-language summary (calculation-based, not templated fiction): describes the
    # current window, the K-step trajectory, and the model's confidence/uncertainty.
    peak_stage = STAGE_UI.get(int(peak[f"stage_k{primary_horizon}"]), "UNMAPPED")
    trend = steps[-1]["risk"] - steps[0]["risk"]
    direction = ("rising" if trend > 0.02 else "falling" if trend < -0.02 else "flat")
    over = float(peak[f"risk_k{primary_horizon}"]) >= float(thr)
    now_txt = (f"Peak forecast risk for this host is {peak[f'risk_k{primary_horizon}']*100:.1f}% "
               f"at {_iso(peak.window_start)[11:19]} UTC, "
               f"{'above' if over else 'below'} the {thr:.3f} alert threshold.")
    next_txt = (f"Over the next {primary_horizon * 30} s the model forecasts a {direction} trajectory "
                f"({steps[0]['risk']*100:.1f}% → {steps[-1]['risk']*100:.1f}%), "
                f"with predicted stage {peak_stage}.")
    if known:
        unc_txt = ("An attack is recorded in this capture; "
                   + (f"the model first alerts {abs(lead):.0f} s before onset."
                      if lead is not None and lead > 0
                      else f"the model alerts {abs(lead):.0f} s after onset."
                      if lead is not None and lead < 0
                      else "the model alerts at onset." if alert
                      else "the model does not raise a sustained alert."))
    else:
        band = steps[-1].get("uncertainty")
        unc_txt = ("This is an uploaded capture with no ground-truth labels; values are model "
                   "predictions" + (f" (±{band*100:.1f}% MC-dropout band at +120 s)." if band else "."))
    plain_language = {"now": now_txt, "next": next_txt, "uncertainty": unc_txt,
                      "trend": direction, "over_threshold": over}
    progression = []
    for row in observed:
        # For trusted labelled replays, the progression rail represents the
        # recorded ATT&CK stage.  The model forecast remains available in the
        # node's `stage` field, so a prediction cannot be mistaken for truth.
        stage = row["observed_stage"] if known and row.get("observed_stage") else row["stage"]
        if not progression or progression[-1]["stage"] != stage:
            progression.append({"stage": stage, "start": row["t"], "end": row["t"],
                                "max_risk": row["risk"],
                                "action": dict(stage_defence(STAGE_UI_TO_ID.get(stage, 0)))})
        else:
            progression[-1]["end"] = row["t"]
            progression[-1]["max_risk"] = max(progression[-1]["max_risk"], row["risk"])
    return {
        "plain_language": plain_language,
        "threshold": round(float(thr), 4),
        "primary_horizon": primary_horizon,
        "alert_level": ("urgent" if any(s["risk"] >= fc.threshold_for_horizon(k) and k <= 2 for k, s in zip(fc.horizons, steps))
                         else "warning" if any(s["risk"] >= fc.threshold_for_horizon(k) and k <= 8 for k, s in zip(fc.horizons, steps))
                         else "advisory" if over else "none"),
        "observed": observed,
        "horizons": [f"+{k * 30}s" for k in fc.horizons],
        "horizon_steps": list(fc.horizons),
        "forecast": steps,
        "progression": progression,
        "attack_intervals": [[_iso(a), _iso(b)] for a, b in attack_intervals(host)] if known else [],
        "alert_events": alert_events,
        "decision_log": decision_log,
        "first_alert": _iso(alert[0]) if alert else None,
        "lead_time_s": (None if lead is None else round(float(lead), 0)),
        "peak_risk": round(float(peak[f"risk_k{primary_horizon}"]), 4),
        "peak_at": _iso(peak.window_start),
        "focus_at": _iso(focus.window_start),
        "n_windows": int(len(host)), "n_forecasts": int(len(tl)),
        "ground_truth": bool(known),
    }


@app.get("/api/health")
def health():
    return {"ok": True, "model": CKPT.exists()}


@app.get("/api/benchmark")
def benchmark():
    return json.loads(BENCH.read_text(encoding="utf-8")) if BENCH.exists() else {}


@app.get("/api/model-card")
def model_card():
    fc = _forecaster()
    cfg = fc.model.config
    return {"parameters": fc.model.num_parameters(), "input_features": len(fc.feature_names),
            "attack_stages": cfg.n_stages, "horizons": [f"+{k*30}s" for k in fc.horizons],
            "attention": bool(cfg.use_attention), "history": f"{fc.history_length} x 30 s windows",
            "window_size": "30 s", "threshold": round(float(fc.threshold), 4),
            "training_data": "CIC-IDS2017 (all days) + CIC-IDS2018 (IP day) + CTU-13 (7 scenarios)",
            "training": "two-stage: benign-dynamics pretrain, then scheduled-sampling fine-tune (onset target)",
            "packet_features": list(PACKET_FEATURES),
            "explainability": "SHAP over state features + temporal attention",
            "phase_status": {"phase7": "telemetry health and schema readiness",
                             "phase8": "graph coverage diagnostics",
                             "phase9": "human-approved decision support",
                             "phase10": "production gates and rollback readiness"},
            "production_warning": "The 30-minute checkpoint is research-only until real long-horizon onset coverage exists."}


@app.get("/api/telemetry")
def telemetry_status():
    """Phase 7 readiness: report what telemetry is actually available."""
    fc = _forecaster()
    return {
        "sources": [
            {"name": "flow/CICFlowMeter", "status": "active", "identity": "source host", "timestamp": True,
             "features": len(fc.feature_names)},
            {"name": "DNS", "status": "not_connected", "identity": "domain", "timestamp": False, "features": 0},
            {"name": "authentication", "status": "not_connected", "identity": "user/host", "timestamp": False, "features": 0},
            {"name": "endpoint/process", "status": "not_connected", "identity": "process/host", "timestamp": False, "features": 0},
        ],
        "missingness_supported": True,
        "note": "Only flow telemetry is currently used by the trained checkpoint; additional sources are not fabricated.",
    }


@app.get("/api/live")
def live_feed():
    """Latest per-host live forecasts written by scripts/live_forecast.py.

    Read-only: the API just serves the parquet the offline live loop produces on the
    monitored host. No model inference happens here and nothing is fabricated.
    """
    if not LIVE_PRED.exists():
        return {"available": False, "hosts": [],
                "note": "No live feed found. Run scripts/live_forecast.py on the monitored host to stream forecasts."}
    try:
        df = pd.read_parquet(LIVE_PRED)
    except Exception as e:  # noqa: BLE001 - report, do not crash the UI
        return {"available": False, "hosts": [], "note": f"Live predictions unreadable: {e}"}
    if df.empty:
        return {"available": False, "hosts": [], "note": "Live predictions file is empty."}
    df = df.sort_values("issued_at")
    latest = df.groupby("host", as_index=False).tail(1)
    issued = str(df["issued_at"].max())
    try:
        age = max(0.0, (pd.Timestamp.now(tz="UTC") - pd.Timestamp(issued)).total_seconds())
    except (ValueError, TypeError):
        age = None
    risk_cols = [c for c in df.columns if c.startswith("risk_k")]
    hosts = []
    for _, r in latest.iterrows():
        risks = {f"+{int(c[6:]) * 30}s": round(float(r[c]), 4) for c in risk_cols}
        stage_value = int(r.get("stage", 0)) if str(r.get("stage", "")).lstrip("-").isdigit() else 0
        hosts.append({
            "host": str(r.get("host", "")), "issued_at": str(r.get("issued_at", "")),
            "last_window": str(r.get("last_window", "")), "risk": risks,
            "peak_risk": round(max(risks.values(), default=0.0), 4),
            "stage": STAGE_UI.get(stage_value, str(r.get("stage", ""))),
            "action": dict(stage_defence(stage_value)),
            "alerting": bool(r.get("alerting", False)), "alert_level": str(r.get("alert_level", "none")),
        })
    hosts.sort(key=lambda hh: hh["peak_risk"], reverse=True)
    fc = _forecaster()
    return {"available": True, "issued_at": issued, "age_seconds": (None if age is None else round(age, 1)),
            "threshold": round(float(fc.threshold), 4), "n_hosts": len(hosts), "hosts": hosts,
            "horizons": [f"+{k * 30}s" for k in fc.horizons],
            "checkpoint": str(CKPT), "calibration": "loaded" if fc.calibrator else "server threshold",
            "note": "Live per-host forecasts from scripts/live_forecast.py (offline, on the monitored host)."}


def _endpoint_columns(path: Path) -> tuple[str, str, str | None] | None:
    """Find source, destination and optional timestamp columns in a raw flow file."""
    try:
        columns = [str(c).strip() for c in pd.read_csv(path, nrows=0).columns]
    except Exception:
        return None
    by_key = {c.lower().replace(" ", "_"): c for c in columns}
    def find(*names):
        return next((by_key[name] for name in names if name in by_key), None)
    src = find("src_ip", "source_ip", "srcaddr", "src_addr")
    dst = find("dst_ip", "destination_ip", "dstaddr", "dst_addr")
    ts = find("timestamp", "starttime", "start_time", "stime")
    return (src, dst, ts) if src and dst else None


def _read_endpoint_file(path: Path) -> pd.DataFrame:
    columns = _endpoint_columns(path)
    if columns is None:
        return pd.DataFrame(columns=["src_ip", "dst_ip", "timestamp"])
    src, dst, ts = columns
    usecols = [src, dst] + ([ts] if ts else [])
    try:
        frame = pd.read_csv(path, usecols=usecols, low_memory=False)
    except Exception:
        return pd.DataFrame(columns=["src_ip", "dst_ip", "timestamp"])
    rename = {src: "src_ip", dst: "dst_ip"}
    if ts:
        rename[ts] = "timestamp"
    frame = frame.rename(columns=rename)
    if "timestamp" not in frame:
        frame["timestamp"] = pd.NaT
    return frame[["src_ip", "dst_ip", "timestamp"]]


def _raw_endpoint_frame(campaign: str) -> pd.DataFrame:
    """Load and cache raw endpoint identities for a gallery campaign."""
    cache = _STATE["endpoint_frames"]
    if campaign in cache:
        return cache[campaign]
    files: list[Path] = []
    low = campaign.lower()
    if low.startswith("cicids2017-"):
        day = low.split("-", 1)[1]
        root = ROOT / "data/raw/CIC-IDS2017/TrafficLabelling"
        files = [p for p in root.glob("*.csv") if day in p.name.lower()]
    elif low.startswith("cicids2018-"):
        token = campaign.split("-", 1)[1].lower()
        root = ROOT / "data/raw/CIC-IDS2018/csv_features"
        files = [p for p in root.glob("*.csv") if token in p.name.lower()]
    elif low.startswith("ctu13-"):
        scenario = campaign.split("-", 1)[1]
        root = ROOT / "data/raw/CTU-13/_full/CTU-13-Dataset" / scenario
        files = list(root.glob("*.binetflow"))
    if not files:
        cache[campaign] = pd.DataFrame(columns=["src_ip", "dst_ip", "timestamp"])
        return cache[campaign]
    frames = [_read_endpoint_file(path) for path in files]
    result = pd.concat(frames, ignore_index=True) if frames else pd.DataFrame(columns=["src_ip", "dst_ip", "timestamp"])
    cache[campaign] = result
    return result


def _endpoint_graph(frame: pd.DataFrame, host: str | None = None) -> dict:
    """Build a real source-to-destination graph from flow-level telemetry."""
    if not {"src_ip", "dst_ip"}.issubset(frame.columns):
        return {"nodes": [], "edges": [], "available": False,
                "note": "This capture contains window aggregates only; source/destination identities were not retained."}
    work = frame.copy()
    work["src_ip"] = work["src_ip"].astype("string").str.strip()
    work["dst_ip"] = work["dst_ip"].astype("string").str.strip()
    work = work.dropna(subset=["src_ip", "dst_ip"])
    if host:
        work = work.loc[work["src_ip"].astype(str) == str(host)]
    if work.empty:
        return {"nodes": [], "edges": [], "available": False,
                "note": "No source-to-destination flows were found for this host."}
    group_cols = ["src_ip", "dst_ip"]
    grouped = work.groupby(group_cols, sort=True, dropna=False)
    edges = []
    for (source, target), group in grouped:
        edge = {"source": str(source), "target": str(target), "type": "flow", "flow_count": int(len(group))}
        if "timestamp" in group:
            edge["first_seen"] = _iso(group["timestamp"].min())
            edge["last_seen"] = _iso(group["timestamp"].max())
        edges.append(edge)
    sources = sorted({edge["source"] for edge in edges})
    targets = sorted({edge["target"] for edge in edges})
    nodes = ([{"id": node, "type": "source_host"} for node in sources] +
             [{"id": node, "type": "destination"} for node in targets if node not in sources])
    return {"nodes": nodes, "edges": edges, "available": bool(edges),
            "note": "Edges are derived from retained flow-level source and destination identities."}


@app.get("/api/network-graph")
def network_graph(campaign: str | None = None, host: str | None = None, upload_id: str | None = None):
    """Phase 8 graph view from retained flow-level endpoint identities."""
    if upload_id:
        record = _UPLOADS.get(upload_id)
        if record is None:
            raise HTTPException(404, "Unknown upload id (session expired).")
        return _endpoint_graph(record.get("flows", pd.DataFrame()), host)
    if campaign == "upload" or not campaign:
        return {"nodes": [], "edges": [], "available": False,
                "note": "The upload session identifier is required to read flow endpoints."}
    data = _gallery()
    frame = data.loc[data.campaign_id == campaign].copy()
    if host:
        frame = frame.loc[frame.entity_id.astype(str) == host]
    graph = _endpoint_graph(frame, host)
    if graph["available"]:
        return graph
    raw = _raw_endpoint_frame(campaign)
    graph = _endpoint_graph(raw, host)
    if graph["available"]:
        graph["note"] = "Edges are derived from the raw flow file for this replay campaign."
    return graph


@app.get("/api/decision-support")
def decision_support(campaign: str | None = None, host: str | None = None,
                     upload_id: str | None = None, mc: int = 0):
    """Phase 9: explainable, human-approved recommendations; never executes response actions."""
    if not host:
        raise HTTPException(422, "A host is required.")
    if upload_id:
        record = _UPLOADS.get(upload_id)
        if record is None:
            raise HTTPException(404, "Unknown upload id (session expired).")
        frame = _upload_host_frame(upload_id, host)
        known = bool(record.get("audit", {}).get("ground_truth", False))
        campaign = "upload"
    else:
        if not campaign or campaign == "upload":
            raise HTTPException(422, "An upload_id is required for uploaded captures.")
        data = _gallery()
        frame = data.loc[(data.campaign_id == campaign) & (data.entity_id.astype(str) == host)].sort_values("window_start")
        if frame.empty:
            raise HTTPException(404, "Unknown campaign/host.")
        known = True
    fc = _timeline_payload(frame.reset_index(drop=True), known=known, mc=mc)
    level = fc["alert_level"]
    action = {"urgent": "Validate the host and isolate only through an approved response workflow.",
              "warning": "Review authentication, endpoint and destination evidence for this host.",
              "advisory": "Increase monitoring and collect corroborating DNS/authentication telemetry.",
              "none": "Continue monitoring; no horizon currently exceeds its calibrated threshold."}[level]
    # Stage-mapped advisory playbook, keyed on the highest-risk forecast step's predicted stage.
    steps = fc["forecast"] or []
    focus_step = max(steps, key=lambda s: s["risk"]) if steps else {"stage": "BENIGN", "risk": 0.0}
    stage_id = STAGE_UI_TO_ID.get(focus_step["stage"], 0)
    defence = stage_defence(stage_id)
    actions_by_stage = []
    seen = set()
    for item in (fc.get("progression") or []) + [{"stage": s.get("stage", "BENIGN")} for s in steps]:
        stage = str(item.get("stage", "BENIGN"))
        if stage in seen:
            continue
        seen.add(stage)
        sid = STAGE_UI_TO_ID.get(stage, 0)
        playbook = stage_defence(sid)
        actions_by_stage.append({"stage": stage, "tactic": STAGE_TACTICS.get(sid, ""),
                                 "status": "early warning" if item in steps else "active investigation",
                                 "summary": playbook["summary"], "actions": list(playbook["actions"]),
                                 "mitre_mitigations": list(playbook["mitre_mitigations"])})
    return {"host": host, "campaign": campaign, "alert_level": level,
            "recommended_action": action, "requires_human_approval": True,
            "automated_action_taken": False, "risk_by_horizon": fc["forecast"],
            "predicted_stage": focus_step["stage"], "stage_tactic": STAGE_TACTICS.get(stage_id, ""),
            "playbook": {"summary": defence["summary"], "actions": list(defence["actions"]),
                         "mitre_mitigations": list(defence["mitre_mitigations"])},
            "actions_by_stage": actions_by_stage,
            "evidence": {"plain_language": fc["plain_language"], "focus_at": fc["focus_at"]},
            "limitations": ["Network evidence is not proof of compromise.",
                            "Recommendations are advisory and do not modify the server."]}


@app.get("/api/production-readiness")
def production_readiness():
    """Phase 10 operational gate summary for the UI and release process."""
    fc = _forecaster()
    metrics_path = ROOT / "models/wm_phase6/metrics.json"
    metrics = json.loads(metrics_path.read_text(encoding="utf-8")) if metrics_path.exists() else {}
    audit = metrics.get("audit", {})
    real_support = sum(audit.get("test", {}).get("positives", []))
    checks = [
        {"name": "checkpoint loads", "status": "pass", "detail": str(CKPT)},
        {"name": "calibration loaded", "status": "pass" if fc.calibrator else "warn", "detail": "horizon calibrator" if fc.calibrator else "not persisted"},
        {"name": "rollback registry", "status": "pass" if (ROOT / "src/deployment/registry.py").exists() else "warn", "detail": "offline registry present"},
        {"name": "real long-horizon test positives", "status": "fail" if real_support == 0 else "pass", "detail": f"{real_support} test positives"},
        {"name": "multi-source telemetry", "status": "warn", "detail": "flow telemetry only"},
        {"name": "graph edges", "status": "warn", "detail": "requires endpoint identity telemetry"},
        {"name": "automated response", "status": "blocked", "detail": "human approval required"},
    ]
    return {"ready_for_production": all(c["status"] == "pass" for c in checks),
            "checkpoint": str(CKPT), "horizons": [f"+{k * 30}s" for k in fc.horizons], "checks": checks,
            "promotion_policy": "Do not promote until real-only long-horizon evaluation has positive attack support."}


@app.get("/api/gallery")
def gallery():
    data = _gallery()
    fc = _forecaster()
    out = []
    for camp in sorted(data.campaign_id.unique()):
        frame = data.loc[data.campaign_id == camp]
        cat = host_catalog(frame, fc.history_length)
        elig = cat.loc[cat.forecasts > 0]
        attacked = elig.loc[elig.attacked]
        hosts = (attacked if not attacked.empty else elig)
        out.append({"campaign": camp, "label": campaign_label(camp),
                    "hosts": hosts.host.tolist()[:50], "attacked": bool(not attacked.empty)})
    return {"campaigns": out}


@app.get("/api/forecast")
def forecast(campaign: str, host: str, mc: int = 0):
    data = _gallery()
    frame = data.loc[(data.campaign_id == campaign) & (data.entity_id.astype(str) == host)]
    if frame.empty:
        raise HTTPException(404, "Unknown campaign/host.")
    host_frame = frame.sort_values("window_start").reset_index(drop=True)
    payload = _timeline_payload(host_frame, known=True, mc=mc)
    payload["scenario"] = {"campaign": campaign, "label": campaign_label(campaign), "host": host,
                           "dataset": "CIC-IDS2017/2018 + CTU-13 replay"}
    return payload


def _explain_host(frame: pd.DataFrame, window: str) -> dict:
    from demo.helpers import history_at
    fc = _forecaster()
    explainer, baseline = _explainer()
    history, raw = history_at(frame, window, fc.feature_names, fc.history_length)
    with _STATE["lock"]:
        attribution = explainer.explain_batch(apply_scaler(raw, fc.scaler))[0]
        tl = fc.forecast_host_timeline(frame)
    sentence, drivers = explain_window(history.iloc[-1], baseline, fc.feature_names, top_k=6)
    cur = history.iloc[-1]
    # Match the requested origin as timestamps, not string prefixes.  The
    # upload path may carry timezone/serialization differences that make the
    # old string match miss the row and silently produce all-zero bars.
    requested = pd.Timestamp(window)
    requested = requested.tz_localize("UTC") if requested.tzinfo is None else requested.tz_convert("UTC")
    timeline_times = pd.to_datetime(tl["window_start"], utc=True)
    nearest = (timeline_times - requested).abs()
    match_idx = int(nearest.argmin()) if len(nearest) else -1
    match = tl.iloc[match_idx] if match_idx >= 0 and nearest.iloc[match_idx] <= pd.Timedelta(seconds=2) else None
    attention_col = next((f"attn_k{k}" for k in sorted(fc.horizons, reverse=True) if f"attn_k{k}" in tl), None)
    raw_weights = np.asarray(match[attention_col], dtype=float).reshape(-1) if match is not None and attention_col else np.zeros(fc.history_length, dtype=float)
    weights = raw_weights[:fc.history_length].tolist()
    if len(weights) < fc.history_length:
        weights.extend([0.0] * (fc.history_length - len(weights)))
    ranked_attention = sorted(
        ({"window": _iso(t), "weight": round(float(w), 5)} for t, w in zip(history.window_start, weights)),
        key=lambda item: item["weight"], reverse=True,
    )[:10]
    return {
        "window": window,
        "shap": [{"feature": n, "contribution": round(float(v), 4),
                  "value": round(float(cur.get(n, 0.0)), 4),
                  "kind": "PACKET" if n in PACKET_FEATURES else "FLOW",
                  "label": FEATURE_LABELS.get(n, n)} for n, v in attribution.top_features(9)],
        "attention": {"windows": [item["window"] for item in ranked_attention],
                      "weights": [item["weight"] for item in ranked_attention],
                      "ordering": "highest_weight_first"},
        "sentence": sentence.replace("—", "-"),
        "drivers": [{"feature": f, "observed": round(float(v), 4), "reference": round(float(b), 4),
                     "kind": "PACKET" if f in PACKET_FEATURES else "FLOW"} for f, v, b in drivers],
    }


@app.get("/api/explain")
def explain(campaign: str, host: str, window: str):
    data = _gallery()
    frame = data.loc[(data.campaign_id == campaign) & (data.entity_id.astype(str) == host)].sort_values("window_start").reset_index(drop=True)
    if frame.empty:
        raise HTTPException(404, "Unknown campaign/host.")
    return _explain_host(frame, window)


def _run_stages(payload: bytes, suffix: str) -> dict:
    """Run the upload pipeline (ingest -> convert -> clean -> window) and return its report."""
    frame, audit, flows = ingest_upload(payload, suffix, return_flows=True)
    return {"audit": audit, "cleaning": audit.get("cleaning", {}), "frame": frame, "flows": flows}


@app.post("/api/upload")
async def upload(file: UploadFile = File(...)):
    suffix = Path(file.filename or "capture.csv").suffix.lower()
    if suffix not in {".csv", ".pcap", ".pcapng"}:
        raise HTTPException(400, "Upload a CSV, PCAP or PCAPNG file.")
    payload = await file.read()
    try:
        res = _run_stages(payload, suffix)
    except Exception as e:
        raise HTTPException(422, f"Ingest failed: {e}")
    fc = _forecaster()
    cat = host_catalog(res["frame"], fc.history_length)
    elig = cat.loc[cat.forecasts > 0].sort_values(
        ["attacked", "forecasts"], ascending=[False, False]
    )
    if elig.empty:
        raise HTTPException(422, "No host has 10 consecutive 30-second windows in this capture.")
    uid = uuid.uuid4().hex[:12]
    _UPLOADS[uid] = {"frame": res["frame"], "flows": res["flows"], "audit": res["audit"]}
    c = res["cleaning"]
    steps = [{"name": "Data ingestion", "detail": f"{c.get('rows_read',0)} rows read, {c.get('empty_dropped',0)} empty + {c.get('duplicates_dropped',0)} duplicate dropped"},
             {"name": "Cleaning", "detail": f"{c.get('nonfinite_imputed',0)} non-finite values imputed ({c.get('nonfinite_pct',0)}%), {c.get('bad_timestamp_dropped',0)} bad-timestamp dropped"},
             {"name": "State construction", "detail": f"{c.get('flows_kept',0)} flows -> {c.get('windows_built',0)} per-host 30 s windows"},
             {"name": "Feature check", "detail": f"{res['audit'].get('model_columns',43)} model features, {res['audit'].get('nonzero_columns',0)} populated"},
             {"name": "Ready", "detail": f"{c.get('hosts_with_history',0)} host(s) with >=10 consecutive windows"}]
    return {"upload_id": uid, "stages": steps, "hosts": elig.host.tolist()[:50]}


def _upload_host_frame(uid: str, host: str) -> pd.DataFrame:
    if uid not in _UPLOADS:
        raise HTTPException(404, "Unknown upload id (session expired).")
    frame = _UPLOADS[uid]["frame"]
    hf = frame.loc[frame.entity_id.astype(str) == host].sort_values("window_start").reset_index(drop=True)
    if hf.empty:
        raise HTTPException(404, "Unknown host in this upload.")
    return hf


@app.get("/api/upload/{uid}/forecast")
def upload_forecast(uid: str, host: str, mc: int = 0):
    record = _UPLOADS.get(uid)
    if record is None:
        raise HTTPException(404, "Unknown upload id (session expired).")
    known = bool(record.get("audit", {}).get("ground_truth", False))
    payload = _timeline_payload(_upload_host_frame(uid, host), known=known, mc=mc)
    payload["upload_id"] = uid
    payload["scenario"] = {"campaign": "upload", "label": "Uploaded capture", "host": host,
                           "dataset": "labelled upload" if known else "user upload (labels unknown)"}
    return payload


@app.get("/api/upload/{uid}/explain")
def upload_explain(uid: str, host: str, window: str):
    return _explain_host(_upload_host_frame(uid, host), window)


@app.get("/api/evaluation")
def evaluation():
    """Per-horizon world-model vs logistic-regression metrics for the Validate page."""
    b = json.loads(BENCH.read_text(encoding="utf-8")) if BENCH.exists() else {"horizons": [], "rows": []}
    by_model = {r["model"]: r for r in b.get("rows", [])}
    wm, lr = by_model.get("World model"), by_model.get("Logistic regression")
    rows = []
    for i, hz in enumerate(b.get("horizons", [])):
        def m(r):
            return None if not r else {"prauc": r["pr_auc"][i], "f1": r["f1"][i], "fpr": r["fpr"][i]}
        rows.append({"horizon": hz, "worldModel": m(wm), "baseline": m(lr)})
    gen_default = [
        {"setting": "In-distribution (held-out time)", "result": "World model beats persistence and LR at every horizon (see benchmark)."},
        {"setting": "Held-out attack family", "result": "Not yet measured in this build."},
        {"setting": "Cross-dataset", "result": "Trained on CIC-IDS2017/2018 + CTU-13; external cross-dataset test not yet run."},
    ]
    gen = gen_default
    if GENERALIZATION.exists():
        try:
            g = json.loads(GENERALIZATION.read_text(encoding="utf-8"))
            gen = g.get("rows", g) if isinstance(g, (dict, list)) else gen_default
        except (ValueError, OSError):
            gen = gen_default
    return {"by_horizon": rows, "takeaway": b.get("takeaway", ""), "generalization": gen}
