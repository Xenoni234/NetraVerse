"""FastAPI backend for the Network Attack Forecasting frontend.

Wraps the real world model (src.inference.engine) and the demo helpers so the
Stitch HTML frontend can render live forecasts, explanations, network trends,
benchmarks, the model card, and an uploaded-capture pipeline with visible
processing stages. Offline, CPU. No model/pipeline semantics are changed here.

Run:  uvicorn api.server:app --port 8000       (from the repo root, in the venv)
"""
from __future__ import annotations

import json
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
from src.mitre.stage_mapping import STAGE_NAMES, STAGE_TACTICS, STAGE_DESCRIPTIONS
from demo.helpers import (PACKET_FEATURES, attack_intervals, benign_references,
    campaign_label, first_sustained, host_catalog, ingest_upload)

CKPT = ROOT / "models/wm_final/best.ckpt"
BENCH = ROOT / "models/wm_final/benchmark.json"

# our stage id -> frontend stage label
STAGE_UI = {0: "BENIGN", 1: "RECONNAISSANCE", 2: "INITIAL ACCESS", 3: "LATERAL MOVEMENT",
            4: "COMMAND AND CONTROL", 5: "EXFILTRATION", 6: "IMPACT"}

app = FastAPI(title="Network Attack Forecasting API")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

_STATE = {"forecaster": None, "explainer": None, "baseline": None, "gallery": None,
          "gallery_path": None, "lock": threading.RLock()}
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


def _timeline_payload(host: pd.DataFrame, *, known: bool, mc: int = 0) -> dict:
    """Build the full per-host forecast payload the frontend pages consume."""
    fc = _forecaster()
    with _STATE["lock"]:
        tl = fc.forecast_host_timeline(host, mc_samples=mc)
    if tl.empty:
        raise HTTPException(422, "Host has fewer than 10 consecutive 30-second windows.")
    thr = fc.threshold_for_horizon(4)
    merged = host.merge(tl, on="window_start", how="right").sort_values("window_start")

    observed = []
    for _, r in merged.iterrows():
        observed.append({
            "t": _iso(r.window_start),
            "risk": round(float(r.risk_k4), 4),
            "stage": STAGE_UI.get(int(r.stage_k4), "UNMAPPED"),
            "attention": round(float(np.asarray(r.attn_k4).max()), 4) if "attn_k4" in merged else 0.0,
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

    # per-horizon forecast (the K-step trajectory) from the latest window
    last = tl.iloc[-1]
    steps = []
    for k in fc.horizons:
        rk = float(last[f"risk_k{k}"])
        band = (round(float(last.get(f"risk_hi_k{k}", rk)) - float(last.get(f"risk_lo_k{k}", rk)), 4)
                if mc else None)
        steps.append({"horizon": f"+{k*30}s", "utc": _iso(pd.Timestamp(last.window_start)+pd.Timedelta(seconds=30*k)),
                      "risk": round(rk, 4), "uncertainty": band,
                      "stage": STAGE_UI.get(int(last[f"stage_k{k}"]), "UNMAPPED"),
                      "tactic": STAGE_TACTICS.get(int(last[f"stage_k{k}"]), ""),
                      "confidence": "High" if rk >= 0.6 else "Medium" if rk >= thr else "Low"})

    alert = first_sustained(tl, "risk_k4", thr)
    lead = lead_time_seconds(tl, horizon_key="risk_k4", threshold=thr) if known else None
    peak = tl.loc[tl.risk_k4.idxmax()]
    return {
        "threshold": round(float(thr), 4),
        "observed": observed,
        "forecast": steps,
        "attack_intervals": [[_iso(a), _iso(b)] for a, b in attack_intervals(host)] if known else [],
        "first_alert": _iso(alert[0]) if alert else None,
        "lead_time_s": (None if lead is None else round(float(lead), 0)),
        "peak_risk": round(float(peak.risk_k4), 4),
        "peak_at": _iso(peak.window_start),
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
            "explainability": "SHAP over state features + temporal attention"}


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
    match = tl.loc[tl.window_start.astype(str).str.startswith(window[:19])]
    weights = (np.asarray(match["attn_k4"].iloc[0]).tolist() if len(match) and "attn_k4" in tl
               else [0.0] * fc.history_length)
    return {
        "window": window,
        "shap": [{"feature": n, "contribution": round(float(v), 4),
                  "value": round(float(cur.get(n, 0.0)), 4),
                  "kind": "PACKET" if n in PACKET_FEATURES else "FLOW",
                  "label": FEATURE_LABELS.get(n, n)} for n, v in attribution.top_features(9)],
        "attention": {"windows": [_iso(t) for t in history.window_start],
                      "weights": [round(float(w), 4) for w in weights]},
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
    frame, audit = ingest_upload(payload, suffix)
    return {"audit": audit, "cleaning": audit.get("cleaning", {}), "frame": frame}


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
    elig = cat.loc[cat.forecasts > 0]
    if elig.empty:
        raise HTTPException(422, "No host has 10 consecutive 30-second windows in this capture.")
    uid = uuid.uuid4().hex[:12]
    _UPLOADS[uid] = {"frame": res["frame"], "audit": res["audit"]}
    c = res["cleaning"]
    steps = [{"name": "Data ingestion", "detail": f"{c.get('rows_read',0)} rows read, {c.get('empty_dropped',0)} empty + {c.get('duplicates_dropped',0)} duplicate dropped"},
             {"name": "Cleaning", "detail": f"{c.get('nonfinite_imputed',0)} non-finite values imputed ({c.get('nonfinite_pct',0)}%), {c.get('bad_timestamp_dropped',0)} bad-timestamp dropped"},
             {"name": "State construction", "detail": f"{c.get('flows_kept',0)} flows -> {c.get('windows_built',0)} per-host 30 s windows"},
             {"name": "Feature check", "detail": f"{res['audit'].get('model_columns',43)} model features, {res['audit'].get('nonzero_columns',0)} populated"},
             {"name": "Ready", "detail": f"{c.get('hosts_with_history',0)} host(s) with >=10 consecutive windows"}]
    return {"upload_id": uid, "stages": steps, "hosts": elig.host.tolist()[:50]}


@app.get("/api/upload/{uid}/forecast")
def upload_forecast(uid: str, host: str, mc: int = 0):
    if uid not in _UPLOADS:
        raise HTTPException(404, "Unknown upload id (session expired).")
    frame = _UPLOADS[uid]["frame"]
    host_frame = frame.loc[frame.entity_id.astype(str) == host].sort_values("window_start").reset_index(drop=True)
    if host_frame.empty:
        raise HTTPException(404, "Unknown host in this upload.")
    payload = _timeline_payload(host_frame, known=False, mc=mc)
    payload["scenario"] = {"campaign": "upload", "label": "Uploaded capture", "host": host,
                           "dataset": "user upload (labels unknown)"}
    return payload
