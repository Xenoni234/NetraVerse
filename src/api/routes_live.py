"""Live-capture endpoints: same service, same model, analysis id "live"."""
from __future__ import annotations

import os
import threading

from fastapi import APIRouter, Header, HTTPException

from src.api.schemas import DecisionRequest
from src.api.service import get_service

router = APIRouter(prefix="/live", tags=["live"])
_monitor = None
_lock = threading.Lock()


def monitor():
    global _monitor
    with _lock:
        if _monitor is None:
            from src.live.sniffer import LiveMonitor
            _monitor = LiveMonitor(get_service())
        return _monitor


def status() -> dict:
    return _monitor.status() if _monitor else {"running": False}


def _check_token(token: str | None) -> None:
    need = os.environ.get("NV_OPERATOR_TOKEN")
    if need and token != need:
        raise HTTPException(403, "Operator token required for real enforcement.")


@router.post("/start")
def start():
    try:
        monitor().start()
    except RuntimeError as e:
        raise HTTPException(400, str(e))
    return monitor().status()


@router.post("/stop")
def stop():
    if _monitor:
        _monitor.stop()
    return status()


@router.get("/state")
def state():
    m = monitor()
    a = m.latest
    if a is None:
        return {"status": m.status(), "overview": None, "series": {}, "actions": m.actions}
    svc = get_service()
    ov = svc.overview(a)
    top = [h["host"] for h in sorted(ov["hosts"], key=lambda h: -h["peak"])[:12]]
    return {"status": m.status(), "overview": ov, "last_step": len(a.steps) - 1,
            "series": {h: list(m.history.get(h, [])) for h in top}, "actions": m.actions}


@router.get("/topology")
def topology(max_nodes: int = 60):
    a = monitor().latest
    if a is None:
        return {"nodes": [], "edges": [], "window": 0}
    return get_service().topology(a, len(a.steps) - 1, max_nodes)


@router.get("/explain")
def explain(host: str):
    a = monitor().latest
    if a is None:
        raise HTTPException(409, "No live data yet.")
    return get_service().explain_step(a, host, len(a.steps) - 1)


@router.get("/decision")
def decision_context(host: str):
    a = monitor().latest
    if a is None:
        raise HTTPException(409, "No live data yet.")
    return get_service().decision_context(a, host, len(a.steps) - 1)


@router.get("/narration")
def narration(host: str):
    a = monitor().latest
    if a is None:
        raise HTTPException(409, "No live data yet.")
    return get_service().narration(a, host, len(a.steps) - 1)


@router.post("/decision")
def decide(req: DecisionRequest, x_operator_token: str | None = Header(default=None)):
    """Accept/Modify apply a REAL nftables rule on the sensor (FR17); risk is then re-measured live."""
    _check_token(x_operator_token)
    m = monitor()
    a = m.latest
    if a is None:
        raise HTTPException(409, "No live data yet.")
    try:
        res = get_service().decide(a, req.host, len(a.steps) - 1, req.choice, req.action, live=True)
    except ValueError as e:
        raise HTTPException(400, str(e))
    hist = list(m.history.get(req.host, []))
    res["measured_before"] = hist[-1]["risk"] if hist else None
    m.actions.append({k: res[k] for k in ("choice", "action", "host", "enforcement", "at")}
                     | {"measured_before": res["measured_before"]})
    return res
