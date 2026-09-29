"""Live-capture endpoints: same service, same model, analysis id "live"."""
from __future__ import annotations

import os
import threading

from fastapi import APIRouter, Header, HTTPException
from fastapi.responses import Response

from src.api.schemas import DecisionRequest, RehearsalStartRequest
from src.api.service import get_service
from demo.scenario_catalog import scenario_specs

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
    """Real enforcement needs an operator token (FR17/R13). Two modes:
    - a sensor secret is configured (NV_OPERATOR_TOKEN): the header must match it exactly;
    - no secret configured: any non-empty operator token is accepted (proves an operator is
      present and driving the console), but a missing/blank token is still refused.
    The dashboard also gates the whole Live Monitor behind entering a token."""
    if _monitor is not None and _monitor.is_rehearsal:
        return
    need = os.environ.get("NV_OPERATOR_TOKEN")
    if need:
        if token != need:
            raise HTTPException(403, "Operator token does not match the sensor's NV_OPERATOR_TOKEN.")
    elif not (token and token.strip()):
        raise HTTPException(403, "Operator token required to apply a containment action.")


@router.post("/start")
def start():
    try:
        monitor().start()
    except RuntimeError as e:
        raise HTTPException(400, str(e))
    return monitor().status()


@router.get("/rehearsal/scenarios")
def rehearsal_scenarios():
    return {"scenarios": scenario_specs()}


@router.post("/rehearsal/start")
def rehearsal_start(req: RehearsalStartRequest):
    global _monitor
    with _lock:
        if _monitor is not None:
            _monitor.stop()
        # This flag is consumed only by action_executor's safe branch. No shell
        # command is reachable from a rehearsal monitor.
        os.environ["NV_LIVE_MODE"] = "safe_rehearsal"
        from src.live.sniffer import LiveMonitor
        _monitor = LiveMonitor(get_service(), tick_s=req.tick_s, scenario=req.scenario, speed=req.speed)
        try:
            _monitor.start()
        except (RuntimeError, ValueError, FileNotFoundError) as e:
            _monitor = None
            os.environ.pop("NV_LIVE_MODE", None)
            raise HTTPException(400, str(e))
        return {"ok": True, "status": _monitor.status()}


@router.post("/rehearsal/stop")
def rehearsal_stop():
    global _monitor
    with _lock:
        if _monitor is not None:
            _monitor.stop()
        if os.environ.get("NV_LIVE_MODE") == "safe_rehearsal":
            os.environ.pop("NV_LIVE_MODE", None)
        return {"ok": True, "status": _monitor.status() if _monitor else {"running": False}}


@router.post("/stop")
def stop():
    if _monitor:
        _monitor.stop()
        if _monitor.is_rehearsal and os.environ.get("NV_LIVE_MODE") == "safe_rehearsal":
            os.environ.pop("NV_LIVE_MODE", None)
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
    series = {h: list(m.history.get(h, [])) for h in top}
    risk_before = {h: (s[-1].get("risk_before") if s else None) for h, s in series.items()}
    risk_after = {h: (s[-1].get("risk_after", s[-1].get("risk")) if s else None)
                  for h, s in series.items()}
    lead_time = {h: (next((int((i + 1) * ov["window_s"]) for i, value in enumerate(s[-1].get("future", []))
                            if value >= ov["threshold"]), None) if s else None)
                 for h, s in series.items()}
    return {"status": m.status(), "overview": ov, "last_step": len(a.steps) - 1,
            "series": series, "risk_before": risk_before, "risk_after": risk_after,
            "lead_time_s": lead_time, "active_mitigations": sorted(m._mitigated),
            "actions": m.actions}


@router.get("/report")
def report():
    from src.reporting.incident_report import build_pdf
    m = monitor()
    a = m.latest
    if a is None:
        raise HTTPException(409, "No live data yet.")
    pdf = build_pdf(get_service(), a, title=f"Live sensor {m.iface or m.replay or ''}",
                    decisions=list(m.actions))
    return Response(pdf, media_type="application/pdf",
                    headers={"Content-Disposition": 'attachment; filename="netraverse_live_report.pdf"'})


@router.get("/topology")
def topology(max_nodes: int = 60):
    m = monitor()
    a = m.latest
    if a is None:
        return {"nodes": [], "edges": [], "window": 0}
    return get_service().topology(a, len(a.steps) - 1, max_nodes,
                                  mitigated_extra=(set(getattr(m, "_neutralized", set()))
                                                    | set(getattr(m, "_mitigated", set()))))


@router.get("/explain")
def explain(host: str):
    a = monitor().latest
    if a is None:
        raise HTTPException(409, "No live data yet.")
    return get_service().explain_step(a, host, len(a.steps) - 1)


@router.get("/shap")
def shap(host: str):
    a = monitor().latest
    if a is None:
        raise HTTPException(409, "No live data yet.")
    return get_service().shap_step(a, host, len(a.steps) - 1)


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
    m.register_action({k: res[k] for k in ("choice", "action", "host", "enforcement", "at")}
                      | {"measured_before": res["measured_before"]})
    return res
