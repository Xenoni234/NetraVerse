"""CSV / PCAP upload endpoints: file -> fusion -> world model -> rollout -> JSON."""
from __future__ import annotations

import shutil
import tempfile
import uuid
from pathlib import Path

from fastapi import APIRouter, File, HTTPException, UploadFile

from src.api.schemas import DecisionRequest, Driver, Timeline, Topology, UploadResponse
from src.api.service import get_service
from src.features.flow_features import UnsupportedFormat
from src.features.fusion import from_file
from src.utils.config import ROOT, UPLOADS

router = APIRouter(prefix="/upload", tags=["upload"])
ALLOWED = {".csv", ".pcap", ".pcapng", ".cap", ".binetflow"}


def _get(aid: str):
    a = get_service().analyses.get(aid)
    if a is None:
        raise HTTPException(404, "Unknown upload id (the API may have restarted - upload again).")
    return a


@router.post("", response_model=UploadResponse)
async def upload(file: UploadFile = File(...)):
    suffix = Path(file.filename or "").suffix.lower()
    if suffix not in ALLOWED:
        raise HTTPException(400, f"Unsupported file type {suffix!r}; use CSV or PCAP.")
    aid = uuid.uuid4().hex[:12]
    UPLOADS.mkdir(parents=True, exist_ok=True)
    dest = UPLOADS / f"{aid}{suffix}"
    with open(dest, "wb") as fh:
        shutil.copyfileobj(file.file, fh)
    try:
        fm = from_file(dest)
    except UnsupportedFormat as e:
        raise HTTPException(422, str(e))
    except ValueError as e:
        raise HTTPException(422, str(e))
    svc = get_service()
    a = svc.analyze(fm, filename=file.filename or dest.name, aid=aid)
    return svc.overview(a)


@router.post("/path", response_model=UploadResponse)
def upload_path(path: str):
    """Analyse a file already on the server (bundled demo samples)."""
    p = Path(path)
    if not p.is_absolute():
        p = ROOT / p
    if ROOT not in p.resolve().parents:
        raise HTTPException(403, "Only files inside the project directory can be analysed by path.")
    if not p.exists():
        raise HTTPException(404, f"{path} not found")
    fm = from_file(p)
    svc = get_service()
    return svc.overview(svc.analyze(fm, filename=p.name))


@router.get("/{aid}", response_model=UploadResponse)
def overview(aid: str):
    return get_service().overview(_get(aid))


@router.get("/{aid}/timeline", response_model=Timeline)
def timeline(aid: str, host: str):
    return get_service().timeline(_get(aid), host)


@router.get("/{aid}/branch")
def branch(aid: str, host: str):
    return get_service().branch_timeline(_get(aid), host)


@router.get("/{aid}/explain", response_model=list[Driver])
def explain(aid: str, host: str, step: int):
    return get_service().explain_step(_get(aid), host, step)


@router.get("/{aid}/topology", response_model=Topology)
def topology(aid: str, step: int, max_nodes: int = 60):
    return get_service().topology(_get(aid), step, max_nodes)


@router.get("/{aid}/decision")
def decision_context(aid: str, host: str, step: int):
    return get_service().decision_context(_get(aid), host, step)


@router.post("/{aid}/decision")
def decide(aid: str, req: DecisionRequest):
    try:
        return get_service().decide(_get(aid), req.host, req.step, req.choice, req.action, live=False)
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.post("/{aid}/reset")
def reset(aid: str):
    get_service().reset_branch(_get(aid))
    return {"ok": True}
