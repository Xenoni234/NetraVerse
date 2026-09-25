"""FastAPI app: one model, one rollout, three input modes.

    uvicorn src.api.main:app --host 0.0.0.0 --port 8000
"""
from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from src.api import routes_live, routes_upload
from src.api.service import get_service
from src.utils.config import ROOT

app = FastAPI(title="NetraVerse API", version="2.0.0",
              description="World-model network attack forecasting (SIH PS 26153)")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
# offline three.js topology bundle, imported by the Streamlit component (same machine / LAN only)
app.mount("/static", StaticFiles(directory=str(ROOT / "dashboard" / "components" / "topology3d" / "dist")),
          name="static")
app.include_router(routes_upload.router)
app.include_router(routes_live.router)


@app.on_event("startup")
def _load() -> None:
    get_service()          # load weights once


@app.get("/health")
def health() -> dict:
    s = get_service()
    return {"ok": True, "checkpoint": s.E.checkpoint, "trained_on": s.E.trained_on,
            "threshold": s.E.threshold, "device": str(s.E.device),
            "window_s": s.E.window_s, "horizon_s": s.E.window_s * s.E.K,
            "live": routes_live.status()}
