"""Thin HTTP client for the NetraVerse FastAPI backend."""
from __future__ import annotations

import os

import httpx

API_URL = os.environ.get("NV_API_URL", "http://127.0.0.1:8000").rstrip("/")
# URL the *browser* uses to fetch the offline 3D bundle (differs from API_URL inside Docker)
PUBLIC_API_URL = os.environ.get("NV_API_PUBLIC_URL", API_URL).rstrip("/")
_client = httpx.Client(base_url=API_URL, timeout=httpx.Timeout(600.0, connect=5.0))


class ApiError(RuntimeError):
    pass


def _ok(r: httpx.Response):
    if r.status_code >= 400:
        try:
            detail = r.json().get("detail")
        except Exception:
            detail = r.text
        raise ApiError(f"{r.status_code}: {detail}")
    return r.json()


def health() -> dict | None:
    try:
        return _ok(_client.get("/health", timeout=3))
    except Exception:
        return None


def upload(name: str, content: bytes) -> dict:
    return _ok(_client.post("/upload", files={"file": (name, content)}))


def upload_path(path: str) -> dict:
    return _ok(_client.post("/upload/path", params={"path": path}))


def overview(aid: str) -> dict:
    return _ok(_client.get(f"/upload/{aid}"))


def timeline(aid: str, host: str) -> dict:
    return _ok(_client.get(f"/upload/{aid}/timeline", params={"host": host}))


def branch(aid: str, host: str) -> dict | None:
    return _ok(_client.get(f"/upload/{aid}/branch", params={"host": host}))


def explain(aid: str, host: str, step: int) -> list:
    return _ok(_client.get(f"/upload/{aid}/explain", params={"host": host, "step": step}))


def topology(aid: str, step: int) -> dict:
    return _ok(_client.get(f"/upload/{aid}/topology", params={"step": step}))


def decision_context(aid: str, host: str, step: int) -> dict:
    return _ok(_client.get(f"/upload/{aid}/decision", params={"host": host, "step": step}))


def decide(aid: str, host: str, step: int, choice: str, action=None) -> dict:
    return _ok(_client.post(f"/upload/{aid}/decision",
                            json={"host": host, "step": step, "choice": choice, "action": action}))


def reset(aid: str) -> dict:
    return _ok(_client.post(f"/upload/{aid}/reset"))


# ---- live
def live_start() -> dict:
    return _ok(_client.post("/live/start"))


def live_state() -> dict:
    return _ok(_client.get("/live/state"))


def live_topology() -> dict:
    return _ok(_client.get("/live/topology"))


def live_explain(host: str) -> list:
    return _ok(_client.get("/live/explain", params={"host": host}))


def live_decision_context(host: str) -> dict:
    return _ok(_client.get("/live/decision", params={"host": host}))


def live_decide(host: str, choice: str, action=None, token: str | None = None) -> dict:
    headers = {"x-operator-token": token} if token else {}
    return _ok(_client.post("/live/decision", json={"host": host, "step": 0, "choice": choice, "action": action},
                            headers=headers))
