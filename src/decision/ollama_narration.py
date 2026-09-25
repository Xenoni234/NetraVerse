"""Analyst-style narration of a decision (Phase 10, FR18, R9).

The local LLM only DESCRIBES a decision the deterministic rule engine already
made. It never chooses or changes the action, runs in a background thread with a
timeout, and the system works identically when Ollama is off (template text).

Env:
  NV_OLLAMA_URL     default http://127.0.0.1:11434   (local only - R10, no cloud APIs)
  NV_OLLAMA_MODEL   default qwen2.5:3b              (any small quantized model: phi3:mini, llama3.2:3b ...)
  NV_OLLAMA_TIMEOUT default 30 (seconds)
  NV_NARRATION      set to 0 to disable the LLM entirely
"""
from __future__ import annotations

import os
import threading
import time

import httpx

_CACHE: dict[str, dict] = {}
_LOCK = threading.Lock()

SYSTEM = ("You are a SOC analyst writing a short incident note. Describe ONLY the facts given. "
          "Do not invent hosts, ports, numbers or actions. Do not recommend anything other than the "
          "action already chosen. Write ONE paragraph of 3-4 flowing prose sentences - no headings, "
          "no lists, no field labels, no markdown.")


def template(ctx: dict) -> str:
    c, st, rec = ctx["context"], ctx["stage"], ctx["recommended"]
    drivers = ", ".join(d["label"] for d in ctx.get("driving_features", [])[:3]) or "its recent traffic pattern"
    victims = ", ".join(c.get("victims") or []) or "no specific internal target"
    return (f"Host {ctx['host']} is forecast at {ctx['risk']:.0%} risk of attack activity within the next "
            f"5 minutes, consistent with {st['tactic']}"
            f"{' (' + st['tactic_id'] + ')' if st.get('tactic_id') else ''}. "
            f"The model's evidence is driven mainly by {drivers}. "
            f"The traffic points to {c.get('attacker')} as the initiating host and {victims} as affected. "
            f"The rule engine recommends: {rec['label']}.")


def _prompt(ctx: dict) -> str:
    c, st, rec = ctx["context"], ctx["stage"], ctx["recommended"]
    ev = "\n".join(f"- {d['sentence']}" for d in ctx.get("driving_features", [])[:5])
    return (f"Alerting host: {ctx['host']} (role: {c.get('role')})\n"
            f"Forecast risk (next 300 s): {ctx['risk']:.0%}\n"
            f"MITRE ATT&CK: {st['tactic']} {st.get('tactic_id') or ''}\n"
            f"Attacker: {c.get('attacker')}; victims: {', '.join(c.get('victims') or []) or 'none identified'}\n"
            f"Evidence:\n{ev or '- (none)'}\n"
            f"Chosen action (already decided, do not change): {rec['label']}\n"
            f"Rationale: {rec['rationale']}\n\nWrite the incident note.")


def _run(key: str, ctx: dict) -> None:
    url = os.environ.get("NV_OLLAMA_URL", "http://127.0.0.1:11434").rstrip("/")
    model = os.environ.get("NV_OLLAMA_MODEL", "qwen2.5:3b")
    t0 = time.time()
    try:
        r = httpx.post(f"{url}/api/chat", timeout=float(os.environ.get("NV_OLLAMA_TIMEOUT", 30)), json={
            "model": model, "stream": False, "keep_alive": "2h",
            "options": {"temperature": 0.2, "num_predict": 180},
            "messages": [{"role": "system", "content": SYSTEM}, {"role": "user", "content": _prompt(ctx)}]})
        r.raise_for_status()
        text = r.json()["message"]["content"].strip()
        res = {"status": "ready", "source": f"ollama:{model}", "text": text}
    except Exception as e:  # LLM is optional: never let it break the decision flow
        res = {"status": "fallback", "source": "template", "text": template(ctx),
               "note": f"LLM unavailable ({type(e).__name__})"}
    res["latency_ms"] = int((time.time() - t0) * 1000)
    with _LOCK:
        _CACHE[key] = res


def request(key: str, ctx: dict) -> dict:
    """Start (once) a background narration for ``key``; return the current state immediately."""
    if os.environ.get("NV_NARRATION", "1") == "0":
        return {"status": "disabled", "source": "template", "text": template(ctx)}
    with _LOCK:
        if key in _CACHE:
            return _CACHE[key]
        _CACHE[key] = {"status": "pending", "source": "template", "text": template(ctx)}
    threading.Thread(target=_run, args=(key, ctx), daemon=True).start()
    return _CACHE[key]


def get(key: str) -> dict | None:
    with _LOCK:
        return _CACHE.get(key)


def warmup() -> None:
    """Load the model into memory in the background at API start (a cold load can take ~1 min)."""
    if os.environ.get("NV_NARRATION", "1") == "0":
        return

    def _go() -> None:
        url = os.environ.get("NV_OLLAMA_URL", "http://127.0.0.1:11434").rstrip("/")
        try:
            httpx.post(f"{url}/api/generate", timeout=180, json={
                "model": os.environ.get("NV_OLLAMA_MODEL", "qwen2.5:3b"), "prompt": "ok",
                "stream": False, "keep_alive": "2h", "options": {"num_predict": 1}})
        except Exception:
            pass
    threading.Thread(target=_go, daemon=True).start()
