"""Two-tier local-LLM (Ollama) decision advisor for operator actionables.

Given a live per-device forecast + present-state detector verdict + MITRE stage,
produce a **human-readable, explainable containment recommendation** and the
exact rule the controller would execute — entirely offline via Ollama.

- **Tier 1** (fast, ``qwen2.5-coder:3b``): instant triage — severity, whether
  containment is warranted, and a *candidate* action (type/target/port/TTL).
- **Tier 2** (deep, e.g. ``qwen2.5:7b``): reasons over Tier-1's candidate + the
  full context to produce the final actionable, a justification, ordered steps,
  and the concrete rule; it may down-grade to monitor-only.

Hard guarantees (not left to the model):
- ``action_type`` is constrained to the supported, reversible action set.
- The target is never a management IP (we never cut our own access).
- Strict JSON is validated; anything malformed or an unreachable Ollama falls
  back to the deterministic per-stage :func:`recommended_action`.

The LLM only *suggests*. A human approves and the controller executes.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any

from src.inference.live_state import recommended_action
from src.response.firewall import ACTION_TYPES

# Tier-1 runs locally on the sensor (small, fast). Tier-2 (larger) can run on a
# second machine reached over Tailscale — set NETRAVERSE_OLLAMA_TIER2_URL to that
# host's Ollama (e.g. http://100.81.46.8:11434). Falls back to the Tier-1 URL.
TIER1_URL = os.environ.get("NETRAVERSE_OLLAMA_URL", "http://127.0.0.1:11434")
TIER2_URL = os.environ.get("NETRAVERSE_OLLAMA_TIER2_URL", TIER1_URL)
TIER1_MODEL = os.environ.get("NETRAVERSE_LLM_TIER1", "qwen2.5-coder:3b")
TIER2_MODEL = os.environ.get("NETRAVERSE_LLM_TIER2", "qwen2.5-coder:7b")

#: IPs the advisor must never target (extended from the firewall guard at call time).
_DEFAULT_MGMT = {ip.strip() for ip in os.environ.get(
    "NETRAVERSE_MANAGEMENT_IPS", "100.81.46.8,100.72.80.52,192.168.0.203"
).split(",") if ip.strip()}


def _ollama_chat(model: str, system: str, user: str, *, url: str,
                 timeout: float = 60.0, keep_alive: str = "15m") -> dict[str, Any] | None:
    """Call Ollama /api/chat with forced JSON output; return the parsed object.

    ``keep_alive`` keeps the model resident in VRAM so subsequent calls are fast
    (the first call still pays the cold-load cost — give it a generous timeout).
    """
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "stream": False,
        "format": "json",
        "keep_alive": keep_alive,
        "options": {"temperature": 0.2},
    }
    req = urllib.request.Request(
        f"{url}/api/chat",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, OSError, ValueError, TimeoutError):
        return None
    content = (body.get("message") or {}).get("content", "")
    try:
        return json.loads(content)
    except (ValueError, TypeError):
        return None


def ollama_available(url: str | None = None) -> bool:
    try:
        req = urllib.request.Request(f"{url or TIER1_URL}/api/tags", method="GET")
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            return resp.status == 200
    except (urllib.error.URLError, OSError, ValueError, TimeoutError):
        return False


def warmup() -> dict[str, bool]:
    """Pre-load both tier models into VRAM so the first real decision is fast."""
    ok = {}
    for tier, model, url in (("tier1", TIER1_MODEL, TIER1_URL), ("tier2", TIER2_MODEL, TIER2_URL)):
        r = _ollama_chat(model, "Reply with JSON.", 'Return {"ok":true}', url=url, timeout=180.0)
        ok[tier] = bool(r)
    return ok


def _context_str(ctx: dict[str, Any]) -> str:
    risk = ctx.get("risk") or {}
    risk_str = ", ".join(f"{k}={float(v):.2f}" for k, v in risk.items())
    det = ctx.get("detector") or {}
    drivers = ctx.get("feature_drivers") or []
    driver_str = "; ".join(
        f"{d.get('label', d.get('feature'))}={d.get('observed')}" for d in drivers[:5]
    )
    return (
        f"Device: {ctx.get('host')} ({ctx.get('hostname') or 'unknown'}, role={ctx.get('role','device')})\n"
        f"Forecast state: {ctx.get('forecast_state')}  peak_risk={float(ctx.get('peak_risk',0)):.2f}\n"
        f"Future risk by horizon: {risk_str}\n"
        f"Predicted ATT&CK stage: {ctx.get('stage')}\n"
        f"Present-state detector: attack_now={float(det.get('attack_now',0)):.2f}, "
        f"stage={det.get('stage_name')}, signature=\"{det.get('signature','')}\"\n"
        f"Top observed drivers: {driver_str or 'n/a'}\n"
        f"Attacker/source IP (if known): {ctx.get('source_ip') or 'unknown'}\n"
    )


_ACTION_LIST = ", ".join(sorted(ACTION_TYPES))

_TIER1_SYS = (
    "You are Tier-1 of a network defense assistant. Triage ONE device's attack forecast quickly. "
    "Respond ONLY as compact JSON with keys: "
    "severity (one of low|medium|high|critical), contain (boolean), "
    f"action_type (one of: {_ACTION_LIST}), target_ip (string), target_port (integer or null), "
    "ttl_seconds (integer 60-3600), one_line (short reason). "
    "Choose the least-disruptive action that stops the predicted stage."
)

_TIER2_SYS = (
    "You are Tier-2 of a network defense assistant: the senior analyst. You are given the full "
    "context and Tier-1's candidate action. Produce the final operator recommendation. "
    "Respond ONLY as JSON with keys: "
    f"action_type (one of: {_ACTION_LIST}), target_ip (string), target_port (integer or null), "
    "ttl_seconds (integer 60-3600), headline (short imperative action title), "
    "rationale (2-3 sentence justification tied to the evidence), "
    "steps (array of 2-4 short strings), confidence (0..1 float), "
    "monitor_only (boolean: true if you judge containment is NOT yet warranted). "
    "Prefer reversible, least-disruptive containment. Never recommend blocking a management IP."
)


def _validate(candidate: dict[str, Any], ctx: dict[str, Any], mgmt: set[str]) -> dict[str, Any] | None:
    """Coerce/validate an LLM action object; return None if unusable."""
    if not isinstance(candidate, dict):
        return None
    action_type = str(candidate.get("action_type", "")).strip()
    if action_type not in ACTION_TYPES:
        return None
    target_ip = str(candidate.get("target_ip") or ctx.get("source_ip") or ctx.get("host") or "").strip()
    if target_ip in mgmt:
        # Never cut our own access: downgrade to monitor-only.
        return {"monitor_only": True}
    port = candidate.get("target_port")
    try:
        port = int(port) if port not in (None, "", "null") else None
    except (TypeError, ValueError):
        port = None
    try:
        ttl = int(candidate.get("ttl_seconds", 300))
    except (TypeError, ValueError):
        ttl = 300
    ttl = max(60, min(3600, ttl))
    return {"action_type": action_type, "target_ip": target_ip, "target_port": port, "ttl_seconds": ttl}


def advise(ctx: dict[str, Any], *, management_ips: set[str] | None = None) -> dict[str, Any]:
    """Return a decision actionable for one device forecast.

    ctx keys: host, hostname, role, forecast_state, peak_risk, risk (dict),
    stage (str), detector (dict), feature_drivers (list), source_ip (optional).
    """
    mgmt = set(management_ips or _DEFAULT_MGMT)
    stage_id = int(ctx.get("stage_id", 0) or 0)
    state = str(ctx.get("forecast_state", "NORMAL"))
    fallback = recommended_action(stage=stage_id, state=state, host=str(ctx.get("host", "")))
    fallback = {**fallback, "source": "fallback", "headline": fallback.get("label", "Monitor only"),
                "rationale": fallback.get("rationale", ""), "steps": [], "confidence": 0.4,
                "tier1": None, "model_tier1": None, "model_tier2": None,
                "rule_preview": None, "monitor_only": fallback.get("action_type") is None}

    # Only engage the LLM when there is something to contain.
    if state not in {"EARLY_WARNING", "CONFIRMED_ALERT"}:
        return {**fallback, "monitor_only": True}
    if not ollama_available():
        return fallback

    ctx_str = _context_str(ctx)
    tier1 = _ollama_chat(TIER1_MODEL, _TIER1_SYS, ctx_str, url=TIER1_URL)
    tier1_valid = _validate(tier1 or {}, ctx, mgmt) if tier1 else None

    tier2_user = ctx_str + "\nTier-1 candidate action:\n" + json.dumps(tier1 or {}, default=str)
    # Tier-2 is larger and may be remote; allow a generous cold-load timeout.
    tier2 = _ollama_chat(TIER2_MODEL, _TIER2_SYS, tier2_user, url=TIER2_URL, timeout=180.0)
    if not tier2:
        # Tier-2 unavailable: use Tier-1's validated candidate if we have one.
        if tier1_valid and not tier1_valid.get("monitor_only"):
            return {**fallback, **tier1_valid, "source": "llm_tier1",
                    "headline": (tier1 or {}).get("one_line", fallback["headline"]),
                    "tier1": tier1, "model_tier1": TIER1_MODEL, "monitor_only": False}
        return fallback

    if tier2.get("monitor_only"):
        return {**fallback, "monitor_only": True, "source": "llm",
                "rationale": str(tier2.get("rationale", fallback["rationale"])),
                "tier1": tier1, "model_tier1": TIER1_MODEL, "model_tier2": TIER2_MODEL}

    valid = _validate(tier2, ctx, mgmt)
    if not valid or valid.get("monitor_only"):
        # Trust Tier-1 if Tier-2's action was malformed/mgmt-targeted.
        if tier1_valid and not tier1_valid.get("monitor_only"):
            valid = tier1_valid
        else:
            return {**fallback, "monitor_only": True, "source": "llm",
                    "rationale": str(tier2.get("rationale", fallback["rationale"])),
                    "tier1": tier1, "model_tier1": TIER1_MODEL, "model_tier2": TIER2_MODEL}

    steps = tier2.get("steps")
    steps = [str(s) for s in steps][:4] if isinstance(steps, list) else []
    try:
        confidence = max(0.0, min(1.0, float(tier2.get("confidence", 0.6))))
    except (TypeError, ValueError):
        confidence = 0.6
    return {
        **fallback,
        **valid,
        "label": str(tier2.get("headline", valid["action_type"].replace("_", " "))),
        "headline": str(tier2.get("headline", valid["action_type"].replace("_", " "))),
        "rationale": str(tier2.get("rationale", fallback["rationale"])),
        "steps": steps,
        "confidence": confidence,
        "requires_human_approval": True,
        "recommendation_only": True,
        "monitor_only": False,
        "source": "llm",
        "tier1": tier1,
        "model_tier1": TIER1_MODEL,
        "model_tier2": TIER2_MODEL,
        "rule_preview": _rule_preview(valid),
    }


def _rule_preview(action: dict[str, Any]) -> str:
    """A human-readable preview of the rule the controller would execute."""
    at, ip, port = action.get("action_type"), action.get("target_ip"), action.get("target_port")
    ttl = action.get("ttl_seconds", 300)
    if at in {"block_source_ip", "block_destination_ip", "isolate_host", "restrict_east_west"}:
        return f"nft drop {ip} (+ router block) for {ttl}s"
    if at == "block_attack_port":
        return f"nft drop {ip}:{port} for {ttl}s"
    if at == "rate_limit":
        return f"nft rate-limit {ip}:{port} for {ttl}s"
    return f"{at} {ip}"


__all__ = ["advise", "ollama_available", "warmup"]
