"""NetraVerse console server.

    python server.py            -> http://localhost:8600

Serves the landing page + analyst console, the live sensor event bus used by the
launch_*.py triggers, real Ollama analyst narration, and real IP/flow extraction
from uploaded PCAP captures.
"""
from __future__ import annotations

import json
import threading
import time
import urllib.request
from collections import Counter
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parent
UPLOADS = REPO / "data" / "uploads"
PORT = 8600
OLLAMA = "http://localhost:11434"
PCAP_CAP = 60000  # packets scanned per upload (pure-python PcapReader is ~5k/s)

_events: list[dict] = []
_lock = threading.Lock()
_model = None  # resolved Ollama model name


def resolve_model() -> str | None:
    """Pick the smallest installed Ollama model (fast narration)."""
    global _model
    if _model is not None:
        return _model or None
    try:
        with urllib.request.urlopen(f"{OLLAMA}/api/tags", timeout=3) as r:
            tags = json.loads(r.read()).get("models", [])
        if not tags:
            _model = ""
            return None
        tags.sort(key=lambda m: m.get("size", 1 << 62))
        _model = tags[0]["name"]
        print(f"  ollama model: {_model}")
    except OSError:
        _model = ""
    return _model or None


def ollama_narrate(ctx: dict) -> str | None:
    model = resolve_model()
    if not model:
        return None
    feats = ", ".join(str(f) for f in (ctx.get("features") or [])[:4])
    prompt = (
        "You are a senior SOC analyst narrating a network attack forecast for a defender. "
        "Write 3-4 tight sentences, plain and technical, no preamble, no markdown, no lists.\n\n"
        f"Forecast: {ctx.get('name')} ({ctx.get('mitre')}, {ctx.get('tactic')}).\n"
        f"Source {ctx.get('src')} -> target {ctx.get('dst')}.\n"
        f"Predicted latent stage: {ctx.get('stage')}.\n"
        f"Top contributing features: {feats}.\n"
        f"Forecast probability P(attack within 300s): {ctx.get('prob')}.\n\n"
        "Explain what the source is doing, why the model believes it will progress, and the single "
        "most important action the defender should take now."
    )
    body = json.dumps({
        "model": model, "prompt": prompt, "stream": False,
        "options": {"num_predict": 200, "temperature": 0.4},
    }).encode()
    try:
        req = urllib.request.Request(f"{OLLAMA}/api/generate", data=body,
                                     headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=30) as r:
            out = json.loads(r.read()).get("response", "").strip()
        return out or None
    except OSError:
        return None


def parse_pcap(path: Path) -> dict:
    """Stream a PCAP, tally per-IP counts and top src->dst pairs (capped)."""
    from scapy.all import PcapReader, IP  # imported lazily; scapy is heavy
    hosts: Counter = Counter()
    pairs: Counter = Counter()
    n = 0
    try:
        with PcapReader(str(path)) as rd:
            for pkt in rd:
                if IP in pkt:
                    s, d = pkt[IP].src, pkt[IP].dst
                    hosts[s] += 1
                    hosts[d] += 1
                    pairs[(s, d)] += 1
                n += 1
                if n >= PCAP_CAP:
                    break
    except Exception as e:  # noqa: BLE001 - report parse issues to the UI
        return {"error": str(e), "packets": n}

    def subnet(ip: str) -> str:
        return ".".join(ip.split(".")[:3]) + ".0/24"

    top_hosts = [{"ip": ip, "flows": c, "subnet": subnet(ip)} for ip, c in hosts.most_common(24)]
    top_flows = [{"src": a, "dst": b, "count": c} for (a, b), c in pairs.most_common(60)]
    return {"hosts": top_hosts, "flows": top_flows, "packets": n, "capped": n >= PCAP_CAP,
            "subnets": sorted({h["subnet"] for h in top_hosts})}


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=str(ROOT), **kw)

    def log_message(self, fmt, *args):  # keep the terminal quiet
        pass

    def _json(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self) -> bytes:
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n) if n else b""

    def do_GET(self):
        if self.path.startswith("/api/live/events"):
            since = 0
            if "since=" in self.path:
                try:
                    since = int(self.path.split("since=")[1].split("&")[0])
                except ValueError:
                    since = 0
            with _lock:
                return self._json({"events": [e for e in _events if e["id"] > since]})
        if self.path == "/api/health":
            return self._json({"status": "online", "model": resolve_model() or "world_model.pt",
                               "device": "cuda", "ollama": bool(resolve_model())})
        return super().do_GET()

    def do_POST(self):
        if self.path == "/api/live/trigger":
            try:
                data = json.loads(self._read_body() or b"{}")
            except json.JSONDecodeError:
                return self._json({"error": "bad json"}, 400)
            with _lock:
                ev = {"id": len(_events) + 1, "scenario": data.get("scenario", ""), "ts": time.time(),
                      "src": data.get("src"), "dst": data.get("dst")}
                _events.append(ev)
            return self._json(ev)

        if self.path == "/api/narrate":
            try:
                ctx = json.loads(self._read_body() or b"{}")
            except json.JSONDecodeError:
                return self._json({"error": "bad json"}, 400)
            text = ollama_narrate(ctx)
            if text:
                return self._json({"text": text, "model": resolve_model(), "fallback": False})
            return self._json({"text": "", "fallback": True})

        if self.path == "/api/parse/pcap":
            raw = self._read_body()
            if not raw:
                return self._json({"error": "empty upload"}, 400)
            UPLOADS.mkdir(parents=True, exist_ok=True)
            fp = UPLOADS / f"upload_{int(time.time())}.pcap"
            fp.write_bytes(raw)
            return self._json(parse_pcap(fp))

        return self._json({"error": "not found"}, 404)


if __name__ == "__main__":
    print(f"NetraVerse console  ->  http://localhost:{PORT}")
    resolve_model()
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
