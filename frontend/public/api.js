/*
 * NetraVerse live-data client — single source of truth for page content.
 *
 * Every page's <main> is a single mount (#nv-root). This file renders ALL page
 * content from the FastAPI world-model backend. There is no fixture/demo data:
 * every number, stage, chart, table and sentence comes from a model call.
 * Missing data renders an honest "unavailable" state, never a fabricated value.
 *
 * The active capture (replay scenario/host or an upload) lives in
 * sessionStorage (`nv_sel`) so the whole product follows one capture.
 */
(() => {
  const queryApi = new URLSearchParams(window.location.search).get("api");
  let storedApi = "";
  try { storedApi = window.localStorage.getItem("nv_api_base") || ""; } catch {}
  const defaultApi = window.location.hostname === "100.81.46.8" ? "http://100.72.80.52:8000" : "http://localhost:8000";
  const BASE = (window.NV_API_BASE || queryApi || storedApi || defaultApi).replace(/\/$/, "");
  const route = document.body.dataset.route || "home";
  const store = {
    get sel() { try { return JSON.parse(sessionStorage.getItem("nv_sel") || "null"); } catch { return null; } },
    set sel(v) { try { sessionStorage.setItem("nv_sel", JSON.stringify(v)); } catch {} },
  };

  /* ---------------- helpers ---------------- */
  const api = {
    async get(p) { const r = await fetch(BASE + p); if (!r.ok) { const body = await r.json().catch(() => ({})); const detail = typeof body.detail === "string" ? body.detail : body.detail ? JSON.stringify(body.detail) : r.statusText; throw new Error(detail); } return r.json(); },
    async post(p, body, token) {
      const headers = { "Content-Type": "application/json" };
      if (token) headers["X-Operator-Token"] = token;
      const r = await fetch(BASE + p, { method: "POST", headers, body: JSON.stringify(body) });
      if (!r.ok) { const data = await r.json().catch(() => ({})); throw new Error(data.detail || r.statusText); }
      return r.json();
    },
    async upload(file) { const fd = new FormData(); fd.append("file", file); const r = await fetch(BASE + "/api/upload", { method: "POST", body: fd }); if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || r.statusText); return r.json(); },
  };
  const h = (html) => { const t = document.createElement("template"); t.innerHTML = html.trim(); return t.content.firstElementChild; };
  const esc = (s) => String(s == null ? "" : s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  const pct = (x) => (x == null || isNaN(x) ? "n/a" : (x * 100).toFixed(1) + "%");
  const num = (x) => (x == null || isNaN(x) ? "—" : (+x).toLocaleString());
  const hhmmss = (iso) => (iso ? String(iso).slice(11, 19) : "—");
  const cap = (s) => (s ? s.charAt(0) + s.slice(1).toLowerCase() : s);
  const stageName = (s) => cap(String(s || "").replace(/_/g, " "));
  const REPLAY_STAGE_META = [
    ["BENIGN", "Benign", "#94a3b8"],
    ["RECONNAISSANCE", "Reconnaissance", "#0284c7"],
    ["INITIAL ACCESS", "Initial Access", "#7c3aed"],
    ["LATERAL MOVEMENT", "Lateral Movement", "#0d9488"],
    ["COMMAND AND CONTROL", "Command & Control", "#dc2626"],
    ["EXFILTRATION", "Exfiltration", "#ea580c"],
    ["IMPACT", "Impact", "#be123c"],
  ];
  const replayStageColor = (stage) =>
    (REPLAY_STAGE_META.find(([key]) => key === String(stage || "").toUpperCase()) || ["", "", "#64748b"])[2];

  /* header context bar + sidebar status */
  const setText = (id, v) => { const el = document.getElementById(id); if (el && v != null) el.textContent = v; };
  function setCtx({ scenario, host, horizon, mode, data }) {
    setText("nv-ctx-scenario", scenario); setText("nv-ctx-host", host);
    setText("nv-ctx-horizon", horizon); setText("nv-ctx-mode", mode); setText("nv-side-data", data);
  }
  function setSide(ok) {
    const el = document.getElementById("nv-side-status"); if (!el) return;
    el.className = "flex items-center gap-1.5 pt-1 " + (ok ? "text-emerald-700" : "text-rose-700");
    el.innerHTML = `<span class="w-1.5 h-1.5 rounded-full ${ok ? "bg-emerald-500" : "bg-rose-500"}"></span>
      <span class="font-mono text-[10px] uppercase tracking-wider font-semibold">${ok ? "Model Online" : "Model Offline"}</span>`;
  }

  const rootEl = () => document.getElementById("nv-root") || document.querySelector("main") || document.body;
  function shell(eyebrow, title, sub, controls) {
    rootEl().innerHTML = `<div class="nv-wrap"><div class="nv-page-head">
      <div><p class="nv-eyebrow">${esc(eyebrow)}</p><h1 class="nv-title">${esc(title)}</h1><p class="nv-sub">${esc(sub)}</p></div>
      <div class="nv-controls" id="nv-ctrl">${controls || ""}</div></div>
      <div id="nv-content"><div class="nv-loading">Loading real model output…</div></div></div>`;
    return document.getElementById("nv-content");
  }
  const section = (step, title, sub, body, cls = "") =>
    `<section class="nv-section ${cls}"><div class="hd"><div>${step ? `<p class="step">${esc(step)}</p>` : ""}<h2 class="t">${esc(title)}</h2>${sub ? `<p class="s">${esc(sub)}</p>` : ""}</div></div><div class="bd">${body}</div></section>`;
  const card = (h3, inner) => `<div class="nv-card">${h3 ? `<h3>${esc(h3)}</h3>` : ""}${inner}</div>`;
  const metric = (k, v, opt = {}) => `<div class="nv-metric ${opt.cls || ""}"><div class="k">${esc(k)}</div><div class="v">${v}</div>${opt.sub ? `<div class="sub">${esc(opt.sub)}</div>` : ""}</div>`;
  const caveat = (t) => `<p class="nv-caveat">${esc(t)}</p>`;

  const riskBadge = (r, thr) => {
    if (r == null) return `<span class="nv-badge observed"><span class="dot"></span>Unavailable</span>`;
    const over = r >= thr;
    const cls = over ? "critical" : (r >= thr * 0.6 ? "elevated" : "benign");
    const lbl = over ? "Elevated" : (r >= thr * 0.6 ? "Approaching" : "Nominal");
    return `<span class="nv-badge ${cls}"><span class="dot"></span>${lbl} · ${pct(r)}</span>`;
  };
  const stageBadge = (s, kind) => {
    const S = String(s || "").toUpperCase();
    const cls = S === "BENIGN" ? "benign" : (["EXFILTRATION", "IMPACT", "COMMAND AND CONTROL"].includes(S) ? "critical" : "elevated");
    return `<span class="nv-badge ${kind || cls}">${esc(stageName(S))}</span>`;
  };

  function leadLabel(d) {
    if (!d.ground_truth) return "n/a (upload)";
    if (!d.first_alert) return "no sustained alert";
    const l = d.lead_time_s;
    if (l == null) return "at onset";
    if (l > 0) return l + " s early";
    if (l < 0) return Math.abs(l) + " s late";
    return "at onset";
  }
  function plainBlock(pl) {
    if (!pl) return "";
    return card("Plain-language read-out", `<div class="nv-plain">
      <div><b>Now</b>${esc(pl.now)}</div>
      <div><b>Next 120 s</b>${esc(pl.next)}</div>
      <div><b>Confidence</b>${esc(pl.uncertainty)}</div></div>`);
  }

  /* ---------------- charts ---------------- */
  // Observed forecast-risk timeline with threshold, attack bands, and a marked peak (t0 boundary).
  function riskTimeline(d) {
    const obs = d.observed || [];
    if (!obs.length) return `<div class="nv-empty">No forecastable windows for this host.</div>`;
    const W = 860, H = 240, padL = 40, padR = 16, padT = 16, padB = 34;
    const iw = W - padL - padR, ih = H - padT - padB, n = obs.length;
    const x = (i) => padL + (n === 1 ? iw / 2 : (i / (n - 1)) * iw);
    const y = (v) => padT + (1 - Math.min(1, v)) * ih;
    const risks = obs.map((o) => o.risk);
    const peakAt = d.peak_at, focusAt = d.focus_at;
    const times = obs.map((o) => Date.parse(o.t));
    // attack bands
    let bands = "";
    (d.attack_intervals || []).forEach(([a, b]) => {
      const ta = Date.parse(a), tb = Date.parse(b);
      let lo = times.findIndex((t) => t >= ta); if (lo < 0) return;
      let hi = times.findIndex((t) => t > tb); if (hi < 0) hi = n; hi = Math.max(lo + 1, hi);
      bands += `<rect x="${x(lo).toFixed(1)}" y="${padT}" width="${(x(Math.min(hi, n - 1)) - x(lo) || 3).toFixed(1)}" height="${ih}" fill="#fca5a5" opacity="0.25"/>`;
    });
    const line = risks.map((v, i) => `${x(i).toFixed(1)},${y(v).toFixed(1)}`).join(" ");
    const area = `${padL},${padT + ih} ${line} ${x(n - 1).toFixed(1)},${padT + ih}`;
    const thrY = y(d.threshold);
    // grid + y labels
    let grid = "";
    [0, 0.25, 0.5, 0.75, 1].forEach((g) => {
      grid += `<line x1="${padL}" y1="${y(g)}" x2="${W - padR}" y2="${y(g)}" stroke="#f1f5f9"/>
        <text x="${padL - 6}" y="${y(g) + 3}" text-anchor="end" font-size="9" fill="#94a3b8" font-family="IBM Plex Mono">${g.toFixed(2)}</text>`;
    });
    // x labels (first, mid, last)
    let xlab = "";
    [0, Math.floor((n - 1) / 2), n - 1].forEach((i) => {
      xlab += `<text x="${x(i)}" y="${H - 12}" text-anchor="middle" font-size="9" fill="#94a3b8" font-family="IBM Plex Mono">${hhmmss(obs[i].t)}</text>`;
    });
    // points + peak marker
    let pts = "", peakX = null;
    obs.forEach((o, i) => {
      const isPeak = o.t === peakAt || o.t === focusAt;
      if (isPeak) peakX = x(i);
      pts += `<circle cx="${x(i).toFixed(1)}" cy="${y(o.risk).toFixed(1)}" r="${isPeak ? 4.5 : 2.6}" fill="${isPeak ? "#0284c7" : "#64748b"}" ${isPeak ? 'stroke="#fff" stroke-width="1.5"' : ""}><title>${hhmmss(o.t)} · risk ${pct(o.risk)} · ${stageName(o.stage)}</title></circle>`;
    });
    const peakMark = peakX != null ? `<line x1="${peakX.toFixed(1)}" y1="${padT}" x2="${peakX.toFixed(1)}" y2="${padT + ih}" stroke="#0284c7" stroke-dasharray="4 3" stroke-width="1"/>
      <text x="${peakX.toFixed(1)}" y="${padT - 4}" text-anchor="middle" font-size="9" fill="#0284c7" font-family="IBM Plex Mono">peak</text>` : "";
    return `<div class="nv-chart"><svg viewBox="0 0 ${W} ${H}" width="100%" preserveAspectRatio="xMidYMid meet">
      ${grid}${bands}
      <polygon points="${area}" fill="#0284c7" opacity="0.07"/>
      <line x1="${padL}" y1="${thrY}" x2="${W - padR}" y2="${thrY}" stroke="#d97706" stroke-dasharray="5 4" stroke-width="1.2"/>
      <text x="${W - padR}" y="${thrY - 4}" text-anchor="end" font-size="9" fill="#b45309" font-family="IBM Plex Mono">alert ${d.threshold}</text>
      <polyline points="${line}" fill="none" stroke="#0284c7" stroke-width="2.2"/>
      ${peakMark}${pts}${xlab}
    </svg></div>
    <div class="nv-legend"><span class="l-risk">forecast risk (per 30 s window)</span><span class="l-thr">alert threshold</span>${d.ground_truth && (d.attack_intervals||[]).length ? '<span class="l-atk">recorded attack window</span>' : ""}</div>`;
  }

  // K-step projection from the current state, with real MC-dropout envelope when present.
  function projectionChart(nowRisk, steps, thr) {
    if (!steps || !steps.length) return "";
    const pts0 = [{ risk: nowRisk, hz: "S_t", unc: 0 }].concat(steps.map((s) => ({ risk: s.risk, hz: s.horizon, unc: s.uncertainty || 0 })));
    const W = 560, H = 170, padL = 38, padR = 16, padT = 14, padB = 26;
    const iw = W - padL - padR, ih = H - padT - padB, n = pts0.length;
    const x = (i) => padL + (i / (n - 1)) * iw;
    const y = (v) => padT + (1 - Math.min(1, Math.max(0, v))) * ih;
    const hasUnc = steps.some((s) => s.uncertainty != null);
    let envelope = "";
    if (hasUnc) {
      const up = pts0.map((p, i) => `${x(i).toFixed(1)},${y(p.risk + p.unc / 2).toFixed(1)}`);
      const dn = pts0.map((p, i) => `${x(i).toFixed(1)},${y(p.risk - p.unc / 2).toFixed(1)}`).reverse();
      envelope = `<polygon points="${up.concat(dn).join(" ")}" fill="#0284c7" opacity="0.12"/>`;
    }
    const line = pts0.map((p, i) => `${x(i).toFixed(1)},${y(p.risk).toFixed(1)}`).join(" ");
    let grid = "";
    [0, 0.5, 1].forEach((g) => { grid += `<line x1="${padL}" y1="${y(g)}" x2="${W - padR}" y2="${y(g)}" stroke="#f1f5f9"/><text x="${padL - 6}" y="${y(g) + 3}" text-anchor="end" font-size="9" fill="#94a3b8" font-family="IBM Plex Mono">${g.toFixed(1)}</text>`; });
    const thrY = y(thr);
    let marks = "";
    pts0.forEach((p, i) => {
      marks += `<circle cx="${x(i).toFixed(1)}" cy="${y(p.risk).toFixed(1)}" r="${i === 0 ? 4 : 3.4}" fill="${i === 0 ? "#0d9488" : "#0284c7"}" stroke="#fff" stroke-width="1.3"><title>${p.hz} · ${pct(p.risk)}${p.unc ? " ±" + pct(p.unc) : ""}</title></circle>
        <text x="${x(i).toFixed(1)}" y="${H - 8}" text-anchor="middle" font-size="9" fill="#64748b" font-family="IBM Plex Mono">${esc(p.hz)}</text>`;
    });
    return `<div class="nv-chart"><svg viewBox="0 0 ${W} ${H}" width="100%" preserveAspectRatio="xMidYMid meet">
      ${grid}${envelope}
      <line x1="${padL}" y1="${thrY}" x2="${W - padR}" y2="${thrY}" stroke="#d97706" stroke-dasharray="5 4" stroke-width="1"/>
      <polyline points="${line}" fill="none" stroke="#0284c7" stroke-width="2.4"/>${marks}
    </svg></div>${hasUnc ? `<p class="nv-note">Shaded band = MC-dropout uncertainty (20 stochastic passes) — real model spread, not a fixed interval.</p>` : ""}`;
  }

  // Simple framed sparkline for a single telemetry series.
  function spark(values, color = "#0284c7", labels) {
    const n = (values || []).length; if (!n) return `<div class="nv-empty">No data.</div>`;
    const W = 560, H = 90, padL = 6, padR = 6, padT = 8, padB = 16;
    const iw = W - padL - padR, ih = H - padT - padB;
    const max = Math.max(1e-9, ...values), min = Math.min(0, ...values);
    const x = (i) => padL + (n === 1 ? iw / 2 : (i / (n - 1)) * iw);
    const y = (v) => padT + (1 - (v - min) / (max - min || 1)) * ih;
    const line = values.map((v, i) => `${x(i).toFixed(1)},${y(v).toFixed(1)}`).join(" ");
    const area = `${padL},${padT + ih} ${line} ${x(n - 1).toFixed(1)},${padT + ih}`;
    let xl = "";
    if (labels) [0, n - 1].forEach((i) => { xl += `<text x="${x(i)}" y="${H - 4}" text-anchor="${i === 0 ? "start" : "end"}" font-size="9" fill="#94a3b8" font-family="IBM Plex Mono">${esc(labels[i])}</text>`; });
    return `<div class="nv-chart"><svg viewBox="0 0 ${W} ${H}" width="100%" preserveAspectRatio="none">
      <polygon points="${area}" fill="${color}" opacity="0.08"/>
      <polyline points="${line}" fill="none" stroke="${color}" stroke-width="2"/>
      <text x="${padL}" y="12" font-size="9" fill="#94a3b8" font-family="IBM Plex Mono">max ${(+max).toLocaleString(undefined,{maximumFractionDigits:2})}</text>${xl}
    </svg></div>`;
  }

  function networkSpark(values, color = "#0284c7", labels = [], unit = "") {
    const vals = (values || []).map((value) => Number.isFinite(+value) ? +value : 0);
    const n = vals.length; if (!n) return `<div class="nv-empty">No data.</div>`;
    const W = 900, H = 250, padL = 58, padR = 22, padT = 24, padB = 38;
    const iw = W - padL - padR, ih = H - padT - padB;
    const max = Math.max(1e-9, ...vals), min = Math.min(0, ...vals), span = max - min || 1;
    const x = (i) => padL + (n === 1 ? iw / 2 : i / (n - 1) * iw);
    const y = (v) => padT + (1 - (v - min) / span) * ih;
    const fmt = (v) => (+v).toLocaleString(undefined, { maximumFractionDigits: 2 });
    const line = vals.map((v, i) => `${x(i).toFixed(1)},${y(v).toFixed(1)}`).join(" ");
    const area = `${padL},${padT + ih} ${line} ${x(n - 1).toFixed(1)},${padT + ih}`;
    let grid = "";
    [0, 0.5, 1].forEach((ratio) => {
      const value = min + span * ratio, yy = y(value);
      grid += `<line x1="${padL}" y1="${yy}" x2="${W - padR}" y2="${yy}" stroke="#e2e8f0"/><text x="${padL - 8}" y="${yy + 4}" text-anchor="end" font-size="11" fill="#64748b" font-family="IBM Plex Mono">${fmt(value)}</text>`;
    });
    const pointLabels = vals.map((value, i) => `<circle cx="${x(i).toFixed(1)}" cy="${y(value).toFixed(1)}" r="${i === n - 1 ? 5 : 2.5}" fill="${color}" stroke="#fff" stroke-width="1"><title>${labels[i] || `window ${i + 1}`} · ${fmt(value)}${unit ? ` ${unit}` : ""}</title></circle>`).join("");
    const labelIndexes = [...new Set([0, Math.floor((n - 1) / 2), n - 1])];
    const timeLabels = labelIndexes.map((i) => `<text x="${x(i)}" y="${H - 10}" text-anchor="middle" font-size="11" fill="#475569" font-family="IBM Plex Mono">${esc(labels[i] || `window ${i + 1}`)}</text>`).join("");
    return `<div class="nv-chart nv-network-chart"><svg viewBox="0 0 ${W} ${H}" width="100%" role="img" aria-label="Network telemetry over time">
      ${grid}<polygon points="${area}" fill="${color}" opacity="0.08"/><polyline points="${line}" fill="none" stroke="${color}" stroke-width="3" stroke-linejoin="round" stroke-linecap="round"/>${pointLabels}
      <text x="${padL}" y="14" font-size="11" fill="#475569" font-family="IBM Plex Mono">max ${fmt(max)}${unit ? ` ${unit}` : ""}</text>${timeLabels}
    </svg></div>`;
  }

  /* ---------------- streaming replay (causal, step-by-step) ---------------- */
  function idxBands(d, times) {
    const out = [];
    (d.attack_intervals || []).forEach(([a, b]) => {
      const ta = Date.parse(a), tb = Date.parse(b);
      let lo = times.findIndex((t) => t >= ta); if (lo < 0) return;
      let hi = times.findIndex((t) => t > tb); if (hi < 0) hi = times.length;
      out.push([lo, Math.max(lo, hi - 1)]);
    });
    return out;
  }
  function revealChart(d, step) {
    const obs = d.observed || [], n = obs.length;
    const W = 860, H = 200, padL = 40, padR = 16, padT = 14, padB = 30;
    const iw = W - padL - padR, ih = H - padT - padB;
    const x = (i) => padL + (n === 1 ? iw / 2 : (i / (n - 1)) * iw);
    const y = (v) => padT + (1 - Math.min(1, v)) * ih;
    const times = obs.map((o) => Date.parse(o.t));
    const bands = idxBands(d, times).filter(([lo]) => lo <= step)
      .map(([lo, hi]) => `<rect x="${x(lo).toFixed(1)}" y="${padT}" width="${(x(Math.min(hi, step)) - x(lo) || 3).toFixed(1)}" height="${ih}" fill="#fca5a5" opacity="0.28"/>`).join("");
    const pts = obs.slice(0, step + 1).map((o, i) => `${x(i).toFixed(1)},${y(o.risk).toFixed(1)}`).join(" ");
    const thrY = y(d.threshold);
    let grid = "";
    [0, 0.5, 1].forEach((g) => { grid += `<line x1="${padL}" y1="${y(g)}" x2="${W - padR}" y2="${y(g)}" stroke="#f1f5f9"/><text x="${padL - 6}" y="${y(g) + 3}" text-anchor="end" font-size="9" fill="#94a3b8" font-family="IBM Plex Mono">${g.toFixed(1)}</text>`; });
    const cur = obs[step];
    const cursor = `<line x1="${x(step).toFixed(1)}" y1="${padT}" x2="${x(step).toFixed(1)}" y2="${padT + ih}" stroke="#0284c7" stroke-width="1.5"/><circle cx="${x(step).toFixed(1)}" cy="${y(cur.risk).toFixed(1)}" r="4.5" fill="#0284c7" stroke="#fff" stroke-width="1.5"/>`;
    return `<div class="nv-chart"><svg viewBox="0 0 ${W} ${H}" width="100%" preserveAspectRatio="xMidYMid meet">
      ${grid}${bands}
      <line x1="${padL}" y1="${thrY}" x2="${W - padR}" y2="${thrY}" stroke="#d97706" stroke-dasharray="5 4" stroke-width="1.2"/>
      <text x="${W - padR}" y="${thrY - 4}" text-anchor="end" font-size="9" fill="#b45309" font-family="IBM Plex Mono">alert ${d.threshold}</text>
      <polyline points="${pts}" fill="none" stroke="#0284c7" stroke-width="2.4"/>${cursor}
      <text x="${x(step).toFixed(1)}" y="${H - 9}" text-anchor="middle" font-size="9" fill="#0284c7" font-family="IBM Plex Mono">now ${hhmmss(cur.t)}</text>
    </svg></div>`;
  }
  function temporalGraph(d, step) {
    const obs = d.observed || []; if (!obs.length) return `<div class="nv-empty">No graphable windows.</div>`;
    const visible = obs.slice(0, Math.max(0, step + 1));
    const W = 920, H = 250, left = 46, right = 18, top = 38, bottom = 44;
    const x = (i) => left + (visible.length === 1 ? (W-left-right)/2 : i/(visible.length-1)*(W-left-right));
    const stageColor = (s) => ({BENIGN:"#94a3b8",RECONNAISSANCE:"#0284c7", "INITIAL ACCESS":"#7c3aed", "LATERAL MOVEMENT":"#0d9488", "COMMAND AND CONTROL":"#dc2626", EXFILTRATION:"#ea580c", IMPACT:"#be123c"}[String(s).toUpperCase()] || "#64748b");
    const displayStage = (o) => d.ground_truth && o.observed_stage ? o.observed_stage : o.stage;
    const lines = visible.slice(1).map((o,i) => `<line x1="${x(i)}" y1="125" x2="${x(i+1)}" y2="125" stroke="#cbd5e1" stroke-width="2"/>`).join("");
    const labelEvery = Math.max(1, Math.ceil(visible.length / 12));
    const nodes = visible.map((o,i) => { const current = i === visible.length-1; const stage = displayStage(o); const r = 5 + Math.round((o.risk||0)*8); return `<g><circle cx="${x(i)}" cy="125" r="${current?r+3:r}" fill="${stageColor(stage)}" opacity="${current?1:.82}" stroke="${current?"#0f172a":"#fff"}" stroke-width="${current?2:1.5}"><title>${hhmmss(o.t)} · ${stageName(stage)} · forecast ${pct(o.risk)}${d.ground_truth && o.observed_stage ? " · recorded stage" : ""}</title></circle>${(i===0||i===visible.length-1||i%labelEvery===0)?`<text x="${x(i)}" y="156" text-anchor="middle" font-size="9" fill="#475569" font-family="IBM Plex Mono">${hhmmss(o.t)}</text><text x="${x(i)}" y="176" text-anchor="middle" font-size="8" fill="#64748b">${esc(stageName(stage))}</text>`:""}</g>`; }).join("");
    const future = obs.length > visible.length ? `<text x="${W-right}" y="22" text-anchor="end" font-size="10" fill="#64748b" font-family="IBM Plex Mono">future windows hidden until replay</text>` : `<text x="${W-right}" y="22" text-anchor="end" font-size="10" fill="#0f766e" font-family="IBM Plex Mono">observed timeline complete</text>`;
    return `<div class="nv-temporal-graph"><svg viewBox="0 0 ${W} ${H}" width="100%" role="img" aria-label="Temporal network replay graph"><line x1="${left}" y1="125" x2="${W-right}" y2="125" stroke="#e2e8f0"/>${lines}${nodes}${future}<text x="${left}" y="218" font-size="9" fill="#94a3b8" font-family="IBM Plex Mono">sequential observed windows · node size = risk</text></svg></div>`;
  }
  function temporalGraphScrollable(d, step) {
    const obs = d.observed || [];
    if (!obs.length) return `<div class="nv-empty">No graphable windows.</div>`;
    const visible = obs.slice(0, Math.max(0, step + 1));
    const H = 250, left = 46, right = 18;
    const W = Math.max(1100, left + right + Math.max(0, visible.length - 1) * 34);
    const x = (i) => left + (visible.length === 1 ? (W - left - right) / 2 : i / (visible.length - 1) * (W - left - right));
    const displayStage = (o) => d.ground_truth && o.observed_stage ? o.observed_stage : o.stage;
    const lines = visible.slice(1).map((o, i) => `<line x1="${x(i)}" y1="125" x2="${x(i + 1)}" y2="125" stroke="#cbd5e1" stroke-width="2"/>`).join("");
    const alertEvents = (d.alert_events || []).map((event) => ({ ...event,
      index: event.alert_at ? obs.findIndex((o) => Date.parse(o.t) >= Date.parse(event.alert_at)) : -1,
    })).filter((event) => event.index >= 0 && event.index < visible.length);
    const primaryAlert = alertEvents.find((event) => event.status !== "missed") || alertEvents[0];
    const alertMarkers = alertEvents.map((event) => {
      const lead = event.lead_time_s == null ? "" : ` · ${event.lead_time_s}s early`;
      const label = event === primaryAlert ? `<text x="${x(event.index)}" y="30" text-anchor="middle" font-size="10" font-weight="700" fill="#b91c1c" font-family="IBM Plex Mono">PREDICTION</text><text x="${x(event.index)}" y="45" text-anchor="middle" font-size="8" fill="#b91c1c" font-family="IBM Plex Mono">alert raised${esc(lead)}</text>` : "";
      return `<g class="nv-graph-alert-marker"><line x1="${x(event.index)}" y1="50" x2="${x(event.index)}" y2="116" stroke="#dc2626" stroke-width="1.5" stroke-dasharray="4 3"/><circle cx="${x(event.index)}" cy="50" r="3" fill="#dc2626"><title>Prediction raised at ${hhmmss(event.alert_at)}${esc(lead)}</title></circle>${label}</g>`;
    }).join("");
    const labelEvery = Math.max(1, Math.ceil(visible.length / 12));
    const nodes = visible.map((o, i) => {
      const current = i === visible.length - 1;
      const stage = displayStage(o);
      const color = replayStageColor(stage);
      const radius = 5 + Math.round((o.risk || 0) * 8);
      const recorded = d.ground_truth && o.observed_stage ? " · recorded stage" : " · predicted stage";
      const label = `${hhmmss(o.t)} · ${stageName(stage)} · forecast ${pct(o.risk)}${recorded}`;
      const labels = (i === 0 || current || i % labelEvery === 0)
        ? `<text x="${x(i)}" y="156" text-anchor="middle" font-size="9" fill="#475569" font-family="IBM Plex Mono">${hhmmss(o.t)}</text><text x="${x(i)}" y="176" text-anchor="middle" font-size="8" fill="#64748b">${esc(stageName(stage))}</text>` : "";
      const prediction = alertEvents.some((event) => event.index === i);
      const nodeLabel = prediction ? `${label} · prediction raised here` : label;
      return `<g class="nv-graph-node${current ? " current" : ""}${prediction ? " prediction-node" : ""}" data-node-index="${i}" tabindex="0" role="button" aria-label="${esc(nodeLabel)}"><circle cx="${x(i)}" cy="125" r="${current ? radius + 3 : radius}" fill="${color}" opacity="${current ? 1 : .82}" stroke="${prediction ? "#dc2626" : current ? "#0f172a" : "#fff"}" stroke-width="${prediction ? 2.5 : current ? 2 : 1.5}"><title>${esc(nodeLabel)}</title></circle>${labels}</g>`;
    }).join("");
    const future = obs.length > visible.length
      ? `<text x="${W - right}" y="22" text-anchor="end" font-size="10" fill="#64748b" font-family="IBM Plex Mono">future windows hidden until replay</text>`
      : `<text x="${W - right}" y="22" text-anchor="end" font-size="10" fill="#0f766e" font-family="IBM Plex Mono">observed timeline complete</text>`;
    const legend = REPLAY_STAGE_META.map(([key, label, color]) => `<span class="nv-graph-legend-item"><i style="background:${color}"></i>${esc(label)}</span>`).join("");
    return `<div class="nv-temporal-graph">
      <div class="nv-graph-header"><span class="nv-mono">temporal network · ${visible.length} observed window${visible.length === 1 ? "" : "s"}</span><span>scroll horizontally · hover a node for state details</span></div>
      <div class="nv-graph-scroll"><svg viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" role="img" aria-label="Scrollable temporal network replay graph"><line x1="${left}" y1="125" x2="${W - right}" y2="125" stroke="#e2e8f0"/>${lines}${alertMarkers}${nodes}${future}<text x="${left}" y="218" font-size="9" fill="#94a3b8" font-family="IBM Plex Mono">sequential observed windows · node size = risk</text></svg></div>
      <div class="nv-graph-legend">${legend}</div>
      <div class="nv-graph-detail" data-graph-detail>Hover a node to inspect its time, stage, risk, and replay state.</div>
    </div>`;
  }

  function replayPlayer(mount, d, onUpdate, onComplete, initialStep = 0, onReset = null) {
    if (!mount) return;
    const obs = d.observed || [];
    if (!obs.length) { mount.innerHTML = `<div class="nv-empty">No forecastable windows to replay.</div>`; return; }
    const n = obs.length, thr = d.threshold, times = obs.map((o) => Date.parse(o.t));
    const bands = idxBands(d, times), firstOnset = bands.length ? bands[0][0] : null;
    // Use the server's guarded first-sustained-alert window + lead time (honest, matches the API,
    // and avoids counting an early spurious threshold crossing as the alert).
    const events = (d.alert_events || []).map((e) => ({ ...e,
      alertIdx: e.alert_at ? obs.findIndex((o) => Date.parse(o.t) >= Date.parse(e.alert_at)) : -1,
      onsetIdx: e.onset_at ? obs.findIndex((o) => Date.parse(o.t) >= Date.parse(e.onset_at)) : -1,
    }));
    const alertIdx = events.find((e) => e.alertIdx >= 0)?.alertIdx ?? -1;
    const inBand = (i) => bands.some(([lo, hi]) => i >= lo && i <= hi);
    // Per-window state reflects the current forecast, not a latched flag.
    const state = (i) => inBand(i) ? "ATTACK_ACTIVE"
      : (obs[i].risk >= thr && i > 0 && obs[i - 1].risk >= thr) ? "ALERTING"
      : (obs[i].risk >= thr * 0.6) ? "ELEVATED" : "QUIET";
    const stCls = { QUIET: "observed", ELEVATED: "elevated", ALERTING: "critical", ATTACK_ACTIVE: "critical" };
    const SPEEDS = [0.5, 1, 2, 4];
    let step = Math.min(n - 1, Math.max(0, Number(initialStep) || 0)), playing = false, speed = 1, timer = null;
    function leadTxtLegacy(i) {
      if (alertIdx < 0) return d.ground_truth ? "no sustained alert" : "monitoring (unlabelled upload)";
      if (i < alertIdx) return "monitoring…";
      if (firstOnset != null && i >= firstOnset) {
        return serverLead == null ? "alerted at onset"
          : serverLead > 0 ? `warned ${serverLead}s BEFORE onset`
          : serverLead < 0 ? `detected ${Math.abs(serverLead)}s after onset` : "alerted at onset";
      }
      if (firstOnset != null) return `⚠ first alert ${hhmmss(d.first_alert)} — onset in ${Math.round((times[firstOnset] - times[i]) / 1000)} s`;
      return `⚠ first alert ${hhmmss(d.first_alert)} · onset unlabelled`;
    }
    // Decision log is event-based: it reports the exact alert decision and
    // its lead time for the relevant onset, never a stale global first alert.
    function leadTxt(i) {
      if (!d.ground_truth) return "monitoring (unlabelled upload)";
      if (!events.length) return "no labelled attack event";
      const active = events.find((e) => e.alertIdx >= 0 && i >= e.alertIdx && (e.onsetIdx < 0 || i <= e.onsetIdx));
      const upcoming = events.find((e) => e.onsetIdx < 0 || i < e.onsetIdx);
      const e = active || upcoming;
      if (!e) return "all labelled attack events processed";
      if (e.alertIdx >= 0 && i >= e.alertIdx) {
        const lead = e.lead_time_s == null ? "n/a" : `${e.lead_time_s}s`;
        const decision = e.action?.summary ? ` · ${e.action.summary}` : "";
        if (e.onsetIdx >= 0 && i >= e.onsetIdx) return `onset reached · alert raised ${hhmmss(e.alert_at)} · lead ${lead}${decision}`;
        return e.status === "early_warning" ? `ALERT RAISED ${hhmmss(e.alert_at)} · warning lead ${lead}${decision}` : `ALERT RAISED ${hhmmss(e.alert_at)} · ${e.status}${decision}`;
      }
      return "monitoring";
    }
    function liveDecisionSupport(event) {
      if (!event || event.alertIdx < 0) return "";
      const action = event.action || {};
      const actions = (action.actions || []).slice(0, 3).map((item) => `<li>${esc(item)}</li>`).join("");
      const mitigations = (action.mitre_mitigations || []).map((item) => `<span class="nv-chip">${esc(item)}</span>`).join("");
      const color = replayStageColor(event.stage);
      return `<div class="nv-live-decision" style="--nv-stage-color:${color}">
        <div class="nv-live-decision-head"><strong>Decision support · ${esc(stageName(event.stage))}</strong><span class="nv-badge critical">ALERT ACTIVE</span></div>
        <p>${esc(action.summary || "Investigate the alert and follow the approved response workflow.")}</p>
        ${actions ? `<ul class="nv-actions">${actions}</ul>` : ""}
        ${mitigations ? `<div class="nv-live-mitigations">${mitigations}</div>` : ""}
        <small>Advisory only · human approval required · warning lead ${event.lead_time_s == null ? "n/a" : `${event.lead_time_s}s`}</small>
      </div>`;
    }
    function render() {
      const cur = obs[step], st = state(step), activeEvent = events.find((e) => e.alertIdx >= 0 && step >= e.alertIdx && (e.onsetIdx < 0 || step <= e.onsetIdx)), warnAhead = Boolean(activeEvent && activeEvent.status === "early_warning");
      const shownStage = activeEvent?.stage || cur.stage;
      mount.innerHTML = `<div class="nv-replay">
        <div class="nv-replay-bar">
          <button class="nv-btn" data-a="playpause">${playing ? "❚❚ Pause" : "▶ Play"}</button>
          <button class="nv-btn sec" data-a="back" title="Step back">◀</button>
          <button class="nv-btn sec" data-a="fwd" title="Step forward">▶</button>
          <button class="nv-btn sec" data-a="restart" title="Restart">⟲</button>
          <span class="nv-replay-speed">${SPEEDS.map((s) => `<button class="nv-chip ${s === speed ? "warn" : ""}" data-speed="${s}">${s}×</button>`).join("")}</span>
          <span class="nv-replay-clock nv-mono">window ${step + 1}/${n}</span>
        </div>
        <div class="nv-replay-status">
          <span class="nv-badge ${stCls[st]}"><span class="dot"></span>${st.replace("_", " ")}</span>
          <span class="nv-mono">forecast risk ${pct(cur.risk)}</span>
          ${stageBadge(shownStage, activeEvent ? "critical" : undefined)}
          <span class="nv-mono ${warnAhead ? "nv-lead-hot" : ""}">${leadTxt(step)}</span>
        </div>
        ${liveDecisionSupport(activeEvent)}
        ${temporalGraphScrollable(d, step)}
        <input class="nv-replay-scrub" type="range" min="0" max="${n - 1}" value="${step}" aria-label="replay position"/>
        <p class="nv-note">Causal replay — at each step the model uses only windows ≤ now. The alert can fire <b>before</b> the shaded attack window is revealed; that gap is the warning lead time.</p>
      </div>`;
      const graphDetail = mount.querySelector("[data-graph-detail]");
      const graphNodes = mount.querySelectorAll("[data-node-index]");
      const showNode = (index) => {
        if (!graphDetail || !obs[index]) return;
        const item = obs[index];
        const itemStage = d.ground_truth && item.observed_stage ? item.observed_stage : item.stage;
        const itemEvent = events.find((e) => e.alertIdx === index);
        const itemState = itemEvent && itemEvent.alertIdx >= 0 && index >= itemEvent.alertIdx ? "ALERT DECISION" : state(index).replace("_", " ");
        graphDetail.innerHTML = `<b>${esc(hhmmss(item.t))}</b><span>${esc(stageName(itemStage))}</span><span>risk ${pct(item.risk)}</span><span>${esc(itemState)}</span><em>${d.ground_truth && item.observed_stage ? "recorded stage" : "model forecast"}</em>`;
      };
      graphNodes.forEach((node) => {
        const index = Number(node.dataset.nodeIndex);
        node.addEventListener("mouseenter", () => showNode(index));
        node.addEventListener("focus", () => showNode(index));
      });
      showNode(step);
      const graphScroll = mount.querySelector(".nv-graph-scroll");
      const currentNode = mount.querySelector(".nv-graph-node.current");
      if (graphScroll && currentNode && graphScroll.scrollWidth > graphScroll.clientWidth) {
        const nodeBox = currentNode.getBoundingClientRect();
        const graphBox = graphScroll.getBoundingClientRect();
        graphScroll.scrollLeft = Math.max(0, graphScroll.scrollLeft + nodeBox.left - graphBox.left - graphBox.width * 0.62);
      }
      mount.querySelectorAll("[data-a]").forEach((b) => b.addEventListener("click", () => action(b.dataset.a)));
      mount.querySelectorAll("[data-speed]").forEach((b) => b.addEventListener("click", () => { speed = +b.dataset.speed; if (playing) { stop(); play(); } else render(); }));
      const scrub = mount.querySelector(".nv-replay-scrub");
      scrub.addEventListener("input", () => { stop(); step = +scrub.value; render(); });
      if (onUpdate) onUpdate(cur, step);
    }
    function action(a) {
      if (a === "playpause") playing ? stop() : play();
      else if (a === "fwd") { stop(); step = Math.min(n - 1, step + 1); render(); if (step === n - 1 && onComplete) onComplete(); }
      else if (a === "back") { stop(); step = Math.max(0, step - 1); render(); }
      else if (a === "restart") { stop(); step = 0; if (onReset) onReset(); render(); }
    }
    function play() { playing = true; render(); timer = setInterval(() => { if (step >= n - 1) { stop(); if (onComplete) onComplete(); render(); return; } step++; render(); }, 900 / speed); }
    function stop() { playing = false; if (timer) { clearInterval(timer); timer = null; } }
    render();
  }

  /* ---------------- scenario picker ---------------- */
  async function pickerControls(sel) {
    if (sel.upload_id) {
      return `<span class="nv-badge forecast">uploaded capture</span><span class="nv-badge observed">${esc(sel.host)}</span>
        <a class="nv-btn sec" href="/simulate">New capture</a>`;
    }
    const g = await api.get("/api/gallery").catch(() => ({ campaigns: [] }));
    const camps = g.campaigns.filter((c) => c.hosts.length);
    const hosts = (camps.find((c) => c.campaign === sel.campaign) || camps[0] || { hosts: [] }).hosts;
    return `<select class="nv-select" id="nv-camp" title="Replay scenario">${camps.map((c) => `<option value="${esc(c.campaign)}"${c.campaign === sel.campaign ? " selected" : ""}>${esc(c.label)}</option>`).join("")}</select>
      <select class="nv-select" id="nv-host" title="Host">${hosts.map((hh) => `<option value="${esc(hh)}"${hh === sel.host ? " selected" : ""}>${esc(hh)}</option>`).join("")}</select>`;
  }
  function wirePicker() {
    const camp = document.getElementById("nv-camp"), host = document.getElementById("nv-host");
    if (camp) camp.addEventListener("change", async () => {
      const g = await api.get("/api/gallery"); const c = g.campaigns.find((x) => x.campaign === camp.value);
      store.sel = { campaign: camp.value, host: c.hosts[0], ground_truth: true }; boot();
    });
    if (host) host.addEventListener("change", () => {
      store.sel = { campaign: document.getElementById("nv-camp").value, host: host.value, ground_truth: true }; boot();
    });
  }

  async function currentSelection() {
    let sel = store.sel;
    if (sel && sel.upload_id) {
      try { sel.fc = await api.get(`/api/upload/${sel.upload_id}/forecast?host=${encodeURIComponent(sel.host)}&mc=20`); sel.fc.upload_id = sel.upload_id; return sel; }
      catch { sel = null; }
    }
    if (!sel) {
      const g = await api.get("/api/gallery");
      const c = g.campaigns.find((x) => x.attacked && x.hosts.length) || g.campaigns.find((x) => x.hosts.length);
      if (!c) throw new Error("No replay scenarios available from the backend.");
      sel = { campaign: c.campaign, host: c.hosts[0], ground_truth: true };
    }
    if (!sel.fc) sel.fc = await api.get(`/api/forecast?campaign=${encodeURIComponent(sel.campaign)}&host=${encodeURIComponent(sel.host)}&mc=20`);
    store.sel = { campaign: sel.campaign, host: sel.host, upload_id: sel.upload_id, ground_truth: sel.fc.ground_truth };
    return sel;
  }

  function ctxFromForecast(d) {
    setCtx({ scenario: String(d.scenario.label || "").split("|")[0].trim(), host: d.scenario.host,
      horizon: (d.forecast.slice(-1)[0] || {}).horizon || "+120s",
      mode: d.ground_truth ? "Offline Replay" : "Uploaded capture", data: (d.scenario.dataset || "World Model") });
  }

  /* ---------------- pages ---------------- */
  function forecastNode(d) {
    const focusRisk = d.peak_risk;
    const steps = d.forecast || [];
    // K-step rollout flow: S_t (now) then each forecast horizon
    const flow = `<div class="nv-flow">
      <div class="nv-step now"><div class="hz">S_t · now</div><div class="st">${esc(stageName((d.observed.find(o=>o.t===d.focus_at)||{}).stage || d.forecast[0]?.stage))}</div><div class="rk">${pct(focusRisk)}</div><div class="meta">observed current state</div></div>
      ${steps.map((s, i) => `<span class="nv-arrow">→</span>
        <div class="nv-step ${i === steps.length - 1 ? "focus" : ""}"><div class="hz">S_t+${d.horizon_steps?.[i] ?? i+1} · ${esc(s.horizon)}</div><div class="st">${esc(stageName(s.stage))}</div><div class="rk">${pct(s.risk)}</div><div class="meta">${esc(s.tactic || "no ATT&CK tactic")} · ${esc(s.confidence)}${s.uncertainty != null ? " · ±" + pct(s.uncertainty) : ""}</div></div>`).join("")}
    </div>`;
    return flow;
  }

  function rolloutForWindow(d, row) {
    const selected = row || (d.observed || []).find((o) => o.t === d.focus_at) || (d.observed || [])[0] || {};
    const steps = (d.horizons || []).map((h, i) => {
      const value = selected.horizons?.[h] || (selected.t === d.focus_at ? d.forecast?.[i] : null) || {};
      return {
        horizon: h,
        utc: value.utc || null,
        risk: value.risk,
        stage: value.stage || "UNMAPPED",
        tactic: value.tactic || "",
        confidence: value.confidence || (value.risk >= d.threshold ? "High" : "Low"),
        uncertainty: value.uncertainty,
      };
    });
    return { selected, steps };
  }

  function forecastNodeForWindow(d, row) {
    const rollout = rolloutForWindow(d, row);
    const selected = rollout.selected;
    const steps = rollout.steps;
    const selectedIndex = Math.max(0, (d.observed || []).indexOf(selected));
    const selectedStage = d.ground_truth && selected.observed_stage ? selected.observed_stage : selected.stage;
    const selectedLabel = selected.t === d.focus_at ? "peak-risk focus · recommended" : "user-selected origin";
    return `<div class="nv-flow">
      <div class="nv-step now"><div class="hz">S_t · window ${selectedIndex + 1}</div><div class="st">${esc(stageName(selectedStage))}</div><div class="rk">${pct(selected.risk)}</div><div class="meta">${esc(hhmmss(selected.t))} · ${selectedLabel} · +120s forecast risk</div></div>
      ${steps.map((s, i) => `<span class="nv-arrow">→</span>
        <div class="nv-step ${i === steps.length - 1 ? "focus" : ""}"><div class="hz">S_t+${d.horizon_steps?.[i] ?? i+1} · ${esc(s.horizon)}</div><div class="st">${esc(stageName(s.stage))}</div><div class="rk">${pct(s.risk)}</div><div class="meta">${esc(s.tactic || "no ATT&CK tactic")} · ${esc(s.confidence)}${s.uncertainty != null ? " · ±" + pct(s.uncertainty) : ""}</div></div>`).join("")}
    </div>`;
  }

  function rolloutWindowPicker(d) {
    const selectedAt = d.focus_at || (d.observed?.[0] || {}).t;
    const width = String((d.observed || []).length).length;
    const options = (d.observed || []).map((o, i) => {
      const label = `${String(i + 1).padStart(width, "0")} · ${hhmmss(o.t)} · ${stageName(o.stage)} · +120s ${pct(o.risk)}`;
      return `<option value="${esc(o.t)}"${o.t === selectedAt ? " selected" : ""}>${esc(label)}${o.t === d.focus_at ? " · PEAK-RISK FOCUS" : ""}</option>`;
    }).join("");
    return `<div class="nv-rollout-picker"><label for="nv-rollout-window"><b>Rollout origin window</b><span>Select any observed 30-second window to inspect its forecast.</span></label><select class="nv-select" id="nv-rollout-window" aria-label="Select rollout origin window">${options}</select></div>`;
  }

  function forecastPage(content, d) {
    ctxFromForecast(d);
    const steps = d.forecast || [];
    content.innerHTML =
      `<div id="nv-replay-pending">${card("Replay result", `<p class="nv-note">Peak risk, full progression and lead time will appear when replay reaches the end.</p><div id="nv-current-replay"></div>`)}</div>` +
      section("Live replay", "Streaming forecast â€” step by step",
        "Play the capture forward one 30-second window at a time and watch the forecast rise and alert before the attack lands.",
        `<div id="nv-replay-host"></div>`, "accent") +
      `<div id="nv-deferred" style="display:none">` +
      plainBlock(d.plain_language) +
      card("", `<div class="nv-grid">
        ${metric("Current state", riskBadge(d.peak_risk, d.threshold))}
        ${metric("Peak onset risk", pct(d.peak_risk), { cls: d.peak_risk >= d.threshold ? "alert" : "" })}
        ${metric("Alert threshold", d.threshold)}
        ${metric("Alert level", `<small>${esc((d.alert_level || "none").toUpperCase())}</small>`, { cls: d.alert_level && d.alert_level !== "none" ? "alert" : "" })}
      </div>`) +
      section("Live replay", "Streaming forecast — step by step",
        "Play the capture forward one 30-second window at a time and watch the forecast rise and alert before the attack lands.",
        `<div id="nv-replay-host"></div>`, "accent") +
      section("K-step rollout", "Current state → future states",
        "The world model rolls the current network state forward one window at a time and scores each projected future state for onset risk.",
        rolloutWindowPicker(d) + `<div id="nv-rollout-content"></div>` +
        caveat("Risk is a per-window onset score from the decoder's predicted future state — not a calibrated probability. Predicted stage is a model output, not a confirmed action.")) +
      section("Risk trajectory", "Forecast risk over the observed timeline",
        "Each point is the model's onset-risk forecast for that 30-second window across the replayed capture.",
        riskTimeline(d) +
        `<div class="nv-tablewrap" style="margin-top:14px"><table class="nv"><thead><tr><th>Horizon</th><th class="num">Forecast risk</th><th>Predicted stage</th><th>ATT&CK tactic</th><th>Confidence</th>${steps.some(s=>s.uncertainty!=null)?'<th class="num">± band</th>':''}</tr></thead>
        <tbody>${steps.map((s) => `<tr><td>${esc(s.horizon)}</td><td class="num">${pct(s.risk)}</td><td>${stageBadge(s.stage)}</td><td>${esc(s.tactic || "—")}</td><td>${esc(s.confidence)}</td>${s.uncertainty!=null?`<td class="num">±${pct(s.uncertainty)}</td>`:''}</tr>`).join("")}</tbody></table></div>`) +
      card("", `<div class="nv-cta-row"><a class="nv-btn sec" href="/attack">ATT&CK trajectory</a><a class="nv-btn sec" href="/investigate">Why this forecast</a><a class="nv-btn sec" href="/network">Network evidence</a></div>`) +
      decisionLog(d) +
      `<div id="nv-decision-support"></div></div>`;
    const replayKey = `nv_replay_complete:${d.upload_id || d.scenario?.campaign || d.scenario?.dataset || "capture"}:${d.scenario?.host || "host"}`;
    const updateCurrent = (cur, step) => { const el = document.getElementById("nv-current-replay"); if (el) el.innerHTML = `<div class="nv-current-replay"><span class="nv-mono">window ${step + 1}/${(d.observed || []).length}</span>${riskBadge(cur.risk, d.threshold)}${stageBadge(cur.stage)}<span class="nv-mono">${hhmmss(cur.t)}</span></div>`; };
    const finish = () => { const pending = document.getElementById("nv-replay-pending"); if (pending) pending.style.display = "none"; const deferred = document.getElementById("nv-deferred"); if (deferred) deferred.style.display = "block"; try { sessionStorage.setItem(replayKey, "1"); } catch {} };
    const resetReplay = () => { try { sessionStorage.removeItem(replayKey); } catch {} const pending = document.getElementById("nv-replay-pending"); if (pending) pending.style.display = "block"; const deferred = document.getElementById("nv-deferred"); if (deferred) deferred.style.display = "none"; };
    const duplicateReplay = document.querySelector("#nv-deferred #nv-replay-host");
    if (duplicateReplay && duplicateReplay.closest(".nv-section")) duplicateReplay.closest(".nv-section").remove();
    const wasComplete = sessionStorage.getItem(replayKey) === "1";
    if (wasComplete) finish();
    replayPlayer(document.getElementById("nv-replay-host"), d, updateCurrent, finish, wasComplete ? (d.observed || []).length - 1 : 0, resetReplay);
    const rolloutSelect = document.getElementById("nv-rollout-window");
    const rolloutContent = document.getElementById("nv-rollout-content");
    const rolloutKey = `nv_rollout_window:${d.upload_id || d.scenario?.campaign || d.scenario?.dataset || "capture"}:${d.scenario?.host || "host"}`;
    let savedRolloutAt = null;
    try { savedRolloutAt = sessionStorage.getItem(rolloutKey); } catch {}
    const renderRollout = (at) => {
      const row = (d.observed || []).find((o) => o.t === at) || (d.observed || []).find((o) => o.t === d.focus_at) || d.observed?.[0];
      if (!row || !rolloutContent) return;
      if (rolloutSelect && rolloutSelect.value !== row.t) rolloutSelect.value = row.t;
      rolloutContent.innerHTML = forecastNodeForWindow(d, row) + `<div style="margin-top:16px">${projectionChart(row.risk, rolloutForWindow(d, row).steps, d.threshold)}</div>`;
      try { sessionStorage.setItem(rolloutKey, row.t); } catch {}
    };
    if (rolloutSelect) {
      rolloutSelect.addEventListener("change", () => renderRollout(rolloutSelect.value));
      renderRollout(savedRolloutAt || rolloutSelect.value || d.focus_at);
    }
    if (d.ground_truth && d.scenario && d.scenario.campaign) {
      api.get(decisionSupportUrl(d))
        .then((ds) => { const el = document.getElementById("nv-decision-support"); if (el) el.innerHTML = defenderPanel(ds); })
        .catch(() => {});
    }
  }

  function decisionSupportUrl(d) {
    const host = encodeURIComponent(d.scenario?.host || "");
    if (d.upload_id) return `/api/decision-support?campaign=upload&upload_id=${encodeURIComponent(d.upload_id)}&host=${host}`;
    return `/api/decision-support?campaign=${encodeURIComponent(d.scenario?.campaign || "")}&host=${host}`;
  }

  function decisionLog(d) {
    const events = d.decision_log || d.alert_events || [];
    if (!events.length) {
      return section("Decision log", "Prediction decisions", "Every sustained alert decision is recorded here during replay.", `<div class="nv-empty">No sustained prediction alert was raised for this capture.</div>`);
    }
    const rows = events.map((event, i) => {
      const action = event.action || {};
      const lead = event.lead_time_s == null ? "n/a" : `${event.lead_time_s}s`;
      const status = String(event.status || "prediction").replace(/_/g, " ");
      return `<tr><td class="num">${i + 1}</td><td class="nv-mono">${hhmmss(event.alert_at || event.window_at)}</td><td>${stageBadge(event.stage, "critical")}</td><td class="num">${pct(event.risk)}</td><td>${esc(status)}</td><td>${esc(lead)}</td><td>${esc(action.summary || "Review and investigate the alert.")}</td></tr>`;
    }).join("");
    return section("Decision log", "Prediction decisions raised during replay", "Each row is a sustained model alert, with the stage, risk, timing and advisory response available at that decision point.",
      `<div class="nv-tablewrap"><table class="nv"><thead><tr><th>#</th><th>Alert time</th><th>Predicted stage</th><th class="num">Risk</th><th>Decision</th><th>Lead time</th><th>Advisory action</th></tr></thead><tbody>${rows}</tbody></table></div><p class="nv-caveat">Decision support is advisory only. It does not prove compromise or execute a network action.</p>`);
  }

  // Shared stage-mapped defender decision-support panel (advisory, human-approved).
  function defenderPanel(ds) {
    const pb = ds.playbook || {};
    const stageCards = (ds.actions_by_stage || []).map((a) => card(stageName(a.stage), `<span class="nv-badge elevated">${esc(a.status || "guidance")}</span> <span class="nv-mono">${esc(a.tactic || "")}</span><p>${esc(a.summary || "")}</p><ul class="nv-actions">${(a.actions || []).map((x) => `<li>${esc(x)}</li>`).join("")}</ul>`)).join("");
    return section("Defender decision support", "Recommended defensive action",
      "Advisory only — every action requires human approval; nothing is executed on the network.",
      card("", `<div class="nv-grid">
          ${metric("Alert level", `<small>${esc((ds.alert_level || "none").toUpperCase())}</small>`, { cls: ds.alert_level && ds.alert_level !== "none" ? "alert" : "" })}
          ${metric("Predicted stage", `<small>${esc(stageName(ds.predicted_stage || "BENIGN"))}</small>`, { sub: ds.stage_tactic || "" })}
        </div>
        <p class="nv-note" style="margin-top:10px"><b>${esc(pb.summary || ds.recommended_action || "")}</b></p>
        ${(pb.actions || []).length ? `<ul class="nv-actions">${pb.actions.map((a) => `<li>${esc(a)}</li>`).join("")}</ul>` : ""}
        ${(pb.mitre_mitigations || []).length ? `<div style="margin-top:8px">${pb.mitre_mitigations.map((m) => `<span class="nv-chip">${esc(m)}</span>`).join("")}</div>` : ""}
        ${stageCards ? `<div class="nv-stage-actions">${stageCards}</div>` : ""}
        <p class="nv-caveat">Human approval required · automated response not taken. ${esc((ds.limitations || [])[0] || "")}</p>`));
  }

  // MITRE kill-chain stage graph, highlighting only the stages the model actually predicts.
  function killChainMap(d) {
    const KILL = [
      ["RECONNAISSANCE", "Reconnaissance", "TA0043"], ["INITIAL ACCESS", "Initial Access", "TA0001"],
      ["LATERAL MOVEMENT", "Lateral Movement", "TA0008"], ["COMMAND AND CONTROL", "Command & Control", "TA0011"],
      ["EXFILTRATION", "Exfiltration", "TA0010"], ["IMPACT", "Impact", "TA0040"],
    ];
    const seen = new Set([...(d.observed || []).map((o) => String((d.ground_truth && o.observed_stage) || o.stage).toUpperCase()),
                          ...(d.forecast || []).map((s) => String(s.stage).toUpperCase())]);
    const focusRow = (d.observed || []).find((o) => o.t === d.focus_at);
    const focusStage = String((focusRow && focusRow.stage) || (d.forecast && (d.forecast.slice(-1)[0] || {}).stage) || "").toUpperCase();
    const nodes = KILL.map(([key, label, tactic]) => {
      const predicted = seen.has(key), focus = key === focusStage;
      const cls = focus ? "focus" : predicted ? "predicted" : "idle";
      return `<div class="nv-kc-node ${cls}" style="--nv-stage-color:${replayStageColor(key)}"><div class="nv-kc-tactic">${tactic}</div><div class="nv-kc-label">${label}</div>
        <div class="nv-kc-state">${focus ? "current focus" : predicted ? "predicted" : "not observed"}</div></div>`;
    }).join(`<span class="nv-kc-arrow">→</span>`);
    const stageLegend = REPLAY_STAGE_META.filter(([key]) => key !== "BENIGN").map(([key, label, color]) => `<span class="nv-graph-legend-item"><i style="background:${color}"></i>${esc(label)}</span>`).join("");
    return `<div class="nv-kc">${nodes}</div>
      <div class="nv-legend"><span class="l-risk">predicted stage</span><span class="l-thr">current focus</span><span class="l-obs">not observed in this capture</span></div>
      <div class="nv-graph-legend nv-kc-stage-legend"><b>Stage colors:</b>${stageLegend}</div>
      <p class="nv-caveat"><b>What predicted progression means:</b> each colored stage is the model's best forecast of the host's future attack behavior for a window. Read the highlighted node as the current focus and the other marked nodes as stages observed or forecast somewhere in this capture. It is a warning signal, not confirmation that an attacker completed that technique.</p>
      <p class="nv-caveat">Stages can repeat, regress or be skipped. Exfiltration does not occur in the training data, so it is never predicted here.</p>`;
  }

  function attackPage(content, d) {
    ctxFromForecast(d);
    const thr = d.threshold, focusAt = d.focus_at;
    const chips = (d.observed || []).map((o) => {
      const S = String(o.stage).toUpperCase();
      let kind = "observed";
      if (o.t === focusAt) kind = "forecast"; else if (o.risk >= thr) kind = "critical"; else if (o.risk >= thr * 0.6) kind = "elevated";
      const lbl = o.t === focusAt ? "CURRENT FOCUS" : stageName(S);
      return `<span class="nv-badge ${kind}" title="${hhmmss(o.t)} · risk ${pct(o.risk)}">${esc(lbl)} · ${hhmmss(o.t).slice(0,5)}</span>`;
    }).join(" ");
    const progressionGraph = temporalGraphScrollable(d, (d.observed || []).length - 1);
    content.innerHTML =
      plainBlock(d.plain_language) +
      section("MITRE kill-chain map", "Predicted attack-stage progression", "Where the model's forecast places this host on the ATT&CK kill chain.",
        killChainMap(d), "accent") +
      card("Legend", `<div style="display:flex;gap:8px;flex-wrap:wrap">
        <span class="nv-badge observed">observed · nominal</span>
        <span class="nv-badge elevated">elevated</span>
        <span class="nv-badge critical">over threshold</span>
        <span class="nv-badge forecast">current focus window</span></div>`) +
      section("Recorded progression", d.ground_truth ? "Recorded ATT&CK stage per observed window" : "Predicted ATT&CK stage per observed window",
        d.ground_truth ? "This labelled replay shows the verified stage mapping; forecast risk remains model output." : "Each window's stage is the model's predicted future ATT&CK stage, not proof that the technique already occurred.",
        progressionGraph +
        `<div class="nv-progression-rail">${(d.progression || []).map((p) => `<div class="nv-progression-item"><b>${esc(stageName(p.stage))}</b><span>${hhmmss(p.start)}–${hhmmss(p.end)}</span><span>${pct(p.max_risk)}</span></div>`).join("")}</div>` +
        caveat("Stages can repeat, regress or be unmapped. These are predictions of a forecasted future state, not confirmed attacker actions, and network traffic alone does not prove host compromise.")) +
      section("K-step stage trajectory", "From the peak-risk window", "",
        `<div class="nv-tablewrap"><table class="nv"><thead><tr><th>Horizon</th><th>Predicted stage</th><th>ATT&CK tactic</th><th class="num">Forecast risk</th><th>Confidence</th></tr></thead>
        <tbody>${(d.forecast||[]).map((s) => `<tr><td>${esc(s.horizon)}</td><td>${stageBadge(s.stage)}</td><td>${esc(s.tactic || "—")}</td><td class="num">${pct(s.risk)}</td><td>${esc(s.confidence)}</td></tr>`).join("")}</tbody></table></div>`) +
      card("", `<div class="nv-cta-row"><a class="nv-btn sec" href="/forecast">Back to Forecast</a><a class="nv-btn sec" href="/investigate">Why this forecast</a></div>`) +
      `<div id="nv-ds-attack"></div>`;
    const graphDetail = content.querySelector("[data-graph-detail]");
    content.querySelectorAll("[data-node-index]").forEach((node) => {
      const index = Number(node.dataset.nodeIndex), item = (d.observed || [])[index];
      const show = () => {
        if (!graphDetail || !item) return;
        const itemStage = d.ground_truth && item.observed_stage ? item.observed_stage : item.stage;
        const prediction = (d.alert_events || []).find((event) => event.alert_at && Date.parse(event.alert_at) === Date.parse(item.t));
        const predictionText = prediction ? `<strong class="nv-graph-prediction">PREDICTION RAISED · warning lead ${prediction.lead_time_s == null ? "n/a" : `${prediction.lead_time_s}s`}</strong>` : "";
        graphDetail.innerHTML = `<b>${esc(hhmmss(item.t))}</b><span>${esc(stageName(itemStage))}</span><span>risk ${pct(item.risk)}</span><span>${d.ground_truth && item.observed_stage ? "recorded stage" : "model forecast"}</span>${predictionText}`;
      };
      node.addEventListener("mouseenter", show);
      node.addEventListener("focus", show);
    });
    const lastNode = content.querySelector(".nv-graph-node.current");
    if (lastNode && graphDetail) lastNode.dispatchEvent(new Event("focus"));
    const progressionScroll = content.querySelector(".nv-graph-scroll");
    if (progressionScroll) progressionScroll.scrollLeft = progressionScroll.scrollWidth;
    if (d.ground_truth && d.scenario && d.scenario.campaign) {
      api.get(decisionSupportUrl(d))
        .then((ds) => { const el = document.getElementById("nv-ds-attack"); if (el) el.innerHTML = defenderPanel(ds); })
        .catch(() => {});
    }
  }

  async function investigatePage(content, sel) {
    const d = sel.fc; ctxFromForecast(d);
    const win = d.focus_at || d.peak_at || (d.observed.slice(-1)[0] || {}).t;
    const path = sel.upload_id
      ? `/api/upload/${sel.upload_id}/explain?host=${encodeURIComponent(sel.host)}&window=${encodeURIComponent(win)}`
      : `/api/explain?campaign=${encodeURIComponent(sel.campaign)}&host=${encodeURIComponent(sel.host)}&window=${encodeURIComponent(win)}`;
    let ex;
    try { ex = await api.get(path); } catch (e) { content.innerHTML = `<div class="nv-err">Explanation unavailable: ${esc(e.message)}</div>`; return; }
    const maxc = Math.max(...ex.shap.map((s) => Math.abs(s.contribution)), 1e-6);
    const maxa = Math.max(...ex.attention.weights, 1e-6);
    const attnFlat = ex.attention.weights.every((w) => w === 0);
    const topDriver = ex.drivers[0];
    // evidence chain (observed behaviour -> feature change -> contribution -> attention -> forecast)
    const chain = `<div class="nv-chain">
      <span class="node">observed behaviour</span><span class="ar">→</span>
      <span class="node">feature change</span><span class="ar">→</span>
      <span class="node">model contribution (SHAP)</span><span class="ar">→</span>
      <span class="node">temporal weight</span><span class="ar">→</span>
      <span class="node">forecast risk ${pct(d.peak_risk)}</span></div>`;
    content.innerHTML =
      section("Evidence chain", "Why did the model forecast this?",
        `Traced backward from the forecast for window ${hhmmss(win)} UTC.`,
        chain + `<p class="nv-note">${esc(ex.sentence)}</p>`) +
      section("Observed behaviour → feature change", "Behavioural drivers vs this host's normal", "",
        `<div class="nv-evidence">${ex.drivers.map((dr) => {
          const up = dr.observed > dr.reference;
          return `<div class="nv-erow"><div class="lbl">${esc(dr.feature.replace(/_/g," "))} <span class="nv-muted" style="font-size:11px">(${dr.kind})</span></div>
            <div class="chg" style="color:${up ? "#dc2626" : "#0d9488"}">${up ? "▲" : "▼"} ${up ? "increased" : "decreased"}</div>
            <div class="val">obs ${(+dr.observed).toLocaleString(undefined,{maximumFractionDigits:2})} · normal ~${(+dr.reference).toLocaleString(undefined,{maximumFractionDigits:2})}</div></div>`;
        }).join("")}</div>`) +
      section("Model contribution", "SHAP attribution over the predicted future state", "",
        `<div class="nv-tablewrap"><table class="nv"><thead><tr><th>Feature</th><th>Kind</th><th class="num">Value</th><th style="width:38%">Contribution to forecast risk</th></tr></thead><tbody>
        ${ex.shap.map((s) => `<tr><td>${esc(s.label)} <span class="nv-muted">(${esc(s.feature)})</span></td><td>${esc(s.kind)}</td><td class="num">${(+s.value).toLocaleString(undefined,{maximumFractionDigits:2})}</td>
          <td><div class="nv-bar ${s.contribution>=0?"pos":"neg"}"><i style="width:${(Math.abs(s.contribution)/maxc*100).toFixed(0)}%"></i></div></td></tr>`).join("")}
        </tbody></table></div><p class="nv-note"><span style="color:#dc2626">red</span> pushes onset risk up, <span style="color:#0d9488">teal</span> pushes it down.</p>` +
        caveat("Attribution indicates model contribution, not causal proof.")) +
      section("Temporal weight", "Top attention windows in the selected history", "Ranked highest-first; these are the model's ten available history inputs for this forecast.",
        attnFlat ? `<div class="nv-empty">Attention unavailable for this window.</div>`
        : `<div class="nv-tablewrap"><table class="nv"><thead><tr><th>History window</th><th style="width:60%">Attention weight</th></tr></thead><tbody>
        ${ex.attention.windows.map((w, i) => `<tr><td>${hhmmss(w)}</td><td><div class="nv-bar blue"><i style="width:${(ex.attention.weights[i]/maxa*100).toFixed(0)}%"></i></div></td></tr>`).join("")}
        </tbody></table></div>`);
  }

  function endpointGraph(g) {
    const allEdges = (g.edges || []).slice().sort((a, b) => (b.flow_count || 0) - (a.flow_count || 0));
    if (!allEdges.length) return `<div class="nv-empty">No endpoint relationships are available for this host.</div>`;
    const edges = allEdges.slice(0, 80);
    const sourceIds = [...new Set(edges.map((edge) => String(edge.source)))];
    const targetIds = [...new Set(edges.map((edge) => String(edge.target)))];
    const cols = Math.min(4, Math.max(1, Math.ceil(targetIds.length / 20)));
    const rows = Math.ceil(targetIds.length / cols);
    const W = Math.max(1080, 260 + cols * 230), H = Math.max(390, 100 + rows * 31);
    const sourceX = 120, targetStartX = 330;
    const sourceY = (id) => 70 + sourceIds.indexOf(id) * ((H - 120) / Math.max(sourceIds.length, 1));
    const targetPos = new Map(targetIds.map((id, i) => [id, { x: targetStartX + (i % cols) * 230, y: 70 + Math.floor(i / cols) * 31 }]));
    const maxFlows = Math.max(...edges.map((edge) => edge.flow_count || 1), 1);
    const edgeLines = edges.map((edge) => {
      const source = String(edge.source), target = String(edge.target), pos = targetPos.get(target);
      const flows = edge.flow_count || 1;
      return `<line x1="${sourceX + 58}" y1="${sourceY(source)}" x2="${pos.x - 58}" y2="${pos.y}" stroke="#94a3b8" stroke-width="${(1 + flows / maxFlows * 4).toFixed(1)}" opacity="0.42"><title>${esc(source)} → ${esc(target)} · ${num(flows)} flow${flows === 1 ? "" : "s"} · ${hhmmss(edge.first_seen)}–${hhmmss(edge.last_seen)}</title></line>`;
    }).join("");
    const sourceNodes = sourceIds.map((id) => `<g class="nv-endpoint-node source"><circle cx="${sourceX}" cy="${sourceY(id)}" r="13" fill="#0284c7" stroke="#0c4a6e" stroke-width="2"><title>Source host ${esc(id)}</title></circle><text x="${sourceX - 20}" y="${sourceY(id) + 29}" text-anchor="middle" font-size="11" fill="#0c4a6e" font-family="IBM Plex Mono">${esc(id)}</text></g>`).join("");
    const targetNodes = targetIds.map((id) => { const pos = targetPos.get(id); return `<g class="nv-endpoint-node destination"><circle cx="${pos.x}" cy="${pos.y}" r="10" fill="#f97316" stroke="#9a3412" stroke-width="1.5"><title>Destination ${esc(id)}</title></circle><text x="${pos.x + 16}" y="${pos.y + 4}" font-size="10" fill="#475569" font-family="IBM Plex Mono">${esc(id)}</text></g>`; }).join("");
    return `<div class="nv-endpoint-graph">
      <div class="nv-endpoint-legend"><span><i class="source"></i>source host</span><span><i class="destination"></i>destination</span><span><i class="edge"></i>edge width = flow count</span></div>
      <div class="nv-endpoint-scroll"><svg viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" role="img" aria-label="Source to destination network graph"><text x="${sourceX}" y="28" text-anchor="middle" font-size="11" fill="#0c4a6e" font-family="IBM Plex Mono">SOURCE</text><text x="${targetStartX}" y="28" font-size="11" fill="#9a3412" font-family="IBM Plex Mono">DESTINATIONS</text>${edgeLines}${sourceNodes}${targetNodes}</svg></div>
      <p class="nv-note">Showing the top ${num(edges.length)} relationships by flow count out of ${num(allEdges.length)} total edges. Hover a node or edge for endpoint and timing details.</p>
    </div>`;
  }

  function networkPage(content, d) {
    ctxFromForecast(d);
    const obs = d.observed || [];
    const last = obs[obs.length - 1] || {};
    // "what changed": last window vs median of the earlier windows
    const med = (arr) => { const s = arr.slice().sort((a, b) => a - b); return s.length ? s[Math.floor(s.length / 2)] : 0; };
    const base = {
      flows: med(obs.slice(0, -1).map((o) => o.flows)), ports: med(obs.slice(0, -1).map((o) => o.distinctPorts)),
      ent: med(obs.slice(0, -1).map((o) => o.portEntropy)), failed: med(obs.slice(0, -1).map((o) => o.failedConns)),
      syn: med(obs.slice(0, -1).map((o) => o.synCount)),
    };
    const delta = (now, b, label, unit) => {
      const d0 = now - b, up = d0 > 0;
      const cls = Math.abs(d0) < 1e-9 ? "" : (up ? "hot" : "");
      return `<span class="nv-chip ${cls}">${esc(label)}: ${(+now).toLocaleString(undefined,{maximumFractionDigits:2})}${unit||""} <span class="nv-muted">(${up?"+":""}${(d0).toLocaleString(undefined,{maximumFractionDigits:2})} vs baseline)</span></span>`;
    };
    content.innerHTML =
      card("Current network state (latest window)", `<div class="nv-grid">
        ${metric("Flows / 30 s", num(last.flows))}
        ${metric("Distinct dst ports", num(last.distinctPorts))}
        ${metric("Port entropy", last.portEntropy ?? "—")}
        ${metric("Failed-conn ratio", last.failedConns ?? "—")}
      </div>`) +
      section("What changed", "Latest window vs earlier-window baseline", "Computed from observed telemetry, not from labels.",
        `<div style="display:flex;flex-wrap:wrap;gap:6px">
          ${delta(last.flows, base.flows, "flows")}
          ${delta(last.distinctPorts, base.ports, "dst ports")}
          ${delta(last.portEntropy, base.ent, "port entropy")}
          ${delta(last.synCount, base.syn, "SYN")}
          ${delta(last.failedConns, base.failed, "failed conn")}
        </div>`) +
      card("How to read the network evidence", `<p class="nv-note" style="margin:0">Each point represents one 30-second observed window. The charts show traffic behaviour that supports the model forecast; they do not independently prove compromise. Look for sustained changes, compare the latest point with the baseline, then use Forecast and Investigate to see how those changes affected risk.</p>`) +
      section("Communication & port activity", "Traffic and destination-port fan-out over time", "Each point is one 30-second observed window. Hover points for exact values; compare the latest point with the baseline above.",
        `<div class="nv-network-charts">
          ${card("Traffic volume (flows / 30 s)", `<p class="nv-chart-explain">How many flow records were observed in each 30-second window. Sudden bursts can indicate automation, scanning, or a large transfer.</p>${networkSpark(obs.map((o) => o.flows), "#0284c7", obs.map((o) => hhmmss(o.t)), "flows")}`)}
          ${card("Destination-port fan-out", `<p class="nv-chart-explain">The number of distinct destination ports contacted. A rising fan-out is a common reconnaissance or port-scan signal.</p>${networkSpark(obs.map((o) => o.distinctPorts), "#b45309", obs.map((o) => hhmmss(o.t)), "ports")}`)}
          ${card("Port entropy", `<p class="nv-chart-explain">How spread out the traffic is across destination ports. Higher entropy means activity is distributed across more ports rather than concentrated on one service.</p>${networkSpark(obs.map((o) => o.portEntropy), "#0d9488", obs.map((o) => hhmmss(o.t)))}`)}
          ${card("Failed-connection ratio", `<p class="nv-chart-explain">The share of connection attempts that failed. A high or rising ratio can support scan, brute-force, or unreachable-service hypotheses.</p>${networkSpark(obs.map((o) => o.failedConns), "#dc2626", obs.map((o) => hhmmss(o.t)), "ratio")}`)}
        </div>`) +
      section("Raw telemetry", "Per-window features that drive the forecast", "",
        `<div class="nv-tablewrap"><table class="nv"><thead><tr><th>Window</th><th class="num">Flows</th><th class="num">Pkts/s</th><th class="num">SYN</th><th class="num">Dst ports</th><th class="num">Port entropy</th><th class="num">Unique dsts</th><th class="num">Failed</th><th class="num">Mean IAT</th></tr></thead>
        <tbody>${obs.slice().reverse().map((o) => `<tr><td>${hhmmss(o.t)}</td><td class="num">${num(o.flows)}</td><td class="num">${o.pktRate}</td><td class="num">${o.synCount}</td><td class="num">${o.distinctPorts}</td><td class="num">${o.portEntropy}</td><td class="num">${o.uniqueDsts}</td><td class="num">${o.failedConns}</td><td class="num">${o.iat}</td></tr>`).join("")}</tbody></table></div>`);
    if (d.scenario && d.scenario.campaign) {
      const graphQuery = d.upload_id
        ? `/api/network-graph?campaign=upload&upload_id=${encodeURIComponent(d.upload_id)}&host=${encodeURIComponent(d.scenario.host || "")}`
        : `/api/network-graph?campaign=${encodeURIComponent(d.scenario.campaign)}&host=${encodeURIComponent(d.scenario.host || "")}`;
      api.get(graphQuery)
        .then((g) => { const block = g.available
          ? `<div class="nv-grid"><div><b>Nodes</b><div class="nv-big">${num(g.nodes.length)}</div></div><div><b>Edges</b><div class="nv-big">${num(g.edges.length)}</div></div></div>${endpointGraph(g)}
             <details class="nv-edge-details"><summary>Show raw edge list</summary><div class="nv-tablewrap" style="margin-top:12px"><table class="nv"><thead><tr><th>Source</th><th>Destination</th><th class="num">Flows</th><th>First seen</th><th>Last seen</th></tr></thead><tbody>${g.edges.slice(0, 100).map((edge) => `<tr><td class="nv-mono">${esc(edge.source)}</td><td class="nv-mono">${esc(edge.target)}</td><td class="num">${num(edge.flow_count)}</td><td>${hhmmss(edge.first_seen)}</td><td>${hhmmss(edge.last_seen)}</td></tr>`).join("")}</tbody></table></div>${g.edges.length > 100 ? `<p class="nv-note">Showing the first 100 of ${num(g.edges.length)} unique relationships.</p>` : ""}</details>`
          : `<div class="nv-empty">Graph edges are unavailable because the loaded state cache does not retain source/destination identities. Phase 8 requires endpoint-aware telemetry.</div>`;
          content.insertAdjacentHTML("beforeend", section("Phase 8 — temporal graph coverage", "Temporal endpoint graph", "Real source-to-destination relationships from the retained flow records.", block)); })
        .catch((error) => { content.insertAdjacentHTML("beforeend", section("Phase 8 — temporal graph coverage", "Temporal endpoint graph", "The graph request failed before endpoint data could be displayed.", `<div class="nv-err">Graph unavailable: ${esc(error.message || "API request failed")}. Restart the backend and re-upload the capture so its flow endpoints are retained.</div>`)); });
    }
  }

  async function homePage(content) {
    let sel; try { sel = await currentSelection(); } catch (e) { content.innerHTML = `<div class="nv-err">${esc(e.message)}</div>`; return; }
    const d = sel.fc; ctxFromForecast(d);
    // top-3 behavioural drivers (real, from explain on the focus window)
    let drivers = "";
    try {
      const win = d.focus_at || d.peak_at;
      const ex = await api.get(sel.upload_id
        ? `/api/upload/${sel.upload_id}/explain?host=${encodeURIComponent(sel.host)}&window=${encodeURIComponent(win)}`
        : `/api/explain?campaign=${encodeURIComponent(sel.campaign)}&host=${encodeURIComponent(sel.host)}&window=${encodeURIComponent(win)}`);
      drivers = section("Behavioural attribution", "Why is the forecast at this level?", "Top behavioural changes contributing to the forecast.",
        `<div class="nv-evidence">${ex.drivers.slice(0, 3).map((dr, i) => {
          const up = dr.observed > dr.reference;
          return `<div class="nv-erow"><div class="lbl"><span class="nv-mono nv-muted">0${i + 1}</span> &nbsp;${esc(dr.feature.replace(/_/g," "))}</div>
            <div class="chg" style="color:${up?"#dc2626":"#0d9488"}">${up?"▲ increased":"▼ decreased"}</div>
            <div class="val">obs ${(+dr.observed).toLocaleString(undefined,{maximumFractionDigits:2})} · normal ~${(+dr.reference).toLocaleString(undefined,{maximumFractionDigits:2})}</div></div>`;
        }).join("")}</div><div class="nv-cta-row"><a class="nv-btn sec" href="/investigate">Investigate supporting evidence →</a></div>`);
    } catch { drivers = ""; }
    content.innerHTML =
      card("", `<div class="nv-grid">
        ${metric("Current state", riskBadge(d.peak_risk, d.threshold))}
        ${metric("Active scenario", `<small>${esc(d.scenario.label.split("|")[0].trim())}</small>`, { sub: d.scenario.host })}
        ${metric("Peak onset risk", pct(d.peak_risk), { cls: d.peak_risk >= d.threshold ? "alert" : "" })}
        ${metric(d.ground_truth ? "Warning lead time" : "Mode", `<small>${esc(leadLabel(d))}</small>`)}
      </div>`) +
      plainBlock(d.plain_language) +
      section("Future forecast", "What happens next?", "Observed forecast-risk timeline with the alert threshold and any recorded attack windows.",
        riskTimeline(d) +
        `<div style="margin-top:14px" class="nv-flow">${forecastNode(d)}</div>`) +
      drivers +
      card("Explore", `<p class="nv-note" style="margin-top:0">Every page below is driven by this same capture — no fixture data.</p>
        <div class="nv-cta-row"><a class="nv-btn" href="/forecast">View forecast</a><a class="nv-btn sec" href="/attack">ATT&CK</a>
        <a class="nv-btn sec" href="/network">Network</a><a class="nv-btn sec" href="/validate">Validate</a>
        <a class="nv-btn sec" href="/model">Model</a><a class="nv-btn sec" href="/simulate">Run a capture</a></div>`);
  }

  async function simulatePage(content) {
    setCtx({ scenario: "Upload / replay", host: "—", horizon: "+120s", mode: "Ingest", data: "User capture" });
    const stepCard = (n, t, s, active) => `<div class="nv-step ${active ? "focus" : ""}" style="flex:1 1 130px"><div class="hz">${n}</div><div class="st" style="font-size:12px">${esc(t)}</div><div class="meta">${esc(s)}</div></div>`;
    content.innerHTML =
      section("Run a forecast simulation", "Select a capture and watch the world model project what happens next", "",
        `<div class="nv-flow" style="margin-bottom:16px">
          ${stepCard("01", "Select traffic", "CSV / PCAP or replay", true)}
          <span class="nv-arrow">→</span>${stepCard("02", "Replay / ingest", "clean + window")}
          <span class="nv-arrow">→</span>${stepCard("03", "Build state S_t", "per-host 30 s windows")}
          <span class="nv-arrow">→</span>${stepCard("04", "Ready", "≥10 consecutive windows")}
          <span class="nv-arrow">→</span>${stepCard("05", "Run forecast", "K-step rollout")}
        </div>
        <div class="nv-grid two">
          ${card("Option A — Upload a capture", `<p class="nv-note" style="margin-top:0">CICFlowMeter CSV or a PCAP/PCAPNG. Cleaned and windowed locally — nothing leaves this machine.</p>
            <div class="nv-controls" style="margin-top:10px"><input type="file" class="nv-file" id="nvFile" accept=".csv,.pcap,.pcapng"><button class="nv-btn lg" id="nvRun">Run forecast →</button></div>
            <div id="nvStages" style="margin-top:14px"></div>`)}
          ${card("Option B — Replay a labelled scenario", `<p class="nv-note" style="margin-top:0">Use a CSE-CIC / CTU-13 replay capture with ground-truth labels, then explore it across every page.</p>
            <div class="nv-cta-row"><a class="nv-btn" href="/forecast">Open forecast on default scenario →</a></div>`)}
        </div>`) +
      `<div id="nvResult"></div>`;
    const fileEl = content.querySelector("#nvFile"), runEl = content.querySelector("#nvRun");
    const stagesEl = content.querySelector("#nvStages"), resultEl = content.querySelector("#nvResult");
    runEl.addEventListener("click", async () => {
      if (!fileEl.files.length) { stagesEl.innerHTML = `<p class="nv-err">Choose a CSV or PCAP file first.</p>`; return; }
      runEl.disabled = true; resultEl.innerHTML = ""; stagesEl.innerHTML = `<div class="nv-stage"><span class="nv-dot run"></span>Processing capture…</div>`;
      try {
        const res = await api.upload(fileEl.files[0]);
        stagesEl.innerHTML = "";
        for (const s of res.stages) {
          const row = h(`<div class="nv-stage"><span class="nv-dot run"></span><div><b>${esc(s.name)}</b> <span class="nv-muted">— ${esc(s.detail)}</span></div></div>`);
          stagesEl.appendChild(row); await new Promise((r) => setTimeout(r, 220));
          row.querySelector(".nv-dot").classList.replace("run", "done");
        }
        const host = res.hosts[0];
        const fc = await api.get(`/api/upload/${res.upload_id}/forecast?host=${encodeURIComponent(host)}&mc=20`);
        store.sel = { campaign: "upload", host, upload_id: res.upload_id, ground_truth: Boolean(fc.ground_truth) };
        const rb = h(`<div id="nv-content"></div>`); resultEl.appendChild(rb);
        forecastPage(rb, { ...fc, upload_id: res.upload_id, scenario: fc.scenario || { host, label: "Uploaded capture" } });
        resultEl.insertBefore(h(`<p class="nv-note">This capture now drives <a href="/forecast">Forecast</a>, <a href="/network">Network</a>, <a href="/attack">ATT&CK</a> and <a href="/investigate">Investigate</a>.</p>`), rb);
      } catch (e) { stagesEl.innerHTML = `<p class="nv-err">Upload failed: ${esc(e.message)}</p>`; }
      finally { runEl.disabled = false; }
    });
  }

  async function validatePage(content) {
    setCtx({ scenario: "Held-out test split", host: "—", horizon: "+120s", mode: "Benchmark", data: "Evaluation" });
    const b = await api.get("/api/benchmark");
    const ev = await api.get("/api/evaluation").catch(() => ({ by_horizon: [], generalization: [] }));
    const rows = b.rows || [], horizons = b.horizons || [];
    const wm = rows.find((r) => /world/i.test(r.model)), lr = rows.find((r) => /logistic/i.test(r.model)), pers = rows.find((r) => /persist/i.test(r.model));
    // hero: WM vs LR headline at the last horizon
    const hi = horizons.length - 1;
    const heroMetric = (k, wmv, lrv, better) => `<div class="nv-metric"><div class="k">${esc(k)}</div><div class="v">${wmv}</div><div class="sub">LR baseline ${lrv} · ${esc(better)}</div></div>`;
    // by-horizon trend chart (PR-AUC)
    const trend = (ev.by_horizon || []);
    const barTrend = trend.length ? `<div class="nv-tablewrap"><table class="nv"><thead><tr><th>Horizon</th><th style="width:50%">World model PR-AUC</th><th class="num">World model</th><th class="num">Logistic reg.</th></tr></thead><tbody>
      ${trend.map((r) => { const w = r.worldModel ? r.worldModel.prauc : 0, mx = Math.max(...trend.map(t=>t.worldModel?t.worldModel.prauc:0),1e-6);
        return `<tr><td>${esc(r.horizon)}</td><td><div class="nv-bar blue"><i style="width:${(w/mx*100).toFixed(0)}%"></i></div></td><td class="num">${r.worldModel?r.worldModel.prauc:"n/a"}</td><td class="num">${r.baseline?r.baseline.prauc:"n/a"}</td></tr>`; }).join("")}
      </tbody></table></div>` : `<div class="nv-empty">Per-horizon metrics unavailable.</div>`;
    // early warning (from current selection, honestly labelled)
    let early = `<div class="nv-empty">Select a replay scenario on the Forecast page to see a concrete early-warning example.</div>`;
    try {
      const sel = await currentSelection(); const d = sel.fc;
      if (d.ground_truth) {
        const lead = d.lead_time_s, alertT = d.first_alert;
        if (!alertT) {
          early = `<div class="nv-empty">The model does not raise a sustained alert on this capture.</div>`;
        } else {
          const alertMs = Date.parse(alertT);
          // Onset consistent with the measured lead time (lead = onset − alert, in seconds).
          const onsetT = (lead != null) ? new Date(alertMs + lead * 1000).toISOString() : ((d.attack_intervals[0] || [])[0] || null);
          const onsetMs = onsetT ? Date.parse(onsetT) : null;
          const alertLeft = onsetMs == null || alertMs <= onsetMs;
          const pinAlert = `<div class="nv-tl-mark alert" style="left:${alertLeft ? 15 : 75}%"><div class="pin"></div><div class="lab">first alert<br>${hhmmss(alertT)}</div></div>`;
          const pinOnset = onsetT ? `<div class="nv-tl-mark onset" style="left:${alertLeft ? 75 : 15}%"><div class="pin"></div><div class="lab">annotated onset<br>${hhmmss(onsetT)}</div></div>` : "";
          early = `<p class="nv-note" style="margin-top:0">Concrete example — scenario <b>${esc(d.scenario.label.split("|")[0].trim())}</b>, host <span class="nv-mono">${esc(d.scenario.host)}</span>:</p>
            <div class="nv-timeline"><div class="nv-tl-track">${pinAlert}${pinOnset}</div></div>
            <div class="nv-grid" style="margin-top:8px">
              ${metric("Warning lead time", `<small>${esc(leadLabel(d))}</small>`, { cls: (lead || 0) > 0 ? "ok" : "" })}
              ${metric("First sustained alert", hhmmss(alertT))}
              ${metric("Onset nearest the alert", hhmmss(onsetT))}</div>
            ${caveat("Onset is the labelled attack onset nearest the alert, derived from the model's measured lead time; positive lead = warned before onset, negative = detected after. Measured on this capture, not a claim about all captures.")}`;
        }
      }
    } catch {}
    content.innerHTML =
      section("World model vs baselines", "Does the forecast work?",
        `Held-out chronological test split. ${esc(b.metric_note || "PR-AUC / F1 higher is better; FPR lower is better.")}`,
        `<div class="nv-grid">
          ${heroMetric(`PR-AUC (${horizons[hi]||""})`, wm?wm.pr_auc[hi]:"n/a", lr?lr.pr_auc[hi]:"n/a", "higher better")}
          ${heroMetric(`F1 (${horizons[hi]||""})`, wm?wm.f1[hi]:"n/a", lr?lr.f1[hi]:"n/a", "higher better")}
          ${heroMetric(`False-positive rate (${horizons[hi]||""})`, wm?wm.fpr[hi]:"n/a", lr?lr.fpr[hi]:"n/a", "lower better")}
          ${metric("Persistence PR-AUC", pers?pers.pr_auc[hi]:"n/a", { sub: "structurally ~0 on onset" })}
        </div>
        <p class="nv-note">${esc(b.takeaway || "")}</p>
        <p class="nv-caveat">The backend reports PR-AUC, F1 and FPR (precision/recall are not exported separately, so they are not shown rather than fabricated).</p>`) +
      section("Performance by horizon", "How does it hold up at +30 / +60 / +120 s?", "", barTrend) +
      section("How early did it warn?", "First sustained alert vs annotated onset", "", early) +
      section("Generalization", "Cross-condition and ablation results", "",
        `<div class="nv-tablewrap"><table class="nv"><thead><tr><th>Setting</th><th>Result</th></tr></thead>
        <tbody>${(ev.generalization || []).map((g) => `<tr><td>${esc(g.setting)}</td><td>${esc(g.result)}</td></tr>`).join("") || `<tr><td colspan="2" class="nv-muted">Not yet measured.</td></tr>`}</tbody></table></div>`) +
      `<details class="nv-acc" style="margin-top:16px"><summary>Evaluation protocol & reproducibility</summary><div class="body">
        Chronological splits only (never a random shuffle); attack campaigns kept intact within a split. The persistence baseline appears in every table.
        Metrics source: <span class="nv-mono">${esc(b.source || "wm_final")}</span>. Warning lead time — seconds before the labelled onset — is the headline metric, reported per capture rather than as a single aggregate.
      </div></details>
      <details class="nv-acc"><summary>Ground-truth handling & honest gaps</summary><div class="body">
        Ground-truth labels are used only for post-hoc evaluation, never as model inputs. External cross-dataset transfer (e.g. UNSW-NB15) is not yet run and is shown as "not measured" rather than estimated.
      </div></details>`;
  }

  async function modelPage(content) {
    setCtx({ scenario: "Architecture", host: "—", horizon: "+120s", mode: "Model card", data: "Checkpoint" });
    const m = await api.get("/api/model-card");
    const telemetry = await api.get("/api/telemetry").catch(() => ({ sources: [] }));
    const readiness = await api.get("/api/production-readiness").catch(() => ({ checks: [], ready_for_production: false }));
    const flow = `<div class="nv-flow" style="margin-bottom:6px">
      <div class="nv-step"><div class="hz">input</div><div class="st" style="font-size:12px">Network traffic</div><div class="meta">flows + packets</div></div>
      <span class="nv-arrow">→</span><div class="nv-step"><div class="hz">S_t</div><div class="st" style="font-size:12px">Network state</div><div class="meta">${m.input_features} features / window</div></div>
      <span class="nv-arrow">→</span><div class="nv-step focus"><div class="hz">core</div><div class="st" style="font-size:12px">Temporal world model</div><div class="meta">LSTM enc–dec · attention</div></div>
      <span class="nv-arrow">→</span><div class="nv-step"><div class="hz">rollout</div><div class="st" style="font-size:12px">K-step future states</div><div class="meta">${esc((m.horizons||[]).join(" · "))}</div></div>
      <span class="nv-arrow">→</span><div class="nv-step"><div class="hz">output</div><div class="st" style="font-size:12px">Forecast</div><div class="meta">risk · stage · evidence</div></div></div>`;
    const rollout = `<div class="nv-chain" style="justify-content:center;font-size:14px;padding:6px 0">
      <span class="node">S_t</span><span class="ar">→ P(S_t+1|S_t) →</span><span class="node">S_t+1</span><span class="ar">→</span><span class="node">S_t+2</span><span class="ar">→ … →</span><span class="node">S_t+4</span></div>`;
    content.innerHTML =
      section("Architecture", "How the forecasting system works", "Traffic becomes a network state; the world model rolls that state forward and scores the predicted future.",
        flow + `<div style="margin-top:14px">${rollout}</div>` +
        `<p class="nv-note">Unlike a classifier that labels the current observation, the model learns the transition dynamics P(S_t+1 | S_t) and scores the <b>predicted future</b> for onset risk.</p>`) +
      section("State representation", "What each window encodes", "",
        `<div class="nv-grid">
          ${metric("Flow behaviour", "SYN/ACK · fan-out", { sub: "connection dynamics" })}
          ${metric("Packet behaviour", `${(m.packet_features||[]).length} features`, { sub: "lengths · IAT · windows" })}
          ${metric("Temporal dynamics", m.history, { sub: "per-window history" })}
          ${metric("Endpoint topology", "ports · peers", { sub: "entropy · new peers" })}
        </div>`) +
      section("Model configuration", "Read from the loaded checkpoint", "",
        `<div class="nv-grid">
          ${metric("Parameters", num(m.parameters))}
          ${metric("Input features", m.input_features)}
          ${metric("ATT&CK stages", m.attack_stages)}
          ${metric("Horizons", `<small>${esc((m.horizons||[]).join(", "))}</small>`)}
          ${metric("Window size", `<small>${esc(m.window_size)}</small>`)}
          ${metric("Alert threshold", m.threshold)}
          ${metric("Attention", `<small>${m.attention ? "enabled" : "off"}</small>`)}
          ${metric("Explainability", `<small>SHAP + attention</small>`)}
        </div>`) +
      section("Phase 7 — telemetry readiness", "Which network evidence is connected?", "Missing telemetry is shown explicitly; unavailable sources are never fabricated.",
        `<div class="nv-tablewrap"><table class="nv"><thead><tr><th>Source</th><th>Status</th><th>Identity</th><th>Timestamp</th><th class="num">Features</th></tr></thead><tbody>${(telemetry.sources||[]).map((s) => `<tr><td>${esc(s.name)}</td><td>${stageBadge(s.status === "active" ? "ACTIVE" : "NOT CONNECTED")}</td><td>${esc(s.identity)}</td><td>${s.timestamp ? "yes" : "no"}</td><td class="num">${num(s.features)}</td></tr>`).join("")}</tbody></table></div>`) +
      section("Phases 8–10 — operational readiness", "Graph, decision support and promotion gates", "The release gate is intentionally conservative.",
        `<div class="nv-grid two">${(readiness.checks||[]).map((c) => metric(c.name, `<small>${esc(c.status.toUpperCase())}</small>`, { sub: c.detail, cls: c.status === "pass" ? "ok" : c.status === "fail" ? "alert" : "" })).join("")}</div><p class="nv-caveat">${readiness.ready_for_production ? "Ready for controlled promotion." : "Not ready for production promotion: real long-horizon evidence or telemetry integrations are still missing."}</p>`) +
      `<details class="nv-acc" style="margin-top:16px"><summary>Packet-derived feature schema</summary><div class="body">
        ${(m.packet_features||[]).map((f) => `<span class="nv-chip">${esc(f)}</span>`).join("") || "n/a"}
        <p class="nv-note">Available when a PCAP is uploaded; CSV captures show these as unavailable rather than fabricated.</p></div></details>
      <details class="nv-acc"><summary>Training & reproducibility</summary><div class="body">${esc(m.training)}.<br>Training data: ${esc(m.training_data)}.</div></details>
      <details class="nv-acc"><summary>Model limitations</summary><div class="body">
        Only attacks with an observable ramp (scan, brute-force, botnet beaconing) can be forecast 30–120 s ahead; single-packet exploits cannot. Risk is an onset score, not a calibrated probability. Passive reconnaissance is not always observable, and network traffic alone does not prove host compromise.</div></details>`;
  }

  async function livePage(content) {
    setCtx({ scenario: "Live server", host: "—", horizon: "+120s", mode: "Live", data: "Live feed" });
    const telemetry = await api.get("/api/telemetry").catch(() => ({ sources: [] }));
    async function tick() {
      let d;
      try { d = await api.get("/api/live"); } catch (e) { content.innerHTML = `<div class="nv-err">${esc(e.message)}</div>`; return; }
      const age = d.age_seconds;
      const fresh = age == null ? "unknown" : age < 60 ? `updated ${Math.round(age)} s ago` : age < 3600 ? `${Math.round(age / 60)} min ago` : `${(age / 3600).toFixed(1)} h ago`;
      const stale = age != null && age > 120;
      const telem = section("Telemetry readiness", "Connected evidence sources", "",
        `<div class="nv-tablewrap"><table class="nv"><thead><tr><th>Source</th><th>Status</th><th>Identity</th><th>Timestamp</th></tr></thead>
        <tbody>${(telemetry.sources || []).map((s) => `<tr><td>${esc(s.name)}</td><td>${stageBadge(s.status === "active" ? "ACTIVE" : "NOT CONNECTED")}</td><td>${esc(s.identity)}</td><td>${s.timestamp ? "yes" : "no"}</td></tr>`).join("")}</tbody></table></div>`) +
        caveat("The live pipeline runs offline on the monitored host (CICFlowMeter → 30 s windows → world model). This page polls its output; it does not sniff traffic itself.");
      if (!d.available) {
        content.innerHTML = section("Live server monitoring", "No live feed connected", "",
          `<div class="nv-empty">Start the live forecaster on the monitored host, then this page updates automatically:<br>
            <code class="nv-mono">python scripts/live_forecast.py --flows &lt;flows_dir&gt; --interval 30</code><br><span class="nv-muted">${esc(d.note || "")}</span></div>`) + telem;
        return;
      }
      const alertingN = d.hosts.filter((hh) => hh.alerting).length;
      content.innerHTML =
        card("", `<div class="nv-grid">
          ${metric("Live hosts", num(d.n_hosts))}
          ${metric("Alerting now", num(alertingN), { cls: alertingN ? "alert" : "" })}
          ${metric("Alert threshold", d.threshold)}
          ${metric("Feed freshness", `<small>${esc(fresh)}</small>`, { cls: stale ? "alert" : "ok" })}
        </div>`) +
        section("Live per-host forecasts", "Streaming from the monitored server",
          "Sorted by peak forecast risk. Read-only — the API serves the offline live loop's output.",
          `<div class="nv-tablewrap"><table class="nv"><thead><tr><th>Host</th><th>Last window</th><th class="num">+60s</th><th class="num">+90s</th><th class="num">+120s</th><th class="num">Peak</th><th>Stage</th><th>Action</th><th>Alert</th></tr></thead>
          <tbody>${d.hosts.slice(0, 40).map((hh) => `<tr><td class="nv-mono">${esc(hh.host)}</td><td>${hhmmss(hh.last_window)}</td>
            <td class="num">${pct(hh.risk["+60s"])}</td><td class="num">${pct(hh.risk["+90s"])}</td><td class="num">${pct(hh.risk["+120s"])}</td>
            <td class="num">${pct(hh.peak_risk)}</td><td>${stageBadge(hh.stage)}</td><td>${esc((hh.action || {}).summary || "Monitor")}</td>
            <td>${hh.alerting ? `<span class="nv-badge critical">${esc(hh.alert_level && hh.alert_level !== "none" ? hh.alert_level.toUpperCase() : "ALERTING")}</span>` : `<span class="nv-badge benign">clear</span>`}</td></tr>`).join("")}</tbody></table></div>`) +
        telem;
    }
    await tick();
    clearInterval(window.__nvLive); window.__nvLive = setInterval(tick, 4000);
  }

  // Operator live console.  The older livePage above is retained as a small
  // compatibility fallback in history; this version adds the guarded response
  // workflow without changing replay pages.
  async function livePageV2(content) {
    setCtx({ scenario: "Live server", host: "—", horizon: "+120s", mode: "Live", data: "Live feed" });
    const telemetry = await api.get("/api/telemetry").catch(() => ({ sources: [] }));
    const tokenKey = "nv_operator_token";
    const getToken = () => { try { return window.NV_OPERATOR_TOKEN || sessionStorage.getItem(tokenKey) || ""; } catch { return window.NV_OPERATOR_TOKEN || ""; } };
    const saveToken = (v) => { try { sessionStorage.setItem(tokenKey, v); } catch {} };
    let selectedHost = null;
    let latest = null;
    const actionOptions = (selected) => `${selected ? "" : "<option value=\"\" selected disabled>No actionable recommendation</option>"}${["block_attack_port", "block_source_ip", "block_destination_ip", "rate_limit", "restrict_east_west", "isolate_host"].map((x) => `<option value="${x}" ${x === selected ? "selected" : ""}>${x}</option>`).join("")}`;
    const actionRows = (items) => !items?.length ? `<div class="nv-empty">No response actions recorded.</div>` : `<div class="nv-tablewrap"><table class="nv"><thead><tr><th>Time</th><th>Action</th><th>Target</th><th>Status</th><th>Mode</th><th></th></tr></thead><tbody>${items.slice(0, 20).map((a) => `<tr><td class="nv-mono">${esc(hhmmss(a.created_at))}</td><td>${esc(a.action_type)}</td><td class="nv-mono">${esc(a.target_ip)}${a.target_port ? `:${esc(a.target_port)}` : ""}</td><td>${esc(a.status)}</td><td>${a.dry_run ? "dry-run" : "enforced"}</td><td>${a.rollback_available ? `<button class="nv-btn sec nv-rollback" data-action-id="${esc(a.action_id)}">Rollback</button>` : ""}</td></tr>`).join("")}</tbody></table></div>`;
    const telemetryPanel = section("Telemetry readiness", "Connected evidence sources", "The live page polls the server-side capture and inference pipeline; it does not sniff traffic in the browser.", `<div class="nv-tablewrap"><table class="nv"><thead><tr><th>Source</th><th>Status</th><th>Identity</th><th>Timestamp</th></tr></thead><tbody>${(telemetry.sources || []).map((s) => `<tr><td>${esc(s.name)}</td><td>${stageBadge(s.status === "active" ? "ACTIVE" : "NOT CONNECTED")}</td><td>${esc(s.identity)}</td><td>${s.timestamp ? "yes" : "no"}</td></tr>`).join("")}</tbody></table></div>`);
    async function tick() {
      let data;
      try { data = await api.get("/api/live"); } catch (e) { content.innerHTML = `<div class="nv-err">${esc(e.message)}</div>`; return; }
      latest = data;
      const events = await api.get("/api/live/events?limit=50").catch(() => ({ events: [] }));
      const age = data.age_seconds;
      const stale = Boolean(data.stale || (age != null && age > 90));
      const fresh = age == null ? "unknown" : age < 60 ? `updated ${Math.round(age)} s ago` : `${Math.round(age / 60)} min ago`;
      if (!data.available || !data.hosts?.length) {
        content.innerHTML = card("", `<div class="nv-grid">${metric("Pipeline", `<small>${stale ? "STALE" : "OFFLINE"}</small>`, { cls: "alert" })}${metric("Response mode", `<small>${esc(data.mode || "dry_run")}</small>`)}</div>`) + section("Live server monitoring", "No live feed connected", "Start the forecaster on the monitored Linux server.", `<div class="nv-empty"><code class="nv-mono">python scripts/live_forecast.py --flows &lt;flows_dir&gt; --interval 5</code><br>${esc(data.note || "Waiting for a valid 10-window history.")}</div>`) + telemetryPanel;
        return;
      }
      if (!selectedHost || !data.hosts.some((h0) => h0.host === selectedHost)) selectedHost = data.hosts[0].host;
      const host = data.hosts.find((h0) => h0.host === selectedHost) || data.hosts[0];
      const horizons = data.horizons || Object.keys(host.risk || {});
      const alerting = data.hosts.filter((h0) => h0.alerting).length;
      const hostEventItems = (events.events || []).filter((e) => e.host === host.host);
      const lastAlertEvent = [...hostEventItems].reverse().find((e) => ["EARLY_WARNING", "CONFIRMED_ALERT"].includes(e.forecast_state) && e.recommended_action?.action_type);
      const currentRecommendation = host.recommended_action?.action_type ? host.recommended_action : null;
      const recommendation = currentRecommendation || lastAlertEvent?.recommended_action || { action_type: null, label: "Monitor only", target_ip: host.host, target_port: null, ttl_seconds: null, rationale: "No current or recent alert recommendation is available.", requires_human_approval: false };
      const recommendationIsCurrent = Boolean(currentRecommendation && host.alerting && !stale);
      // Only the server-side recommendation is actionable.  Do not silently
      // turn a stage label into a containment action when the backend returned
      // monitor-only (for example, an alert with no reliable stage).
      const stageAction = recommendation.action_type || "";
      const recommendationTargetPort = recommendation.target_port == null ? "" : recommendation.target_port;
      const recommendationTarget = recommendation.target_ip || host.host;
      const hostRows = data.hosts.slice(0, 50).map((h0) => `<tr class="nv-live-host-row ${h0.host === host.host ? "selected" : ""}" data-live-host="${esc(h0.host)}"><td class="nv-mono">${esc(h0.host)}</td><td>${hhmmss(h0.last_window)}</td>${horizons.map((hz) => `<td class="num">${pct(h0.risk?.[hz])}</td>`).join("")}<td class="num">${pct(h0.peak_risk)}</td><td>${stageBadge(h0.stage)}</td><td>${h0.forecast_state === "CONFIRMED_ALERT" ? `<span class="nv-badge critical">CONFIRMED</span>` : h0.forecast_state === "EARLY_WARNING" ? `<span class="nv-badge elevated">EARLY WARNING</span>` : `<span class="nv-badge benign">NORMAL</span>`}</td></tr>`).join("");
      const driverRows = (host.feature_drivers || []).map((f) => `<tr><td>${esc(f.label || f.feature)}</td><td class="nv-mono">${esc(f.feature)}</td><td class="num">${esc(f.observed)}</td><td class="num">${esc(f.robust_deviation)}</td></tr>`).join("");
      const timelineRows = (host.timeline || []).map((r) => `<div class="nv-live-timeline-row"><span class="nv-mono">${esc(hhmmss(r.last_window || r.window_start))}</span>${horizons.map((hz) => { const k = Number(String(hz).replace("+", "").replace("s", "")) / 30; const value = Number(r[`risk_k${k}`] || 0); return `<span class="nv-live-risk-cell"><i style="width:${Math.max(2, Math.min(100, value * 100))}%"></i><b>${pct(value)}</b></span>`; }).join("")}</div>`).join("") || `<div class="nv-empty">Waiting for completed forecast windows.</div>`;
      const hostEvents = hostEventItems.slice(-10).reverse().map((e) => `<tr><td class="nv-mono">${esc(hhmmss(e.issued_at))}</td><td>${esc(e.forecast_state)}</td><td>${esc((e.crossed_horizons || []).join(", ") || "none")}</td><td class="nv-mono">${esc(e.event_id)}</td></tr>`).join("") || `<tr><td colspan="4">No forecast events for this host.</td></tr>`;
      content.innerHTML = card("", `<div class="nv-grid">${metric("Live hosts", num(data.n_hosts))}${metric("Alerting now", num(alerting), { cls: alerting ? "alert" : "" })}${metric("Feed freshness", `<small>${esc(fresh)}</small>`, { cls: stale ? "alert" : "ok" })}${metric("Pipeline", `<small>${esc(stale ? "STALE" : "LIVE")}</small>`, { cls: stale ? "alert" : "ok" })}${metric("Response mode", `<small>${esc(data.mode || "dry_run")}</small>`)}</div>`) +
        section("Live per-host forecasts", "Streaming from the monitored server", "Click a host to inspect the forecast and response controls.", `<div class="nv-tablewrap"><table class="nv"><thead><tr><th>Host</th><th>Last window</th>${horizons.map((hz) => `<th class="num">${esc(hz)}</th>`).join("")}<th class="num">Peak</th><th>Stage</th><th>State</th></tr></thead><tbody>${hostRows}</tbody></table></div>`) +
        section("Focused host", `${host.host} · ${host.forecast_state}`, "Forecast state is advisory; network traffic alone does not prove compromise.", `<div class="nv-grid">${horizons.map((hz) => metric(`${hz} risk`, pct(host.risk?.[hz]), { cls: (host.risk?.[hz] || 0) >= data.threshold ? "alert" : "" })).join("")}${metric("Confidence", host.confidence == null ? "n/a" : pct(host.confidence))}${metric("Resolution", `${data.measurement_resolution_seconds || 30}s`)}</div><p class="nv-note">${host.forecast_state === "EARLY_WARNING" ? "Early warning: review evidence before containment." : host.forecast_state === "CONFIRMED_ALERT" ? "Confirmed forecast state: a human decision is required before containment." : "No calibrated forecast threshold is currently crossed."}</p>`) +
        section("Risk timeline", "Observed forecast history", "Each row is a completed 30-second observation window; bars show the model risk available at that origin.", `<div class="nv-live-timeline-head"><span>window</span>${horizons.map((hz) => `<span>${esc(hz)}</span>`).join("")}</div><div class="nv-live-timeline">${timelineRows}</div>`) +
        section("Forecast evidence", "Top observed drivers", "Robust-scaled observations from the current window; these are evidence signals, not causal attributions.", `<div class="nv-tablewrap"><table class="nv"><thead><tr><th>Feature</th><th>Model field</th><th class="num">Observed</th><th class="num">Deviation</th></tr></thead><tbody>${driverRows || `<tr><td colspan="4">No driver data available.</td></tr>`}</tbody></table></div>`) +
        section("Live recommendation", recommendationIsCurrent ? "Recommended action now" : recommendation.action_type ? "Last alert recommendation" : "Monitor only", recommendationIsCurrent ? "Generated from the current forecast; approval is required and nothing is applied automatically." : recommendation.action_type ? "The alert has cleared. This recommendation is retained for audit and is read-only until a new alert is active." : "No containment action is recommended while the current forecast is below the calibrated alert threshold.", `<div class="nv-recommendation"><div><b>${esc(recommendation.label || recommendation.action_type)}</b><span class="nv-badge ${recommendationIsCurrent ? "elevated" : recommendation.action_type ? "observed" : "benign"}">${recommendationIsCurrent ? "REVIEW REQUIRED" : recommendation.action_type ? "HISTORICAL" : "MONITOR"}</span></div><p>${esc(recommendation.rationale || "")}</p>${recommendation.action_type ? `<p class="nv-note">Target: <span class="nv-mono">${esc(recommendationTarget)}${recommendationTargetPort ? `:${esc(recommendationTargetPort)}` : ""}</span> · TTL: ${esc(recommendation.ttl_seconds || 300)}s${recommendation.target_port_note ? ` · ${esc(recommendation.target_port_note)}` : ""}</p>` : ""}</div>`) +
        section("Human-in-the-loop response", "Preview a defensive action", "The form is populated from the current recommendation. Dry-run is the default; preview shows the exact target, rule and TTL before approval.", `<div class="nv-live-action-form"><label>Operator token <input id="nv-op-token" type="password" placeholder="required for approval" value="${esc(getToken())}"></label><label>Action <select id="nv-action-type">${actionOptions(stageAction)}</select></label><label>Target IP <input id="nv-action-ip" value="${esc(recommendationTarget)}"></label><label>Port <input id="nv-action-port" type="number" min="1" max="65535" value="${esc(recommendationTargetPort)}"></label><label>TTL seconds <input id="nv-action-ttl" type="number" min="1" max="3600" value="${esc(recommendation.ttl_seconds || 300)}"></label><label>Mode <select id="nv-action-mode"><option value="dry_run">dry-run</option><option value="enforce">enforce if server allows</option></select></label><button class="nv-btn" id="nv-action-preview" ${stale || !recommendationIsCurrent ? "disabled" : ""}>Preview response</button>${stale ? `<span class="nv-caveat">Feed is stale; response controls are disabled.</span>` : !recommendationIsCurrent ? `<span class="nv-caveat">${recommendation.action_type ? "Approval is enabled only while this host is currently alerting." : "No actionable recommendation was generated by the live forecast."}</span>` : ""}</div><div id="nv-action-preview-result"></div>`) +
        section("Forecast event log", "State transitions", "Events written by the server-side live loop.", `<div class="nv-tablewrap"><table class="nv"><thead><tr><th>Time</th><th>State</th><th>Crossed horizons</th><th>Event</th></tr></thead><tbody>${hostEvents}</tbody></table></div>`) +
        section("Response audit", "Approved actions", "Every action is operator-approved, TTL-bound and reversible.", actionRows(data.actions)) + telemetryPanel;
      content.querySelectorAll("[data-live-host]").forEach((row) => row.addEventListener("click", () => { selectedHost = row.dataset.liveHost; tick(); }));
      const tokenInput = content.querySelector("#nv-op-token");
      if (tokenInput) tokenInput.addEventListener("change", () => saveToken(tokenInput.value));
      const preview = content.querySelector("#nv-action-preview");
      if (preview) preview.addEventListener("click", async () => {
        const token = getToken() || window.prompt("Enter the live operator token:");
        if (!token) return;
        saveToken(token);
        const result = content.querySelector("#nv-action-preview-result");
        try {
          const p = await api.post("/api/live/actions/preview", { alert_id: host.event_id || `live-${host.host}`, host: host.host, action_type: content.querySelector("#nv-action-type").value, target_ip: content.querySelector("#nv-action-ip").value, target_port: Number(content.querySelector("#nv-action-port").value || 22), ttl_seconds: Number(content.querySelector("#nv-action-ttl").value || 300), reason: `Human review of ${host.forecast_state} ${host.stage} forecast`, mode: content.querySelector("#nv-action-mode").value }, token);
          result.innerHTML = card("Action preview", `<p><b>${esc(p.rule)}</b></p><p class="nv-note">${p.dry_run ? "Dry-run: no firewall change will be made." : "Enforcement is enabled on the server."} Expires ${esc(p.expires_at)}.</p><button class="nv-btn" id="nv-action-approve">Approve this action</button>`);
          result.querySelector("#nv-action-approve").addEventListener("click", async () => { try { await api.post(`/api/live/actions/${encodeURIComponent(p.preview_id)}/approve`, {}, token); await tick(); } catch (e) { result.innerHTML += `<p class="nv-err">${esc(e.message)}</p>`; } });
        } catch (e) { result.innerHTML = `<p class="nv-err">${esc(e.message)}</p>`; }
      });
      content.querySelectorAll(".nv-rollback").forEach((button) => button.addEventListener("click", async () => { const token = getToken() || window.prompt("Enter the live operator token:"); if (!token) return; try { await api.post(`/api/live/actions/${encodeURIComponent(button.dataset.actionId)}/rollback`, {}, token); await tick(); } catch (e) { window.alert(e.message); } }));
    }
    await tick();
    clearInterval(window.__nvLive); window.__nvLive = setInterval(tick, 5000);
  }

  /* ---------------- boot ---------------- */
  async function boot() {
    try { await api.get("/api/health"); setSide(true); }
    catch {
      setSide(false);
      shell("System", "Backend offline", "The live model API is not reachable.").innerHTML =
        `<div class="nv-err">Cannot reach the model backend at <code>${esc(BASE)}</code>.<br>
        Start it from the model repo venv:<br><code>python -m uvicorn api.server:app --port 8000</code></div>`;
      return;
    }
    try {
      if (route === "home") { shell("01 / Command centre", "NetraVerse", "Network attack forecasting — live world model."); return void homePage(document.getElementById("nv-content")); }
      if (route === "simulate") { shell("02 / Simulate", "Run a forecast simulation", "Select or upload traffic, build the network state, and run the forecast."); return void simulatePage(document.getElementById("nv-content")); }
      if (route === "validate") { shell("07 / Validate", "Does the forecast work?", "Benchmarks, per-horizon performance, early warning and generalization."); return void validatePage(document.getElementById("nv-content")); }
      if (route === "model") { shell("08 / Model", "How the forecasting system works", "Architecture, state representation and configuration, from the checkpoint."); return void modelPage(document.getElementById("nv-content")); }
      if (route === "live") { shell("09 / Live", "Live server monitoring", "Real-time forecasts streamed from the monitored host."); return void livePageV2(document.getElementById("nv-content")); }

      const meta = {
        forecast: ["03 / Forecast", "What is likely to happen next?", "Current state → future states → risk and ATT&CK-stage trajectory."],
        attack: ["04 / ATT&CK", "How does the forecast map to ATT&CK?", "Predicted MITRE stage progression from the same forecast state."],
        investigate: ["05 / Investigate", "Why did the model forecast this?", "Trace the forecast back through evidence, attribution and attention."],
        network: ["06 / Network", "What is actually happening on the network?", "Observed telemetry that supports the network-state representation."],
      };
      const [eb, t, s] = meta[route] || ["", "Live", "World-model output"];
      const content = shell(eb, t, s, "");
      const sel = await currentSelection();
      const ctrlEl = document.getElementById("nv-ctrl"); if (ctrlEl) ctrlEl.innerHTML = await pickerControls(sel);
      wirePicker();
      if (route === "forecast") forecastPage(content, sel.fc);
      else if (route === "attack") attackPage(content, sel.fc);
      else if (route === "network") networkPage(content, { ...sel.fc, upload_id: sel.upload_id });
      else if (route === "investigate") await investigatePage(content, sel);
      else homePage(content);
    } catch (e) {
      const c = document.getElementById("nv-content") || rootEl();
      c.innerHTML = `<div class="nv-err">${esc(e.message)}</div>`;
    }
  }

  window.NV_boot = boot;
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot); else boot();
})();
