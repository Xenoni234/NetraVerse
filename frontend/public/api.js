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
  const BASE = (window.NV_API_BASE || "http://localhost:8000").replace(/\/$/, "");
  const route = document.body.dataset.route || "home";
  const store = {
    get sel() { try { return JSON.parse(sessionStorage.getItem("nv_sel") || "null"); } catch { return null; } },
    set sel(v) { try { sessionStorage.setItem("nv_sel", JSON.stringify(v)); } catch {} },
  };

  /* ---------------- helpers ---------------- */
  const api = {
    async get(p) { const r = await fetch(BASE + p); if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || r.statusText); return r.json(); },
    async upload(file) { const fd = new FormData(); fd.append("file", file); const r = await fetch(BASE + "/api/upload", { method: "POST", body: fd }); if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || r.statusText); return r.json(); },
  };
  const h = (html) => { const t = document.createElement("template"); t.innerHTML = html.trim(); return t.content.firstElementChild; };
  const esc = (s) => String(s == null ? "" : s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  const pct = (x) => (x == null || isNaN(x) ? "n/a" : (x * 100).toFixed(1) + "%");
  const num = (x) => (x == null || isNaN(x) ? "—" : (+x).toLocaleString());
  const hhmmss = (iso) => (iso ? String(iso).slice(11, 19) : "—");
  const cap = (s) => (s ? s.charAt(0) + s.slice(1).toLowerCase() : s);
  const stageName = (s) => cap(String(s || "").replace(/_/g, " "));

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
      try { sel.fc = await api.get(`/api/upload/${sel.upload_id}/forecast?host=${encodeURIComponent(sel.host)}&mc=20`); return sel; }
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
        <div class="nv-step ${i === steps.length - 1 ? "focus" : ""}"><div class="hz">S_t+${[1,2,4][i] ?? i+1} · ${esc(s.horizon)}</div><div class="st">${esc(stageName(s.stage))}</div><div class="rk">${pct(s.risk)}</div><div class="meta">${esc(s.tactic || "no ATT&CK tactic")} · ${esc(s.confidence)}${s.uncertainty != null ? " · ±" + pct(s.uncertainty) : ""}</div></div>`).join("")}
    </div>`;
    return flow;
  }

  function forecastPage(content, d) {
    ctxFromForecast(d);
    const steps = d.forecast || [];
    content.innerHTML =
      plainBlock(d.plain_language) +
      card("", `<div class="nv-grid">
        ${metric("Current state", riskBadge(d.peak_risk, d.threshold))}
        ${metric("Peak onset risk", pct(d.peak_risk), { cls: d.peak_risk >= d.threshold ? "alert" : "" })}
        ${metric("Alert threshold", d.threshold)}
        ${metric(d.ground_truth ? "Warning lead time" : "Mode", `<small>${esc(leadLabel(d))}</small>`)}
      </div>`) +
      section("K-step rollout", "Current state → future states",
        "The world model rolls the current network state forward one window at a time and scores each projected future state for onset risk.",
        forecastNode(d) + `<div style="margin-top:16px">${projectionChart(d.peak_risk, steps, d.threshold)}</div>` +
        caveat("Risk is a per-window onset score from the decoder's predicted future state — not a calibrated probability. Predicted stage is a model output, not a confirmed action.")) +
      section("Risk trajectory", "Forecast risk over the observed timeline",
        "Each point is the model's onset-risk forecast for that 30-second window across the replayed capture.",
        riskTimeline(d) +
        `<div class="nv-tablewrap" style="margin-top:14px"><table class="nv"><thead><tr><th>Horizon</th><th class="num">Forecast risk</th><th>Predicted stage</th><th>ATT&CK tactic</th><th>Confidence</th>${steps.some(s=>s.uncertainty!=null)?'<th class="num">± band</th>':''}</tr></thead>
        <tbody>${steps.map((s) => `<tr><td>${esc(s.horizon)}</td><td class="num">${pct(s.risk)}</td><td>${stageBadge(s.stage)}</td><td>${esc(s.tactic || "—")}</td><td>${esc(s.confidence)}</td>${s.uncertainty!=null?`<td class="num">±${pct(s.uncertainty)}</td>`:''}</tr>`).join("")}</tbody></table></div>`) +
      card("", `<div class="nv-cta-row"><a class="nv-btn sec" href="/attack">ATT&CK trajectory</a><a class="nv-btn sec" href="/investigate">Why this forecast</a><a class="nv-btn sec" href="/network">Network evidence</a></div>`);
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
    content.innerHTML =
      plainBlock(d.plain_language) +
      card("Legend", `<div style="display:flex;gap:8px;flex-wrap:wrap">
        <span class="nv-badge observed">observed · nominal</span>
        <span class="nv-badge elevated">elevated</span>
        <span class="nv-badge critical">over threshold</span>
        <span class="nv-badge forecast">current focus window</span></div>`) +
      section("Predicted progression", "Predicted ATT&CK stage per observed window",
        "Each window's predicted stage comes from the model's +120 s forecast of that window's future state.",
        `<div style="line-height:2.1">${chips || '<span class="nv-muted">No windows.</span>'}</div>` +
        caveat("Stages can repeat, regress or be unmapped. These are predictions of a forecasted future state, not confirmed attacker actions, and network traffic alone does not prove host compromise.")) +
      section("K-step stage trajectory", "From the peak-risk window", "",
        `<div class="nv-tablewrap"><table class="nv"><thead><tr><th>Horizon</th><th>Predicted stage</th><th>ATT&CK tactic</th><th class="num">Forecast risk</th><th>Confidence</th></tr></thead>
        <tbody>${(d.forecast||[]).map((s) => `<tr><td>${esc(s.horizon)}</td><td>${stageBadge(s.stage)}</td><td>${esc(s.tactic || "—")}</td><td class="num">${pct(s.risk)}</td><td>${esc(s.confidence)}</td></tr>`).join("")}</tbody></table></div>`) +
      card("", `<div class="nv-cta-row"><a class="nv-btn sec" href="/forecast">Back to Forecast</a><a class="nv-btn sec" href="/investigate">Why this forecast</a></div>`);
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
      section("Temporal weight", "Attention over the 10-window history", "",
        attnFlat ? `<div class="nv-empty">Attention weights are uniform for this window — the model did not concentrate on a specific history step here.</div>`
        : `<div class="nv-tablewrap"><table class="nv"><thead><tr><th>History window</th><th style="width:60%">Attention weight</th></tr></thead><tbody>
        ${ex.attention.windows.map((w, i) => `<tr><td>${hhmmss(w)}</td><td><div class="nv-bar blue"><i style="width:${(ex.attention.weights[i]/maxa*100).toFixed(0)}%"></i></div></td></tr>`).join("")}
        </tbody></table></div>`);
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
      section("Communication & port activity", "Traffic and destination-port fan-out over time", "A spike in distinct destination ports is the signature of a scan.",
        `<div class="nv-grid two">
          ${card("Traffic volume (flows / 30 s)", spark(obs.map((o) => o.flows), "#0284c7", [hhmmss(obs[0]?.t), hhmmss(last.t)]))}
          ${card("Destination-port fan-out", spark(obs.map((o) => o.distinctPorts), "#b45309", [hhmmss(obs[0]?.t), hhmmss(last.t)]))}
          ${card("Port entropy", spark(obs.map((o) => o.portEntropy), "#0d9488"))}
          ${card("Failed-connection ratio", spark(obs.map((o) => o.failedConns), "#dc2626"))}
        </div>`) +
      section("Raw telemetry", "Per-window features that drive the forecast", "",
        `<div class="nv-tablewrap"><table class="nv"><thead><tr><th>Window</th><th class="num">Flows</th><th class="num">Pkts/s</th><th class="num">SYN</th><th class="num">Dst ports</th><th class="num">Port entropy</th><th class="num">Unique dsts</th><th class="num">Failed</th><th class="num">Mean IAT</th></tr></thead>
        <tbody>${obs.slice().reverse().map((o) => `<tr><td>${hhmmss(o.t)}</td><td class="num">${num(o.flows)}</td><td class="num">${o.pktRate}</td><td class="num">${o.synCount}</td><td class="num">${o.distinctPorts}</td><td class="num">${o.portEntropy}</td><td class="num">${o.uniqueDsts}</td><td class="num">${o.failedConns}</td><td class="num">${o.iat}</td></tr>`).join("")}</tbody></table></div>`);
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
        store.sel = { campaign: "upload", host, upload_id: res.upload_id, ground_truth: false };
        const rb = h(`<div id="nv-content"></div>`); resultEl.appendChild(rb);
        forecastPage(rb, { ...fc, scenario: fc.scenario || { host, label: "Uploaded capture" } });
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
      `<details class="nv-acc" style="margin-top:16px"><summary>Packet-derived feature schema</summary><div class="body">
        ${(m.packet_features||[]).map((f) => `<span class="nv-chip">${esc(f)}</span>`).join("") || "n/a"}
        <p class="nv-note">Available when a PCAP is uploaded; CSV captures show these as unavailable rather than fabricated.</p></div></details>
      <details class="nv-acc"><summary>Training & reproducibility</summary><div class="body">${esc(m.training)}.<br>Training data: ${esc(m.training_data)}.</div></details>
      <details class="nv-acc"><summary>Model limitations</summary><div class="body">
        Only attacks with an observable ramp (scan, brute-force, botnet beaconing) can be forecast 30–120 s ahead; single-packet exploits cannot. Risk is an onset score, not a calibrated probability. Passive reconnaissance is not always observable, and network traffic alone does not prove host compromise.</div></details>`;
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
      else if (route === "network") networkPage(content, sel.fc);
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
