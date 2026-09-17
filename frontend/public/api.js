/*
 * NetraVerse live-data client (single source of truth for page content).
 *
 * Every page's <main> is gutted to a single mount point (#nv-root); this file
 * renders the ENTIRE content of each page from the FastAPI backend (the real
 * world model). There is no hardcoded/demo data anywhere in the UI — every
 * number, label, table, chart and sentence below comes from a model call.
 *
 * Shared selection (scenario/host or uploaded capture) lives in sessionStorage
 * (`nv_sel`) so the whole product follows one capture across pages.
 */
(() => {
  const BASE = (window.NV_API_BASE || "http://localhost:8000").replace(/\/$/, "");
  const route = document.body.dataset.route || "home";
  const store = {
    get sel() { try { return JSON.parse(sessionStorage.getItem("nv_sel") || "null"); } catch { return null; } },
    set sel(v) { sessionStorage.setItem("nv_sel", JSON.stringify(v)); },
  };

  /* ---------- design system (matches app-shell.css tokens, self-contained) ---------- */
  const css = `
  #nv-root{--nv-bg:#f8fafc;--nv-card:#ffffff;--nv-line:#e2e8f0;--nv-ink:#0f172a;--nv-mut:#64748b;
    --nv-accent:#0284c7;--nv-warn:#f59e0b;--nv-bad:#dc2626;--nv-good:#0d9488;
    font-family:"IBM Plex Sans",system-ui,sans-serif;color:var(--nv-ink);display:block}
  #nv-root *{box-sizing:border-box}
  .nv-wrap{max-width:1180px;margin:0 auto;padding:22px 4px 48px}
  .nv-head{display:flex;flex-wrap:wrap;justify-content:space-between;align-items:flex-end;gap:14px;margin-bottom:6px}
  .nv-title{font-size:24px;font-weight:700;letter-spacing:-.01em;margin:0}
  .nv-sub{font-size:13px;color:var(--nv-mut);margin:4px 0 0}
  .nv-controls{display:flex;flex-wrap:wrap;gap:8px;align-items:center}
  .nv-select,.nv-file{border:1px solid #cbd5e1;border-radius:6px;padding:7px 10px;font-size:13px;background:#fff;color:var(--nv-ink)}
  .nv-btn{background:var(--nv-accent);color:#fff;border:none;border-radius:6px;padding:8px 15px;font-size:13px;cursor:pointer;font-weight:600}
  .nv-btn.sec{background:#fff;color:var(--nv-accent);border:1px solid var(--nv-accent)}
  .nv-btn:disabled{background:#94a3b8;cursor:default}
  .nv-card{background:var(--nv-card);border:1px solid var(--nv-line);border-radius:10px;padding:16px 18px;margin-top:16px}
  .nv-card h3{font-size:12px;letter-spacing:.06em;text-transform:uppercase;color:var(--nv-accent);margin:0 0 10px;font-weight:700}
  .nv-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}
  .nv-metric{background:var(--nv-bg);border:1px solid var(--nv-line);border-radius:8px;padding:12px 14px}
  .nv-metric .k{font-size:11px;color:var(--nv-mut);text-transform:uppercase;letter-spacing:.04em}
  .nv-metric .v{font-size:26px;font-family:"IBM Plex Mono",ui-monospace,monospace;margin-top:4px;font-weight:600}
  .nv-metric .v small{font-size:13px;color:var(--nv-mut);font-weight:400}
  .nv-metric.alert .v{color:var(--nv-bad)}
  .nv-note{font-size:12.5px;color:var(--nv-mut);margin:8px 0 0;line-height:1.5}
  .nv-plain{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px}
  .nv-plain div{background:var(--nv-bg);border-left:3px solid var(--nv-accent);border-radius:0 6px 6px 0;padding:10px 12px;font-size:13px;line-height:1.5}
  .nv-plain b{display:block;font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:var(--nv-mut);margin-bottom:3px}
  table.nv{width:100%;border-collapse:collapse;font-size:12.5px;margin-top:4px}
  table.nv th,table.nv td{border-bottom:1px solid #eef2f6;padding:7px 9px;text-align:left;
    font-family:"IBM Plex Mono",ui-monospace,monospace}
  table.nv th{color:var(--nv-mut);font-weight:600;text-transform:uppercase;font-size:10px;letter-spacing:.04em}
  .nv-chip{display:inline-block;padding:3px 9px;border:1px solid #cbd5e1;border-radius:999px;font-size:11px;
    font-family:"IBM Plex Mono",monospace;margin:2px 3px 2px 0;background:#fff}
  .nv-chip.hot{border-color:var(--nv-bad);color:var(--nv-bad)}
  .nv-chip.warn{border-color:var(--nv-warn);color:#b45309}
  .nv-bar{height:9px;background:var(--nv-line);border-radius:4px;overflow:hidden}
  .nv-bar>i{display:block;height:100%}
  .nv-stage{display:flex;align-items:center;gap:11px;padding:8px 0;border-bottom:1px solid #f1f5f9}
  .nv-dot{width:11px;height:11px;border-radius:50%;background:#cbd5e1;flex:none}
  .nv-dot.done{background:var(--nv-good)}.nv-dot.err{background:var(--nv-bad)}.nv-dot.run{background:var(--nv-warn)}
  .nv-err{color:#b91c1c;font-size:13px;background:#fef2f2;border:1px solid #fecaca;border-radius:8px;padding:12px 14px}
  .nv-muted{color:var(--nv-mut)}
  .nv-legend{display:flex;gap:16px;flex-wrap:wrap;font-size:11px;color:var(--nv-mut);margin-top:6px}
  .nv-legend span::before{content:"";display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:5px;vertical-align:-1px}
  .nv-legend .l-risk::before{background:var(--nv-accent)}
  .nv-legend .l-thr::before{background:var(--nv-warn)}
  .nv-legend .l-atk::before{background:#fca5a5}
  @media (max-width:700px){.nv-title{font-size:20px}.nv-metric .v{font-size:22px}}
  `;
  const style = document.createElement("style"); style.textContent = css; document.head.appendChild(style);

  /* ---------- helpers ---------- */
  const api = {
    async get(p) { const r = await fetch(BASE + p); if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || r.statusText); return r.json(); },
    async upload(file) { const fd = new FormData(); fd.append("file", file); const r = await fetch(BASE + "/api/upload", { method: "POST", body: fd }); if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || r.statusText); return r.json(); },
  };
  const h = (html) => { const t = document.createElement("template"); t.innerHTML = html.trim(); return t.content.firstElementChild; };
  const pct = (x) => (x == null ? "n/a" : (x * 100).toFixed(1) + "%");
  const esc = (s) => String(s == null ? "" : s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  const hhmmss = (iso) => (iso ? String(iso).slice(11, 19) : "-");
  const root = () => document.getElementById("nv-root") || (document.querySelector("main") || document.body);

  function shell(title, sub, controls) {
    root().innerHTML = `<div class="nv-wrap"><div class="nv-head">
      <div><h1 class="nv-title">${esc(title)}</h1><p class="nv-sub">${esc(sub)}</p></div>
      <div class="nv-controls" id="nv-ctrl">${controls || ""}</div></div>
      <div id="nv-content"><div class="nv-card"><p class="nv-muted">Loading real model output…</p></div></div></div>`;
    return document.getElementById("nv-content");
  }
  const card = (h3, inner) => `<div class="nv-card">${h3 ? `<h3>${esc(h3)}</h3>` : ""}${inner}</div>`;
  const metric = (k, v, alert) => `<div class="nv-metric${alert ? " alert" : ""}"><div class="k">${esc(k)}</div><div class="v">${v}</div></div>`;

  function chart(values, opts = {}) {
    const w = 720, ht = 120, n = values.length; if (!n) return "";
    const max = Math.max(opts.max || 0, 1e-6, ...values);
    const x = (i) => (i / Math.max(1, n - 1)) * w;
    const y = (v) => ht - (v / max) * (ht - 14) - 7;
    const pts = values.map((v, i) => `${x(i).toFixed(1)},${y(v).toFixed(1)}`).join(" ");
    const area = `0,${ht} ${pts} ${w},${ht}`;
    const thY = opts.threshold != null ? y(Math.min(opts.threshold, max)) : null;
    const bands = (opts.bands || []).map(([a, b]) => `<rect x="${x(a)}" y="0" width="${Math.max(2, x(b) - x(a))}" height="${ht}" fill="#fca5a5" opacity="0.28"/>`).join("");
    const col = opts.color || "#0284c7";
    return `<svg viewBox="0 0 ${w} ${ht}" width="100%" height="${ht}" preserveAspectRatio="none" style="display:block">
      ${bands}
      <polygon points="${area}" fill="${col}" opacity="0.08"/>
      ${thY != null ? `<line x1="0" y1="${thY}" x2="${w}" y2="${thY}" stroke="#f59e0b" stroke-dasharray="5 4" stroke-width="1.2"/>` : ""}
      <polyline points="${pts}" fill="none" stroke="${col}" stroke-width="2.2"/></svg>`;
  }

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

  // map observed windows to attack-band indices for the chart overlay
  function bandIndices(d) {
    if (!d.attack_intervals || !d.observed.length) return [];
    const ts = d.observed.map((o) => Date.parse(o.t));
    const out = [];
    for (const [a, b] of d.attack_intervals) {
      const ta = Date.parse(a), tb = Date.parse(b);
      let lo = ts.findIndex((t) => t >= ta), hi = ts.findIndex((t) => t > tb);
      if (lo < 0) continue; if (hi < 0) hi = ts.length; out.push([lo, Math.max(lo + 0.5, hi - 1)]);
    }
    return out;
  }

  /* ---------- shared scenario picker ---------- */
  async function pickerControls(sel) {
    if (sel.upload_id) {
      return `<span class="nv-chip warn">uploaded capture</span>
        <span class="nv-chip">${esc(sel.host)}</span>
        <a class="nv-btn sec" href="/simulate">New capture</a>`;
    }
    const g = await api.get("/api/gallery").catch(() => ({ campaigns: [] }));
    const camps = g.campaigns.filter((c) => c.hosts.length);
    const hosts = (camps.find((c) => c.campaign === sel.campaign) || camps[0] || { hosts: [] }).hosts;
    return `<select class="nv-select" id="nv-camp">${camps.map((c) => `<option value="${esc(c.campaign)}"${c.campaign === sel.campaign ? " selected" : ""}>${esc(c.label)}</option>`).join("")}</select>
      <select class="nv-select" id="nv-host">${hosts.map((hh) => `<option value="${esc(hh)}"${hh === sel.host ? " selected" : ""}>${esc(hh)}</option>`).join("")}</select>`;
  }
  function wirePicker() {
    const camp = document.getElementById("nv-camp"), host = document.getElementById("nv-host");
    if (!camp) return;
    camp.addEventListener("change", async () => {
      const g = await api.get("/api/gallery");
      const c = g.campaigns.find((x) => x.campaign === camp.value);
      store.sel = { campaign: camp.value, host: c.hosts[0], ground_truth: true };
      boot();
    });
    if (host) host.addEventListener("change", () => {
      store.sel = { campaign: camp.value, host: host.value, ground_truth: true };
      boot();
    });
  }

  async function currentSelection() {
    let sel = store.sel;
    if (sel && sel.upload_id) {
      try { sel.fc = await api.get(`/api/upload/${sel.upload_id}/forecast?host=${encodeURIComponent(sel.host)}`); return sel; }
      catch { sel = null; }
    }
    if (!sel) {
      const g = await api.get("/api/gallery");
      const c = g.campaigns.find((x) => x.attacked && x.hosts.length) || g.campaigns.find((x) => x.hosts.length);
      if (!c) throw new Error("No replay scenarios available from the backend.");
      sel = { campaign: c.campaign, host: c.hosts[0], ground_truth: true };
    }
    if (!sel.fc) sel.fc = await api.get(`/api/forecast?campaign=${encodeURIComponent(sel.campaign)}&host=${encodeURIComponent(sel.host)}`);
    store.sel = { campaign: sel.campaign, host: sel.host, upload_id: sel.upload_id, ground_truth: sel.fc.ground_truth };
    return sel;
  }

  /* ---------- page renderers ---------- */
  function forecastPage(content, d) {
    const risks = d.observed.map((o) => o.risk);
    const bands = bandIndices(d);
    const leadTxt = leadLabel(d);
    content.innerHTML =
      plainBlock(d.plain_language) +
      card("", `<div class="nv-grid">
        ${metric("Host", `<small>${esc(d.scenario.host)}</small>`)}
        ${metric("Peak onset risk", pct(d.peak_risk), d.peak_risk >= d.threshold)}
        ${metric("Alert threshold", d.threshold)}
        ${metric(d.ground_truth ? "Warning lead time" : "Ground truth", `<small>${esc(leadTxt)}</small>`)}
      </div>`) +
      card("Forecast risk trajectory (per 30 s window, +120 s horizon)",
        chart(risks, { threshold: d.threshold, bands }) +
        `<div class="nv-legend"><span class="l-risk">forecast risk</span><span class="l-thr">alert threshold</span>${d.ground_truth ? '<span class="l-atk">recorded attack window</span>' : ""}</div>
         <p class="nv-note">${d.ground_truth ? "Shaded = labelled attack windows in this capture." : "Uploaded capture; labels unknown — values are model predictions."}</p>`) +
      card("K-step forecast from the peak-risk window",
        `<table class="nv"><thead><tr><th>Horizon</th><th>Forecast risk</th><th>Predicted stage</th><th>ATT&amp;CK tactic</th><th>Confidence</th>${d.observed[0] && d.forecast[0].uncertainty != null ? "<th>±band</th>" : ""}</tr></thead>
        <tbody>${d.forecast.map((s) => `<tr><td>${esc(s.horizon)}</td><td>${pct(s.risk)}</td><td>${esc(s.stage)}</td><td>${esc(s.tactic || "-")}</td><td>${esc(s.confidence)}</td>${s.uncertainty != null ? `<td>±${pct(s.uncertainty)}</td>` : ""}</tr>`).join("")}</tbody></table>
        <p class="nv-note"><a class="nv-btn sec" href="/attack">See ATT&amp;CK trajectory</a> <a class="nv-btn sec" href="/investigate">Why this forecast</a> <a class="nv-btn sec" href="/network">Network evidence</a></p>`);
  }

  function networkPage(content, d) {
    const vol = d.observed.map((o) => o.flows), ports = d.observed.map((o) => o.distinctPorts);
    const ent = d.observed.map((o) => o.portEntropy), failed = d.observed.map((o) => o.failedConns);
    content.innerHTML =
      card("Traffic volume (flows / 30 s)", chart(vol, { color: "#0284c7" })) +
      card("Destination-port fan-out (distinct ports / 30 s) — a spike is a scan", chart(ports, { color: "#7c3aed" })) +
      `<div class="nv-grid">
        ${card("Port entropy", chart(ent, { color: "#0d9488" }))}
        ${card("Failed-connection ratio", chart(failed, { color: "#dc2626" }))}</div>` +
      card("Per-window telemetry (drives the forecast, not derived from labels)",
        `<table class="nv"><thead><tr><th>Window</th><th>Flows</th><th>Pkts/s</th><th>SYN</th><th>Dst ports</th><th>Port entropy</th><th>Unique dsts</th><th>Failed conn</th><th>Mean IAT</th></tr></thead>
        <tbody>${d.observed.slice().reverse().map((o) => `<tr><td>${hhmmss(o.t)}</td><td>${o.flows}</td><td>${o.pktRate}</td><td>${o.synCount}</td><td>${o.distinctPorts}</td><td>${o.portEntropy}</td><td>${o.uniqueDsts}</td><td>${o.failedConns}</td><td>${o.iat}</td></tr>`).join("")}</tbody></table>`);
  }

  function attackPage(content, d) {
    const stageChip = (s) => {
      const cls = s === "BENIGN" ? "" : (["EXFILTRATION", "IMPACT", "COMMAND AND CONTROL"].includes(s) ? "hot" : "warn");
      return `<span class="nv-chip ${cls}">${esc(s)}</span>`;
    };
    content.innerHTML =
      plainBlock(d.plain_language) +
      card("Predicted ATT&CK stage per observed window (+120 s forecast)",
        `<div>${d.observed.map((o) => `${stageChip(o.stage)}<span class="nv-muted" style="font-size:10px">${hhmmss(o.t)}</span> `).join(" ")}</div>
         <p class="nv-note">Stages can repeat, regress, or be unmapped — these are predictions of the forecasted future state, not confirmed actions.</p>`) +
      card("K-step stage trajectory (from the peak-risk window)",
        `<table class="nv"><thead><tr><th>Horizon</th><th>Predicted stage</th><th>ATT&amp;CK tactic</th><th>Forecast risk</th><th>Confidence</th></tr></thead>
        <tbody>${d.forecast.map((s) => `<tr><td>${esc(s.horizon)}</td><td>${stageChip(s.stage)}</td><td>${esc(s.tactic || "-")}</td><td>${pct(s.risk)}</td><td>${esc(s.confidence)}</td></tr>`).join("")}</tbody></table>`);
  }

  async function investigatePage(content, sel) {
    const win = sel.fc.focus_at || sel.fc.peak_at || (sel.fc.observed.slice(-1)[0] || {}).t;
    const path = sel.upload_id
      ? `/api/upload/${sel.upload_id}/explain?host=${encodeURIComponent(sel.host)}&window=${encodeURIComponent(win)}`
      : `/api/explain?campaign=${encodeURIComponent(sel.campaign)}&host=${encodeURIComponent(sel.host)}&window=${encodeURIComponent(win)}`;
    const d = await api.get(path);
    const maxc = Math.max(...d.shap.map((s) => Math.abs(s.contribution)), 1e-6);
    const maxa = Math.max(...d.attention.weights, 1e-6);
    content.innerHTML =
      card(`SHAP feature contributions (window ${hhmmss(win)} UTC)`,
        `<table class="nv"><thead><tr><th>Feature</th><th>Kind</th><th>Value</th><th>Contribution to forecast risk</th></tr></thead><tbody>
        ${d.shap.map((s) => `<tr><td>${esc(s.label)} <span class="nv-muted">(${esc(s.feature)})</span></td><td>${esc(s.kind)}</td><td>${s.value}</td>
          <td><div class="nv-bar"><i style="width:${(Math.abs(s.contribution) / maxc * 100).toFixed(0)}%;background:${s.contribution >= 0 ? "#dc2626" : "#0d9488"}"></i></div></td></tr>`).join("")}
        </tbody></table><p class="nv-note">Red = pushes risk up, teal = pushes risk down (SHAP over the predicted future state).</p>`) +
      card("Temporal attention over the 10-window history",
        `<table class="nv"><thead><tr><th>History window</th><th>Attention weight</th></tr></thead><tbody>
        ${d.attention.windows.map((w2, i) => `<tr><td>${hhmmss(w2)}</td><td><div class="nv-bar"><i style="width:${(d.attention.weights[i] / maxa * 100).toFixed(0)}%;background:#0284c7"></i></div></td></tr>`).join("")}
        </tbody></table>`) +
      card("Evidence sentence", `<p style="font-size:14px;line-height:1.6;margin:0">${esc(d.sentence)}</p>`);
  }

  async function validatePage(content) {
    const b = await api.get("/api/benchmark");
    const ev = await api.get("/api/evaluation").catch(() => ({ by_horizon: [], generalization: [] }));
    const rows = b.rows || [];
    content.innerHTML =
      card("Benchmark on the held-out chronological test split",
        `<table class="nv"><thead><tr><th>Model</th>${(b.horizons || []).map((x) => `<th>PR-AUC ${x}</th>`).join("")}${(b.horizons || []).map((x) => `<th>F1 ${x}</th>`).join("")}</tr></thead>
        <tbody>${rows.map((r) => `<tr><td>${esc(r.model)}</td>${r.pr_auc.map((v) => `<td>${v}</td>`).join("")}${r.f1.map((v) => `<td>${v}</td>`).join("")}</tr>`).join("")}</tbody></table>
        <p class="nv-note">${esc(b.takeaway || "")} Higher PR-AUC/F1 is better; lower FPR is better.</p>`) +
      card("Per-horizon: world model vs logistic-regression baseline",
        `<table class="nv"><thead><tr><th>Horizon</th><th>World model</th><th>Logistic regression</th></tr></thead>
        <tbody>${(ev.by_horizon || []).map((r) => `<tr><td>${esc(r.horizon)}</td>
          <td>${r.worldModel ? `PR-AUC ${r.worldModel.prauc} · F1 ${r.worldModel.f1} · FPR ${r.worldModel.fpr}` : "n/a"}</td>
          <td>${r.baseline ? `PR-AUC ${r.baseline.prauc} · F1 ${r.baseline.f1} · FPR ${r.baseline.fpr}` : "n/a"}</td></tr>`).join("")}</tbody></table>`) +
      card("Generalization",
        `<table class="nv"><thead><tr><th>Setting</th><th>Result</th></tr></thead>
        <tbody>${(ev.generalization || []).map((g) => `<tr><td>${esc(g.setting)}</td><td>${esc(g.result)}</td></tr>`).join("") || `<tr><td colspan="2" class="nv-muted">Not yet measured.</td></tr>`}</tbody></table>`);
  }

  async function modelPage(content) {
    const m = await api.get("/api/model-card");
    const rows = [["Parameters", m.parameters.toLocaleString()], ["Input features", m.input_features],
      ["ATT&CK stages", m.attack_stages], ["Horizons", (m.horizons || []).join(", ")], ["Attention", String(m.attention)],
      ["History", m.history], ["Window size", m.window_size], ["Alert threshold", m.threshold],
      ["Training data", m.training_data], ["Training", m.training], ["Explainability", m.explainability]];
    content.innerHTML =
      card("World-model card (read from the loaded checkpoint)",
        `<table class="nv"><tbody>${rows.map(([k, v]) => `<tr><th style="width:200px">${esc(k)}</th><td>${esc(v)}</td></tr>`).join("")}</tbody></table>`) +
      (m.packet_features && m.packet_features.length ? card("Packet-derived features",
        `<div>${m.packet_features.map((f) => `<span class="nv-chip">${esc(f)}</span>`).join("")}</div>
         <p class="nv-note">Available when a PCAP is uploaded; CSV captures show these as unavailable rather than fabricated.</p>`) : "");
  }

  async function simulatePage(content) {
    content.innerHTML = card("Upload a capture (CSV or PCAP)",
      `<p class="nv-note" style="margin-top:0">Upload a CICFlowMeter CSV or a PCAP/PCAPNG capture. It is cleaned and windowed locally, then forecast by the world model — nothing leaves this machine.</p>
       <div class="nv-controls" style="margin-top:12px">
         <input type="file" class="nv-file" id="nvFile" accept=".csv,.pcap,.pcapng">
         <button class="nv-btn" id="nvRun">Analyze capture</button></div>
       <div id="nvStages" style="margin-top:14px"></div>`) +
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
          stagesEl.appendChild(row);
          await new Promise((r) => setTimeout(r, 220));
          row.querySelector(".nv-dot").classList.replace("run", "done");
        }
        const host = res.hosts[0];
        const fc = await api.get(`/api/upload/${res.upload_id}/forecast?host=${encodeURIComponent(host)}`);
        store.sel = { campaign: "upload", host, upload_id: res.upload_id, ground_truth: false };
        const rb = h(`<div id="nv-content"></div>`);
        resultEl.appendChild(rb); forecastPage(rb, { ...fc, scenario: fc.scenario || { host } });
        resultEl.insertBefore(h(`<p class="nv-note">Now open <a href="/forecast">Forecast</a>, <a href="/network">Network</a>, <a href="/attack">ATT&amp;CK</a> or <a href="/investigate">Investigate</a> — they all follow this capture.</p>`), rb);
      } catch (e) {
        stagesEl.innerHTML = `<p class="nv-err">Upload failed: ${esc(e.message)}</p>`;
      } finally { runEl.disabled = false; }
    });
  }

  async function homePage(content) {
    let sel;
    try { sel = await currentSelection(); } catch (e) { content.innerHTML = `<p class="nv-err">${esc(e.message)}</p>`; return; }
    const d = sel.fc;
    content.innerHTML =
      plainBlock(d.plain_language) +
      card("", `<div class="nv-grid">
        ${metric("Active scenario", `<small>${esc(d.scenario.label)}</small>`)}
        ${metric("Host", `<small>${esc(d.scenario.host)}</small>`)}
        ${metric("Peak onset risk", pct(d.peak_risk), d.peak_risk >= d.threshold)}
        ${metric(d.ground_truth ? "Warning lead time" : "Mode", d.ground_truth ? `<small>${leadLabel(d)}</small>` : "<small>uploaded</small>")}
      </div>`) +
      card("Forecast risk trajectory", chart(d.observed.map((o) => o.risk), { threshold: d.threshold, bands: bandIndices(d) })) +
      card("Explore", `<p class="nv-note" style="margin-top:0">Every page below is driven by this capture — no fixture data.</p>
        <p><a class="nv-btn sec" href="/forecast">Forecast</a> <a class="nv-btn sec" href="/network">Network</a>
        <a class="nv-btn sec" href="/attack">ATT&amp;CK</a> <a class="nv-btn sec" href="/investigate">Investigate</a>
        <a class="nv-btn sec" href="/validate">Validate</a> <a class="nv-btn sec" href="/model">Model</a>
        <a class="nv-btn" href="/simulate">Upload a capture</a></p>`);
  }

  /* ---------- boot ---------- */
  async function boot() {
    try { await api.get("/api/health"); }
    catch {
      shell("Backend offline", "The live model API is not reachable.").innerHTML =
        `<div class="nv-card"><p class="nv-err">Cannot reach the model backend at ${esc(BASE)}.<br>
        Start it from the model repo venv:<br><code>python -m uvicorn api.server:app --port 8000</code></p></div>`;
      return;
    }
    try {
      if (route === "home") { shell("NetraVerse", "Network attack forecasting — live world model"); return void homePage(document.getElementById("nv-content")); }
      if (route === "simulate") { shell("Simulate", "Upload a capture and watch the processing pipeline"); return void simulatePage(document.getElementById("nv-content")); }
      if (route === "validate") { shell("Validate", "Benchmarks, per-horizon metrics and generalization"); return void validatePage(document.getElementById("nv-content")); }
      if (route === "model") { shell("Model", "World-model architecture and training, from the checkpoint"); return void modelPage(document.getElementById("nv-content")); }

      const sel = await currentSelection();
      const ctrl = await pickerControls(sel);
      const titles = {
        forecast: ["Forecast", "Per-host onset-risk forecast and warning lead time"],
        network: ["Network", "Per-window traffic telemetry behind the forecast"],
        attack: ["ATT&CK trajectory", "Predicted MITRE stage progression"],
        investigate: ["Investigate", "SHAP contributions, attention and evidence"],
      };
      const [t, s] = titles[route] || ["Live", "World-model output"];
      const content = shell(t, s, ctrl);
      wirePicker();
      if (route === "forecast") forecastPage(content, sel.fc);
      else if (route === "network") networkPage(content, sel.fc);
      else if (route === "attack") attackPage(content, sel.fc);
      else if (route === "investigate") await investigatePage(content, sel);
      else homePage(content);
    } catch (e) {
      const c = document.getElementById("nv-content") || root();
      c.innerHTML = `<div class="nv-card"><p class="nv-err">${esc(e.message)}</p></div>`;
    }
  }

  window.NV_boot = boot;
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot); else boot();
})();
