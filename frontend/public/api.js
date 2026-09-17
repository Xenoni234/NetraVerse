/*
 * NetraVerse live-data client.
 * Connects the Stitch pages to the FastAPI backend (the real world model).
 * It injects a styled "live" panel (matching app-shell.css) into each page's
 * <main>, so every screen shows real model output, and provides a working
 * CSV/PCAP upload with visible processing stages. Additive: the Stitch visuals
 * remain below.
 */
(() => {
  const BASE = (window.NV_API_BASE || "http://localhost:8000").replace(/\/$/, "");
  const route = document.body.dataset.route || "home";
  const store = {
    get sel() { try { return JSON.parse(sessionStorage.getItem("nv_sel") || "null"); } catch { return null; } },
    set sel(v) { sessionStorage.setItem("nv_sel", JSON.stringify(v)); },
  };

  const css = `
  .nv-live{font-family:"IBM Plex Sans",system-ui,sans-serif;background:#fff;border:1px solid #e2e8f0;
    border-radius:3px;margin:16px 0;color:#0f172a}
  .nv-live h2{font-size:13px;letter-spacing:.06em;text-transform:uppercase;color:#0369a1;margin:0;
    padding:10px 14px;border-bottom:1px solid #e2e8f0;font-weight:600}
  .nv-body{padding:14px}
  .nv-row{display:flex;flex-wrap:wrap;gap:14px}
  .nv-metric{flex:1 1 150px;background:#f8fafc;border:1px solid #e2e8f0;padding:10px 12px}
  .nv-metric .k{font-size:11px;color:#475569;text-transform:uppercase;letter-spacing:.04em}
  .nv-metric .v{font-size:22px;font-family:"IBM Plex Mono",ui-monospace,monospace;margin-top:4px}
  .nv-note{font-size:12px;color:#475569;margin-top:8px}
  .nv-live table{width:100%;border-collapse:collapse;font-size:12px;margin-top:6px}
  .nv-live th,.nv-live td{border-bottom:1px solid #eef2f6;padding:6px 8px;text-align:left;
    font-family:"IBM Plex Mono",ui-monospace,monospace}
  .nv-live th{color:#475569;font-weight:600;text-transform:uppercase;font-size:10px;letter-spacing:.04em}
  .nv-btn{background:#0284c7;color:#fff;border:none;border-radius:2px;padding:8px 14px;font-size:13px;
    cursor:pointer;font-weight:600}
  .nv-btn:disabled{background:#94a3b8;cursor:default}
  .nv-select,.nv-file{border:1px solid #cbd5e1;border-radius:2px;padding:7px 10px;font-size:13px;background:#fff}
  .nv-stage{display:flex;align-items:center;gap:10px;padding:7px 0;border-bottom:1px solid #f1f5f9}
  .nv-dot{width:10px;height:10px;border-radius:50%;background:#cbd5e1;flex:none}
  .nv-dot.done{background:#0d9488}.nv-dot.err{background:#dc2626}.nv-dot.run{background:#f59e0b}
  .nv-bar{height:8px;background:#e2e8f0;border-radius:2px;overflow:hidden}
  .nv-bar>i{display:block;height:100%;background:#0284c7}
  .nv-chip{display:inline-block;padding:2px 8px;border:1px solid #cbd5e1;border-radius:2px;font-size:11px;
    font-family:"IBM Plex Mono",monospace;margin:2px}
  .nv-err{color:#b91c1c;font-size:13px}
  .nv-muted{color:#64748b}
  `;
  const style = document.createElement("style"); style.textContent = css; document.head.appendChild(style);

  const api = {
    async get(path) { const r = await fetch(BASE + path); if (!r.ok) throw new Error((await r.json()).detail || r.statusText); return r.json(); },
    async upload(file) { const fd = new FormData(); fd.append("file", file); const r = await fetch(BASE + "/api/upload", { method: "POST", body: fd }); if (!r.ok) throw new Error((await r.json()).detail || r.statusText); return r.json(); },
  };

  const h = (html) => { const t = document.createElement("template"); t.innerHTML = html.trim(); return t.content.firstElementChild; };
  const pct = (x) => (x == null ? "n/a" : (x * 100).toFixed(1) + "%");
  const esc = (s) => String(s).replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));

  function mount(title) {
    const main = document.querySelector("main") || document.body;
    const panel = h(`<section class="nv-live"><h2>${title} · live model</h2><div class="nv-body"><p class="nv-muted">Loading live data from the world model...</p></div></section>`);
    main.insertBefore(panel, main.firstChild);
    return panel.querySelector(".nv-body");
  }

  function sparkline(values, threshold) {
    const w = 640, ht = 90, n = values.length; if (!n) return "";
    const max = Math.max(1e-6, ...values);
    const pts = values.map((v, i) => `${(i / Math.max(1, n - 1)) * w},${ht - (v / max) * (ht - 10) - 5}`).join(" ");
    const thY = threshold ? ht - (Math.min(threshold, max) / max) * (ht - 10) - 5 : null;
    return `<svg viewBox="0 0 ${w} ${ht}" width="100%" height="${ht}" preserveAspectRatio="none">
      ${thY != null ? `<line x1="0" y1="${thY}" x2="${w}" y2="${thY}" stroke="#f59e0b" stroke-dasharray="4 4" stroke-width="1"/>` : ""}
      <polyline points="${pts}" fill="none" stroke="#0284c7" stroke-width="2"/></svg>`;
  }

  const metric = (k, v) => `<div class="nv-metric"><div class="k">${k}</div><div class="v">${v}</div></div>`;

  function renderForecast(body, d) {
    const risks = d.observed.map((o) => o.risk);
    body.innerHTML = `
      <div class="nv-row">
        ${metric("Host", esc(d.scenario.host))}
        ${metric("Peak onset risk", pct(d.peak_risk))}
        ${metric("Alert threshold", d.threshold)}
        ${metric(d.ground_truth ? "Warning lead time" : "Ground truth", d.ground_truth ? (d.lead_time_s != null && d.lead_time_s > 0 ? d.lead_time_s + " s early" : (d.first_alert ? "at onset" : "no alert")) : "unknown (upload)")}
      </div>
      <div style="margin-top:14px">${sparkline(risks, d.threshold)}
        <div class="nv-note">Forecast risk per 30 s window (+120 s horizon). ${d.ground_truth ? "Red-dashed = alert threshold; shaded windows = recorded attack." : "Uploaded capture; labels unknown, values are model predictions."}</div>
      </div>
      <table><thead><tr><th>Horizon</th><th>Forecast risk</th><th>Predicted stage</th><th>ATT&amp;CK</th><th>Confidence</th></tr></thead>
        <tbody>${d.forecast.map((s) => `<tr><td>${s.horizon}</td><td>${pct(s.risk)}</td><td>${esc(s.stage)}</td><td>${esc(s.tactic || "-")}</td><td>${esc(s.confidence)}</td></tr>`).join("")}</tbody></table>`;
  }

  function renderNetwork(body, d) {
    const ports = d.observed.map((o) => o.distinctPorts), vol = d.observed.map((o) => o.flows);
    body.innerHTML = `
      <div class="nv-note">Traffic volume (flows / 30 s)</div>${sparkline(vol)}
      <div class="nv-note" style="margin-top:12px">Destination-port fan-out (distinct ports / 30 s) - a spike is a scan</div>${sparkline(ports)}
      <table style="margin-top:10px"><thead><tr><th>Window</th><th>Flows</th><th>Pkts/s</th><th>SYN</th><th>Dst ports</th><th>Port entropy</th><th>Failed conn</th></tr></thead>
      <tbody>${d.observed.slice(-8).reverse().map((o) => `<tr><td>${o.t.slice(11, 19)}</td><td>${o.flows}</td><td>${o.pktRate}</td><td>${o.synCount}</td><td>${o.distinctPorts}</td><td>${o.portEntropy}</td><td>${o.failedConns}</td></tr>`).join("")}</tbody></table>`;
  }

  function renderStage(body, d) {
    body.innerHTML = `<div class="nv-note">Predicted ATT&amp;CK stage per window (+120 s). Stages can repeat, move back, or be unmapped - these are predictions, not confirmed actions.</div>
      <div style="margin-top:8px">${d.observed.map((o) => `<span class="nv-chip">${o.t.slice(11,19)} · ${esc(o.stage)}</span>`).join("")}</div>`;
  }

  async function renderExplain(body, sel) {
    const win = sel.fc.focus_at || sel.fc.peak_at || sel.fc.observed[sel.fc.observed.length - 1].t;
    const path = sel.upload_id
      ? `/api/upload/${sel.upload_id}/explain?host=${encodeURIComponent(sel.host)}&window=${encodeURIComponent(win)}`
      : `/api/explain?campaign=${encodeURIComponent(sel.campaign)}&host=${encodeURIComponent(sel.host)}&window=${encodeURIComponent(win)}`;
    try {
      const d = await api.get(path);
      const maxc = Math.max(...d.shap.map((s) => Math.abs(s.contribution)), 1e-6);
      body.innerHTML = `<div class="nv-note">Why the model forecast this (window ${esc(win.slice(11,19))}). SHAP contribution per feature; flow vs packet-derived.</div>
        <table><thead><tr><th>Feature</th><th>Kind</th><th>Value</th><th>SHAP contribution</th></tr></thead><tbody>
        ${d.shap.map((s) => `<tr><td>${esc(s.label)} (${esc(s.feature)})</td><td>${s.kind}</td><td>${s.value}</td>
          <td><div class="nv-bar"><i style="width:${(Math.abs(s.contribution)/maxc*100).toFixed(0)}%;background:${s.contribution>=0?"#dc2626":"#0d9488"}"></i></div></td></tr>`).join("")}
        </tbody></table>
        <div class="nv-note" style="margin-top:10px">${esc(d.sentence)}</div>`;
    } catch (e) { body.innerHTML = `<p class="nv-err">Explanation unavailable: ${esc(e.message)}</p>`; }
  }

  async function renderValidate(body) {
    const b = await api.get("/api/benchmark");
    const ev = await api.get("/api/evaluation").catch(() => ({ by_horizon: [], generalization: [] }));
    const rows = b.rows || [];
    body.innerHTML = `<div class="nv-note">Benchmark on the held-out test split. Higher PR-AUC / F1 is better; lower FPR is better.</div>
      <table><thead><tr><th>Model</th>${b.horizons.map((x) => `<th>PR-AUC ${x}</th>`).join("")}${b.horizons.map((x) => `<th>F1 ${x}</th>`).join("")}</tr></thead>
      <tbody>${rows.map((r) => `<tr><td>${esc(r.model)}</td>${r.pr_auc.map((v) => `<td>${v}</td>`).join("")}${r.f1.map((v) => `<td>${v}</td>`).join("")}</tr>`).join("")}</tbody></table>
      <div class="nv-note" style="margin-top:8px">${esc(b.takeaway || "")}</div>
      <div class="nv-note" style="margin-top:14px">Per-horizon: world model vs logistic-regression baseline (PR-AUC / F1 / FPR)</div>
      <table><thead><tr><th>Horizon</th><th>World model</th><th>Logistic regression</th></tr></thead>
      <tbody>${(ev.by_horizon || []).map((r) => `<tr><td>${r.horizon}</td>
        <td>${r.worldModel ? `PR-AUC ${r.worldModel.prauc} · F1 ${r.worldModel.f1} · FPR ${r.worldModel.fpr}` : "n/a"}</td>
        <td>${r.baseline ? `PR-AUC ${r.baseline.prauc} · F1 ${r.baseline.f1} · FPR ${r.baseline.fpr}` : "n/a"}</td></tr>`).join("")}</tbody></table>
      <div class="nv-note" style="margin-top:14px">Generalization</div>
      <table><thead><tr><th>Setting</th><th>Result</th></tr></thead>
      <tbody>${(ev.generalization || []).map((g) => `<tr><td>${esc(g.setting)}</td><td>${esc(g.result)}</td></tr>`).join("")}</tbody></table>`;
  }

  async function renderModel(body) {
    const m = await api.get("/api/model-card");
    const rows = [["Parameters", m.parameters.toLocaleString()], ["Input features", m.input_features],
      ["ATT&CK stages", m.attack_stages], ["Horizons", m.horizons.join(", ")], ["Attention", m.attention],
      ["History", m.history], ["Window size", m.window_size], ["Alert threshold", m.threshold],
      ["Training data", m.training_data], ["Training", m.training], ["Explainability", m.explainability]];
    body.innerHTML = `<table><tbody>${rows.map(([k, v]) => `<tr><th style="width:180px">${k}</th><td>${esc(v)}</td></tr>`).join("")}</tbody></table>`;
  }

  async function uploadWidget(body) {
    body.innerHTML = `
      <div class="nv-note">Upload a CICFlowMeter CSV or a PCAP/PCAPNG capture. It is cleaned and windowed locally, then forecast by the world model. Nothing leaves this machine.</div>
      <div class="nv-row" style="align-items:center;margin-top:10px">
        <input type="file" class="nv-file" id="nvFile" accept=".csv,.pcap,.pcapng">
        <button class="nv-btn" id="nvRun">Analyze capture</button>
      </div>
      <div id="nvStages" style="margin-top:12px"></div>
      <div id="nvResult" style="margin-top:12px"></div>`;
    const fileEl = body.querySelector("#nvFile"), runEl = body.querySelector("#nvRun");
    const stagesEl = body.querySelector("#nvStages"), resultEl = body.querySelector("#nvResult");
    runEl.addEventListener("click", async () => {
      if (!fileEl.files.length) { stagesEl.innerHTML = `<p class="nv-err">Choose a CSV or PCAP file first.</p>`; return; }
      runEl.disabled = true; resultEl.innerHTML = ""; stagesEl.innerHTML = `<div class="nv-stage"><span class="nv-dot run"></span>Processing capture...</div>`;
      try {
        const res = await api.upload(fileEl.files[0]);
        stagesEl.innerHTML = "";
        for (const s of res.stages) {
          const row = h(`<div class="nv-stage"><span class="nv-dot run"></span><div><b>${esc(s.name)}</b> <span class="nv-muted">- ${esc(s.detail)}</span></div></div>`);
          stagesEl.appendChild(row);
          await new Promise((r) => setTimeout(r, 250));
          row.querySelector(".nv-dot").classList.replace("run", "done");
        }
        const host = res.hosts[0];
        const fc = await api.get(`/api/upload/${res.upload_id}/forecast?host=${encodeURIComponent(host)}`);
        store.sel = { campaign: "upload", host, upload_id: res.upload_id, peak_at: fc.peak_at, ground_truth: false };
        const rb = h(`<div class="nv-live"><h2>Forecast · ${esc(host)}</h2><div class="nv-body"></div></div>`);
        resultEl.appendChild(rb); renderForecast(rb.querySelector(".nv-body"), fc);
        resultEl.appendChild(h(`<p class="nv-note">Open the Forecast, Network, ATT&amp;CK and Investigate pages to see this capture across the product.</p>`));
      } catch (e) {
        stagesEl.innerHTML = `<p class="nv-err">Upload failed: ${esc(e.message)}</p>`;
      } finally { runEl.disabled = false; }
    });
  }

  async function currentSelection() {
    let sel = store.sel;
    if (sel && sel.campaign === "upload") {
      try { const fc = await api.get(`/api/upload/${sel.upload_id}/forecast?host=${encodeURIComponent(sel.host)}`); return { ...sel, fc }; }
      catch { sel = null; }
    }
    if (!sel) {
      const g = await api.get("/api/gallery");
      const c = g.campaigns.find((x) => x.attacked && x.hosts.length) || g.campaigns.find((x) => x.hosts.length);
      sel = { campaign: c.campaign, host: c.hosts[0], ground_truth: true };
    }
    if (!sel.fc) sel.fc = await api.get(`/api/forecast?campaign=${encodeURIComponent(sel.campaign)}&host=${encodeURIComponent(sel.host)}`);
    sel.peak_at = sel.fc.peak_at; store.sel = { campaign: sel.campaign, host: sel.host, upload_id: sel.upload_id, peak_at: sel.peak_at, ground_truth: sel.fc.ground_truth };
    return sel;
  }

  async function boot() {
    try {
      await api.get("/api/health");
    } catch {
      const body = mount("Backend");
      body.innerHTML = `<p class="nv-err">Cannot reach the model backend at ${BASE}. Start it with:<br><code>uvicorn api.server:app --port 8000</code> in the model repo venv.</p>`;
      return;
    }
    if (route === "simulate" || route === "home") {
      const body = mount(route === "home" ? "Upload a capture" : "Run a capture");
      await uploadWidget(body);
      if (route === "home") { const b2 = mount("Latest forecast"); try { const s = await currentSelection(); renderForecast(b2, s.fc); } catch (e) { b2.innerHTML = `<p class="nv-err">${esc(e.message)}</p>`; } }
      return;
    }
    const body = mount({ forecast: "Forecast", network: "Network telemetry", attack: "Attack trajectory", investigate: "Explanation", validate: "Validation", model: "Model card" }[route] || "Live");
    try {
      if (route === "validate") return void (await renderValidate(body));
      if (route === "model") return void (await renderModel(body));
      const sel = await currentSelection();
      if (route === "forecast") renderForecast(body, sel.fc);
      else if (route === "network") renderNetwork(body, sel.fc);
      else if (route === "attack") renderStage(body, sel.fc);
      else if (route === "investigate") await renderExplain(body, sel);
    } catch (e) { body.innerHTML = `<p class="nv-err">${esc(e.message)}</p>`; }
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot); else boot();
})();
