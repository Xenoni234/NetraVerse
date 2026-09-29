/* NetraVerse console controller */
(() => {
  const { WIN, STAGES, buildScenario, campaignRisk, modifyQuality, LIVE_TEMPLATES, HOSTS } = window.NV;
  const LIVE_PRE = 4;   // windows of gradual pre-alert rise before the live forecast fires
  const $ = (id) => document.getElementById(id);
  const COL = { red: "#ff4d4f", amber: "#f0a52c", teal: "#35c2b5", green: "#3ecf7a",
    blue: "#4c9bff", violet: "#a57bff", muted: "#8a93a1", dim: "#5d6573", line: "#262c36", bg: "#0c0e12" };
  const CAMP_COLORS = [COL.red, COL.amber, COL.violet, COL.blue, COL.green];

  const PLOT_CFG = { displayModeBar: false, responsive: true };
  const BASE_LAYOUT = {
    paper_bgcolor: "transparent", plot_bgcolor: "transparent",
    font: { family: "JetBrains Mono, monospace", color: COL.muted, size: 11 },
    margin: { l: 46, r: 16, t: 10, b: 64 },
    xaxis: { gridcolor: COL.line, zerolinecolor: COL.line, title: { text: "minutes since capture start", font: { size: 11 } } },
    yaxis: { gridcolor: COL.line, zerolinecolor: COL.line, range: [0, 1.02], title: { text: "P(attack ≤ 300 s)", font: { size: 11 } }, tickformat: ".0%" },
    legend: { orientation: "h", y: -0.28, x: 0, font: { size: 10 }, bgcolor: "transparent" },
    shapes: [{ type: "line", x0: 0, x1: 1, xref: "paper", y0: 0.43, y1: 0.43, line: { color: COL.muted, width: 1, dash: "dot" } }],
    annotations: [{ x: 0, xref: "paper", y: 0.43, xanchor: "left", yanchor: "bottom", text: "alert threshold 0.43", showarrow: false, font: { size: 9, color: COL.muted } }],
  };

  // ---------- state ----------
  let mode = "csv";
  let scn = null;                 // current scenario (has realHosts/realFlows)
  let cursor = 0;                 // current window index (monotonic in live)
  let playing = false;
  let timer = null;
  let speed = 2;
  const decisions = {};           // campId -> decision record
  const forecasts = {};           // campId -> {alertAt, handled}
  let mitCount = 0;
  let paused = false;
  let pendingCamp = null;
  let liveSince = 0, livePoll = null, liveRun = 0, liveReady = false;
  const liveCampaigns = [];
  let topoMod = null;             // 3D bundle module

  // ---------- helpers ----------
  const fmtClock = (i) => { const s = Math.max(0, i) * WIN; return `t+${String(Math.floor(s / 60)).padStart(2, "0")}:${String(s % 60).padStart(2, "0")}`; };
  const speedMs = () => ({ 1: 1400, 2: 800, 4: 420 }[speed]);
  const isIP = (s) => /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(s);
  const subnetOf = (ip) => ip.split(".").slice(0, 3).join(".") + ".0/24";

  function activeCampaigns() { return mode === "live" ? liveCampaigns.filter((c) => !c.done) : (scn ? scn.campaigns : []); }
  function allCampaigns() { return mode === "live" ? liveCampaigns : (scn ? scn.campaigns : []); }

  function riskAt(c, i) {
    const d = decisions[c.id];
    const st = d
      ? { decision: d.decision, quality: d.quality, decidedAt: d.decidedAt, riskAtDecision: d.riskAtDecision, stoppedAt: d.stoppedAt }
      : { decision: null };
    return campaignRisk(c, i, st);
  }
  function netRiskAt(i) {
    let m = 0.02 + 0.008 * Math.sin(i * 1.3);
    for (const c of activeCampaigns()) m = Math.max(m, riskAt(c, i));
    return Math.min(1, m);
  }

  // ---------- real host / flow model ----------
  // default monitored network (used for live and before a file is parsed)
  function defaultHostsFlows() {
    const hosts = [];
    hosts.push({ ip: HOSTS.gateway.ip, subnet: subnetOf(HOSTS.gateway.ip), flows: 900 });
    HOSTS.servers.forEach((h, i) => hosts.push({ ip: h.ip, subnet: subnetOf(h.ip), flows: 400 - i * 20 }));
    HOSTS.ext.forEach((h, i) => hosts.push({ ip: h.ip, subnet: subnetOf(h.ip), flows: 120 - i * 10 }));
    const gw = HOSTS.gateway.ip;
    const flows = [];
    HOSTS.servers.forEach((h) => { flows.push({ src: h.ip, dst: gw, count: 60 }); flows.push({ src: gw, dst: h.ip, count: 50 }); });
    // some east-west benign traffic
    flows.push({ src: HOSTS.servers[3].ip, dst: HOSTS.servers[0].ip, count: 40 });
    flows.push({ src: HOSTS.servers[1].ip, dst: HOSTS.servers[2].ip, count: 35 });
    flows.push({ src: HOSTS.servers[4].ip, dst: HOSTS.servers[5].ip, count: 30 });
    return { hosts, flows };
  }

  // small stats helpers
  const mean = (a) => (a.length ? a.reduce((s, x) => s + x, 0) / a.length : 0);
  const clamp = (v, lo, hi) => Math.max(lo, Math.min(hi, v));
  const pct = (v) => `${Math.round(v * 100)}%`;
  function groupBy(rows, key) { const m = new Map(); for (const r of rows) { const k = key(r); (m.get(k) || m.set(k, []).get(k)).push(r); } return m; }
  function topKey(rows, key) { const c = new Map(); for (const r of rows) { const k = key(r); c.set(k, (c.get(k) || 0) + 1); } let best = null, n = -1; for (const [k, v] of c) if (v > n) { n = v; best = k; } return best; }

  // parse CSV text -> {hosts, flows, campaigns, nWindows}
  function parseCsv(text) {
    const lines = text.split(/\r?\n/);
    if (lines.length < 2) return { ...defaultHostsFlows(), campaigns: null, nWindows: null };
    const h = lines[0].split(",").map((s) => s.trim().toLowerCase());
    const col = (name, alt) => { let i = h.indexOf(name); if (i < 0 && alt) i = h.indexOf(alt); return i; };
    let si = col("src_ip", "source"), di = col("dst_ip", "destination");
    const ti = col("ts_start", "timestamp"), pi = col("dport", "dst_port");
    const syi = col("syn"), ri = col("rst"), fbi = col("fwd_bytes"), li = col("label");
    if (si < 0 || di < 0) {
      const row = (lines[1] || "").split(",");
      const idxs = row.map((v, k) => (isIP(v.trim()) ? k : -1)).filter((k) => k >= 0);
      si = idxs[0] ?? 2; di = idxs[1] ?? 3;
    }
    const rows = [];
    for (let k = 1; k < lines.length; k++) {
      const p = lines[k].split(","); const s = (p[si] || "").trim(), d = (p[di] || "").trim();
      if (!isIP(s) || !isIP(d)) continue;
      rows.push({ s, d, dport: pi >= 0 ? (p[pi] || "").trim() : "", ts: ti >= 0 ? parseFloat(p[ti]) : k,
        syn: syi >= 0 ? +p[syi] || 0 : 0, rst: ri >= 0 ? +p[ri] || 0 : 0, fwdb: fbi >= 0 ? +p[fbi] || 0 : 0,
        label: li >= 0 ? (p[li] || "").trim() : "" });
    }
    if (!rows.length) return { ...defaultHostsFlows(), campaigns: null, nWindows: null };

    const hostC = new Map(), pairC = new Map();
    for (const r of rows) {
      hostC.set(r.s, (hostC.get(r.s) || 0) + 1); hostC.set(r.d, (hostC.get(r.d) || 0) + 1);
      const key = r.s + "|" + r.d; pairC.set(key, (pairC.get(key) || 0) + 1);
    }
    const hosts = [...hostC.entries()].sort((a, b) => b[1] - a[1]).slice(0, 26)
      .map(([ip, flows]) => ({ ip, subnet: subnetOf(ip), flows }));
    const flows = [...pairC.entries()].sort((a, b) => b[1] - a[1]).slice(0, 70)
      .map(([key, count]) => { const [src, dst] = key.split("|"); return { src, dst, count }; });

    const t0 = Math.min(...rows.map((r) => r.ts).filter((x) => isFinite(x)));
    const maxW = Math.max(...rows.map((r) => Math.floor((r.ts - t0) / WIN)).filter((x) => isFinite(x)));
    const nWindows = Math.max(12, Math.min(40, (isFinite(maxW) ? maxW : 20) + 2));
    const campaigns = detectCampaigns(rows, t0);
    return { hosts, flows, campaigns: campaigns.length ? campaigns : null, nWindows };
  }

  // detect attack campaigns from the file's own feature calculation (fan-out, port hammering, timing)
  function detectCampaigns(rows, t0) {
    const camps = []; let idx = 0;
    const win = (r) => Math.floor((r.ts - t0) / WIN);
    const bySrc = groupBy(rows, (r) => r.s);
    for (const [s, ar] of bySrc) {
      const dsts = new Set(ar.map((r) => r.d)), ports = new Set(ar.map((r) => r.dport));
      // --- PortScan / service discovery: wide fan-out across hosts + ports ---
      if (dsts.size >= 15 && ports.size >= 15) {
        const wd = new Map();
        for (const r of ar) { const w = win(r); (wd.get(w) || wd.set(w, new Set()).get(w)).add(r.d); }
        const onsetW = [...wd.keys()].sort((a, b) => a - b).find((w) => wd.get(w).size >= 8);
        const synR = mean(ar.map((r) => r.syn));
        const lbl = topKey(ar.filter((r) => r.label && !/benign/i.test(r.label)), (r) => r.label) || "";
        camps.push(mkCsvCamp(idx++, "T1046", "Reconnaissance", 1, /scan|port/i.test(lbl) ? "Network service scan" : "Network service scan",
          s, subnetOf(topKey(ar, (r) => r.d)), onsetW != null ? onsetW : win(ar[0]),
          [[`distinct destinations contacted (${dsts.size})`, clamp(dsts.size / 600, 0.08, 0.42), 1],
          [`distinct destination ports (${ports.size})`, clamp(ports.size / 2000, 0.06, 0.3), 1],
          [`SYN-only flow ratio (${pct(synR)})`, clamp(synR * 0.25, 0.03, 0.22), 1],
          ["mean flow duration", -0.12, -1]],
          { reco: `Block source ${s} at the core gateway ACL`, action: "Block source at gateway", cmd: `iptables -A FORWARD -s ${s} -j DROP` },
          `Source ${s} contacted ${dsts.size} distinct hosts across ${ports.size} ports in short SYN-driven flows.`));
      }
      // --- Brute force: heavy flows to one host on a specific auth port ---
      // (evaluated per auth port so port-scan noise to the same host doesn't mask it)
      const byDst = groupBy(ar, (r) => r.d);
      for (const [d, vr] of byDst) {
        for (const authPort of ["22", "21", "3389", "23"]) {
          const pr = vr.filter((r) => r.dport === authPort);
          // require sustained volume AND that the auth port dominates this host's traffic
          // (so port-scan spillover onto 22/3389 is not mistaken for a brute force)
          if (pr.length < 40 || pr.length < 0.35 * vr.length) continue;
          const wf = new Map(); for (const r of pr) { const w = win(r); wf.set(w, (wf.get(w) || 0) + 1); }
          const onsetW = [...wf.keys()].sort((a, b) => a - b).find((w) => wf.get(w) >= 15);
          const rstR = mean(pr.map((r) => r.rst)), avgb = Math.round(mean(pr.map((r) => r.fwdb)));
          const svc = authPort === "3389" ? "RDP" : authPort === "21" ? "FTP" : authPort === "23" ? "Telnet" : "SSH";
          camps.push(mkCsvCamp(idx++, "T1110", "Credential Access", 2, `${svc} brute force`,
            s, d, onsetW != null ? onsetW : win(pr[0]),
            [[`repeated dst port ${authPort} (${pr.length} flows)`, clamp(pr.length / 3000, 0.12, 0.4), 1],
            ["single-target concentration", 0.24, 1],
            [`small uniform payload (${avgb} B)`, clamp(1 - avgb / 2000, 0.05, 0.2), 1],
            [`connection reset ratio (${pct(rstR)})`, clamp(rstR * 0.3, 0.03, 0.2), 1]],
            { reco: `Rate-limit ${s} and enforce credential lockout on ${d}`, action: `Rate-limit + credential lockout on ${d}`, cmd: `fail2ban-client set sshd banip ${s}; ufw limit ${authPort}/tcp` },
            `Source ${s} drove ${pr.length} ${svc} attempts at ${d} on port ${authPort} with small uniform payloads.`));
          break; // one brute-force campaign per target host
        }
      }
    }
    camps.sort((a, b) => a.alertAt - b.alertAt);
    return camps.slice(0, 4);
  }

  function mkCsvCamp(i, mitre, tactic, stage, name, src, dst, onsetW, shap, act, reasoning) {
    const onset = Math.max(2, onsetW);
    const alertAt = Math.max(1, onset - 2);
    return {
      id: "csv_" + i, name, mitre, tactic, stage, src, dst,
      srcLabel: src, dstLabel: dst.includes("/") ? "server subnet" : dst,
      alertAt, onset: Math.max(alertAt + 1, onset), peak: 0.92,
      leadSec: (Math.max(alertAt + 1, onset) - alertAt) * WIN,
      reco: act.reco, action: act.action, cmd: act.cmd, shap, reasoning,
    };
  }

  function hostIps() { return new Set((scn.realHosts || []).map((h) => h.ip)); }
  function busiest(n = 1, exclude = new Set()) {
    return (scn.realHosts || []).filter((h) => !exclude.has(h.ip)).slice(0, n).map((h) => h.ip);
  }
  // resolve a campaign's src + target IPs onto hosts that exist in the file
  function resolveCampaign(c) {
    const ips = hostIps();
    let src = c.src;
    if (!ips.has(src)) src = busiest(1)[0] || c.src;
    let targets = [];
    if (c.dst.includes("/")) {
      // subnet: pick a few real hosts in that subnet, else top hosts
      const sub = c.dst;
      targets = (scn.realHosts || []).filter((h) => h.subnet === sub && h.ip !== src).slice(0, 4).map((h) => h.ip);
      if (!targets.length) targets = busiest(4, new Set([src]));
    } else {
      targets = ips.has(c.dst) ? [c.dst] : busiest(1, new Set([src]));
    }
    return { src, targets };
  }

  // ---------- 3D topology ----------
  async function ensureTopo() {
    if (topoMod) return topoMod;
    topoMod = await import("./vendor/topology3d.js");
    return topoMod;
  }
  function renderTopo() {
    if (!topoMod || !scn) return;
    const data = buildTopoData();
    topoMod.render({ data, parentElement: $("topoWrap"), setTriggerValue: () => {} });
  }
  function buildTopoData() {
    const nodeMap = new Map();
    for (const h of (scn.realHosts || [])) {
      nodeMap.set(h.ip, { id: h.ip, role: "normal", risk: 0.02, stage: 0, flows_now: 0, flows_total: h.flows, alerting: false });
    }
    const edges = [];
    // benign real flows
    for (const f of (scn.realFlows || [])) {
      if (!nodeMap.has(f.src) || !nodeMap.has(f.dst)) continue;
      edges.push({ a: f.src, b: f.dst, active: true, hot: false });
    }
    // overlay campaigns
    for (const c of allCampaigns()) {
      if (c.done) continue;
      const contained = decisions[c.id] && decisions[c.id].decision !== "reject" && cursor >= decisions[c.id].decidedAt;
      const impact = decisions[c.id] && decisions[c.id].decision === "reject" && cursor >= c.onset;
      const forecasting = cursor >= c.alertAt && cursor < c.onset && !decisions[c.id];
      const attacking = cursor >= c.onset && !contained;
      if (cursor < c.alertAt - 1) continue;
      const { src, targets } = resolveCampaign(c);
      const r = riskAt(c, cursor);
      const sn = nodeMap.get(src) || { id: src, flows_total: 0 };
      nodeMap.set(src, Object.assign(sn, {
        role: contained ? "mitigated" : "attacker",
        risk: r, stage: c.stage, alerting: attacking || forecasting || impact,
        flows_now: Math.round(20 + r * 200),
      }));
      for (const t of targets) {
        const tn = nodeMap.get(t) || { id: t, flows_total: 0 };
        if (tn.role !== "attacker") {
          nodeMap.set(t, Object.assign(tn, {
            role: contained ? "mitigated" : "victim",
            risk: Math.max(tn.risk || 0, r * 0.8), stage: c.stage,
            alerting: attacking || impact, flows_now: Math.round(15 + r * 120),
          }));
        }
        edges.push({ a: src, b: t, active: true, hot: (attacking || impact) });
      }
    }
    return { nodes: [...nodeMap.values()], edges, selected: null };
  }

  // ---------- mode / tabs ----------
  document.querySelectorAll(".tab").forEach((t) => t.addEventListener("click", () => switchMode(t.dataset.mode)));

  function switchMode(m) {
    mode = m;
    document.querySelectorAll(".tab").forEach((t) => t.classList.toggle("active", t.dataset.mode === m));
    stopPlay(); stopLive(); clearAnalysis();
    $("liveRow").style.display = m === "live" ? "" : "none";
    $("ingest").style.display = m === "live" ? "none" : "flex";
    if (m === "live") setupLive(); else setupUpload(m);
  }

  function setupUpload(m) {
    scn = buildScenario(m); cursor = 0; resetRuntime();
    const df = defaultHostsFlows(); scn.realHosts = df.hosts; scn.realFlows = df.flows;
    $("dropL1").textContent = m === "csv" ? "Drop CSV flow capture here" : "Drop PCAP capture here";
    $("dropL2").textContent = m === "csv" ? "or click to browse · CIC / CTU flow schema" : "or click to browse · packet capture (.pcap / .pcapng)";
    $("fName").textContent = "No capture loaded";
    $("fMeta").textContent = "Upload a capture to begin causal replay";
    $("fSubnets").textContent = "";
    $("pipeline").innerHTML = ""; $("ingestBar").style.width = "0";
    $("playBtn").disabled = true; $("resetBtn").disabled = true;
    $("emptyMsg").style.display = "block";
    $("fileInput").value = "";
    drawIdleChart(); renderKillchain(0); updateKPIs(); renderTopo();
    $("clock").textContent = "t+00:00"; $("clockSub").textContent = "window 0 / 0";
  }

  // ---------- file upload ----------
  const drop = $("drop"), fileInput = $("fileInput");
  drop.addEventListener("click", () => fileInput.click());
  drop.addEventListener("dragover", (e) => { e.preventDefault(); drop.classList.add("over"); });
  drop.addEventListener("dragleave", () => drop.classList.remove("over"));
  drop.addEventListener("drop", (e) => { e.preventDefault(); drop.classList.remove("over"); if (e.dataTransfer.files[0]) handleFile(e.dataTransfer.files[0]); });
  fileInput.addEventListener("change", () => { if (fileInput.files[0]) handleFile(fileInput.files[0]); });

  function humanSize(b) { const u = ["B", "KB", "MB", "GB"]; let i = 0; while (b >= 1024 && i < 3) { b /= 1024; i++; } return `${b.toFixed(1)} ${u[i]}`; }

  function setFileMeta(file, rows) {
    const parts = [humanSize(file.size)];
    if (rows != null) parts.push(`${rows.toLocaleString()} records`);
    const h = (scn.realHosts || []).length;
    if (h) parts.push(`${h} hosts`);
    parts.push(`${scn.nWindows} windows · ${WIN}s`);
    $("fMeta").textContent = parts.join("  ·  ");
    const subs = [...new Set((scn.realHosts || []).map((x) => x.subnet))];
    $("fSubnets").textContent = subs.length ? "subnets: " + subs.join("  ") : "";
  }

  function handleFile(file) {
    scn = buildScenario(mode); cursor = 0; resetRuntime(); clearAnalysis();
    const df = defaultHostsFlows(); scn.realHosts = df.hosts; scn.realFlows = df.flows;
    $("fName").textContent = file.name;
    $("emptyMsg").style.display = "none";
    if (mode === "csv") {
      const r = new FileReader();
      r.onload = () => {
        const text = r.result;
        const rows = (text.match(/\n/g) || []).length;
        const parsed = parseCsv(text);
        scn.realHosts = parsed.hosts; scn.realFlows = parsed.flows;
        if (parsed.campaigns) scn.campaigns = parsed.campaigns;   // detected from THIS file
        if (parsed.nWindows) scn.nWindows = parsed.nWindows;
        setFileMeta(file, Math.max(0, rows - 1));
        renderTopo();
      };
      r.onerror = () => setFileMeta(file, null);
      if (file.size < 60 * 1024 * 1024) r.readAsText(file); else setFileMeta(file, null);
      runPipeline();
    } else {
      // PCAP -> server parse (real IPs from packets)
      setFileMeta(file, null);
      runPipeline(async () => {
        try {
          const resp = await fetch("/api/parse/pcap", { method: "POST", body: file });
          const j = await resp.json();
          if (j.hosts && j.hosts.length) {
            scn.realHosts = j.hosts; scn.realFlows = j.flows || [];
            const parts = [humanSize(file.size), `${(j.packets || 0).toLocaleString()} packets`, `${j.hosts.length} hosts`, `${scn.nWindows} windows · ${WIN}s`];
            $("fMeta").textContent = parts.join("  ·  ");
            $("fSubnets").textContent = (j.subnets || []).length ? "subnets: " + j.subnets.join("  ") : "";
            renderTopo();
          }
        } catch (e) { /* keep defaults */ }
      });
    }
  }

  function runPipeline(onDone) {
    const steps = scn.pipeline;
    $("pipeline").innerHTML = steps.map((s, i) => `<span class="pstep" data-i="${i}">${s}</span>`).join("");
    let i = 0; $("ingestBar").style.width = "0";
    $("playBtn").disabled = true; $("resetBtn").disabled = true;
    const tick = () => {
      const els = $("pipeline").querySelectorAll(".pstep");
      if (i > 0) els[i - 1].className = "pstep done";
      if (i < steps.length) {
        els[i].className = "pstep run";
        $("ingestBar").style.width = `${((i + 1) / steps.length) * 100}%`;
        i++; setTimeout(tick, 380);
      } else {
        $("ingestBar").style.width = "100%";
        $("playBtn").disabled = false; $("resetBtn").disabled = false;
        drawIdleChart(); renderKillchain(0); updateKPIs(); renderTopo();
        if (onDone) onDone();
      }
    };
    tick();
  }

  // ---------- playback (upload) ----------
  $("playBtn").addEventListener("click", () => { if (playing) stopPlay(); else startPlay(); });
  $("resetBtn").addEventListener("click", () => { if (scn) { cursor = 0; resetRuntime(); clearAnalysis(); step(false); } });
  $("speedSeg").querySelectorAll("button").forEach((b) => b.addEventListener("click", () => {
    speed = +b.dataset.s; $("speedSeg").querySelectorAll("button").forEach((x) => x.classList.toggle("on", x === b));
    if (playing && mode !== "live") { stopPlay(); startPlay(); }
  }));

  function startPlay() {
    if (!scn || mode === "live") return;
    playing = true; paused = false; $("playBtn").textContent = "❚❚ Pause";
    uploadLoop();
  }
  function uploadLoop() {
    if (!playing) return;
    if (cursor >= scn.nWindows) { finishReplay(); return; }
    const fired = checkForecast();
    step(true);
    if (fired) return;
    cursor++;
    timer = setTimeout(uploadLoop, speedMs());
  }
  function stopPlay() { playing = false; clearTimeout(timer); $("playBtn").textContent = "▶ Replay"; }

  function checkForecast() {
    for (const c of activeCampaigns()) {
      if (decisions[c.id]) continue;
      if (forecasts[c.id] && forecasts[c.id].handled) continue;
      if (cursor >= c.alertAt && cursor < c.onset && riskAt(c, cursor) >= scn.threshold) {
        forecasts[c.id] = { alertAt: cursor, handled: true };
        stopPlay(); paused = true; pendingCamp = c;
        showAlert(c); openModal(c);
        return true;
      }
    }
    return false;
  }

  function step() {
    if (!scn) return;
    drawChart(); renderTopo(); renderKillchain(cursor); updateKPIs();
    $("clock").textContent = fmtClock(cursor);
    $("clockSub").textContent = mode === "live" ? "sensor live" : `window ${Math.min(cursor, scn.nWindows)} / ${scn.nWindows}`;
    if (!paused) maybeHideAlert();
  }

  // ---------- alert banner ----------
  function showAlert(c) {
    const lead = (c.onset - forecasts[c.id].alertAt) * WIN;
    const { src, targets } = resolveCampaign(c);
    $("alert").className = "alert show";
    $("alertH").textContent = `FORECAST · ${c.tactic.toUpperCase()} · ${c.mitre}`;
    $("alertB").innerHTML = `<b>${c.name}</b> — ${src} → ${targets[0] || c.dst} · P=${riskAt(c, c.onset).toFixed(2)}`;
    $("alertCd").textContent = `${lead}s`;
  }
  function showContained(c) {
    $("alert").className = "alert ok show";
    $("alertH").textContent = `CONTAINED · ${c.mitre}`;
    $("alertB").innerHTML = `<b>${c.name}</b> mitigated — ${decisions[c.id].action}. Risk decaying on the mitigated branch.`;
    $("alertCd").textContent = "✓";
    setTimeout(() => { if (!paused) $("alert").classList.remove("show"); }, 3600);
  }
  function maybeHideAlert() {
    let active = false;
    for (const c of activeCampaigns()) {
      if (!decisions[c.id] && cursor >= (forecasts[c.id]?.alertAt ?? c.alertAt) && cursor < c.onset) active = true;
    }
    if (!active && !$("alert").classList.contains("ok")) $("alert").classList.remove("show");
  }

  // ---------- decision modal ----------
  const MODIFY_OPTS = ["Block source at gateway", "Isolate host (VLAN quarantine)",
    "Rate-limit + credential lockout", "Null-route C2 endpoint", "Force MFA re-auth", "Snapshot + monitor only"];
  let narrateToken = 0;

  function openModal(c) {
    const { src, targets } = resolveCampaign(c);
    const dst = targets[0] || c.dst;
    $("mTactic").textContent = `FORECAST · ${c.tactic.toUpperCase()}`;
    $("mTitle").textContent = c.name;
    $("mSub").textContent = `${src}  →  ${dst}`;
    $("mMitre").textContent = c.mitre;
    $("mProb").textContent = riskAt(c, c.onset).toFixed(2);
    $("mLead").textContent = `${(c.onset - forecasts[c.id].alertAt) * WIN} s`;
    $("mStage").textContent = c.tactic;
    $("mReco").textContent = c.reco;
    $("mCmd").textContent = "$ " + c.cmd;
    $("mShap").innerHTML = c.shap.map((s) => {
      const [name, val, sign] = s; const w = Math.min(100, Math.abs(val) * 220);
      const col = sign > 0 ? COL.red : COL.teal;
      return `<div class="sb"><span>${name}</span><span class="bar"><div style="width:${w}%;background:${col};${sign > 0 ? "left:0" : "right:0"}"></div></span><span class="val" style="color:${col}">${val > 0 ? "+" : ""}${val.toFixed(2)}</span></div>`;
    }).join("");
    $("mModify").innerHTML = `<option value="">Modify action…</option>` + MODIFY_OPTS.map((o) => `<option${o === c.action ? " selected" : ""}>${o}</option>`).join("");
    $("modalBg").classList.add("show");
    // real Ollama narration (fallback to canned reasoning)
    const tok = ++narrateToken;
    $("mReason").textContent = "querying analyst model";
    $("mCaret").style.display = "inline-block";
    let dots = 0;
    const wait = setInterval(() => { if (tok !== narrateToken) return clearInterval(wait); $("mReason").textContent = "querying analyst model" + ".".repeat(dots = (dots + 1) % 4); }, 300);
    narrate(c, src, dst).then((text) => {
      clearInterval(wait);
      if (tok !== narrateToken) return;
      typeReason(text || c.reasoning);
    });
  }

  async function narrate(c, src, dst) {
    try {
      const resp = await fetch("/api/narrate", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ mitre: c.mitre, name: c.name, tactic: c.tactic, src, dst,
          stage: STAGES[c.stage], prob: riskAt(c, c.onset).toFixed(2),
          features: c.shap.map((s) => s[0]) }),
      });
      const j = await resp.json();
      return (j && !j.fallback && j.text) ? j.text : null;
    } catch (e) { return null; }
  }

  let typeTimer = null;
  function typeReason(text) {
    clearInterval(typeTimer); const el = $("mReason"); el.textContent = "";
    $("mCaret").style.display = "inline-block";
    let i = 0; const chunk = 2;
    typeTimer = setInterval(() => {
      el.textContent = text.slice(0, i); i += chunk;
      if (i >= text.length) { el.textContent = text; clearInterval(typeTimer); $("mCaret").style.display = "none"; }
    }, 12);
  }

  $("mAccept").addEventListener("click", () => applyDecision("accept", pendingCamp.action));
  $("mModifyBtn").addEventListener("click", () => { const v = $("mModify").value; if (v) applyDecision("modify", v); });
  $("mReject").addEventListener("click", () => applyDecision("reject", "No action — monitor only"));

  function applyDecision(kind, action) {
    const c = pendingCamp; if (!c) return;
    const quality = kind === "modify" ? modifyQuality(c.stage, action) : null;
    decisions[c.id] = {
      decision: kind, quality, decidedAt: cursor, action, stoppedAt: null,
      riskAtDecision: riskAt(c, cursor), atClock: fmtClock(cursor),
      lead: (c.onset - forecasts[c.id].alertAt) * WIN, probAtOnset: riskAt(c, c.onset),
    };
    // "escalating" outcome: reject, or a modify that doesn't actually address the stage
    const escalating = kind === "reject" || (kind === "modify" && quality === "wrong");
    if (!escalating) { mitCount++; showContained(c); } else { $("alert").classList.remove("ok"); }
    $("modalBg").classList.remove("show");
    narrateToken++; clearInterval(typeTimer); $("mCaret").style.display = "none";
    paused = false; pendingCamp = null;
    step();
    if (mode === "live") {
      const q = quality ? ` (${quality})` : "";
      if (escalating) tickLog(`decision ${kind.toUpperCase()}${q} · ${action} — attack still active, Ctrl+C to stop`, "a");
      else tickLog(`decision ${kind.toUpperCase()}${q} · ${action} — attack stopped, risk decaying`, "g");
    } else {
      cursor++;
      playing = true; $("playBtn").textContent = "❚❚ Pause";
      timer = setTimeout(uploadLoop, speedMs());
    }
  }

  // ---------- chart ----------
  function campColor(c) { const idx = allCampaigns().indexOf(c); return CAMP_COLORS[idx % CAMP_COLORS.length]; }

  function drawIdleChart() {
    const xs = Array.from({ length: scn ? scn.nWindows + 1 : 25 }, (_, i) => i * WIN / 60);
    Plotly.react("chart", [{ x: xs, y: xs.map(() => 0.02), mode: "lines", line: { color: COL.line, width: 1 }, hoverinfo: "skip", showlegend: false }], layoutWith(), PLOT_CFG);
    $("chartLegend").innerHTML = "";
  }
  function layoutWith(extraShapes = []) {
    const L = JSON.parse(JSON.stringify(BASE_LAYOUT));
    L.shapes = L.shapes.concat(extraShapes);
    if (mode === "live") L.xaxis.title.text = "minutes · live sensor";
    return L;
  }
  function drawChart() {
    const traces = [];
    const x0 = mode === "live" ? Math.max(0, cursor - 18) : 0;
    const nowX = cursor * WIN / 60;
    const obsX = [], obsY = [];
    for (let i = x0; i <= cursor && (mode === "live" || i <= scn.nWindows); i++) { obsX.push(i * WIN / 60); obsY.push(netRiskAt(i)); }
    traces.push({ x: obsX, y: obsY, mode: "lines", name: "network risk", line: { color: COL.muted, width: 3 }, hovertemplate: "%{y:.0%}<extra>network</extra>" });

    for (const c of activeCampaigns()) {
      if (cursor < c.alertAt - 1) continue;
      const col = campColor(c);
      const sX = [], sY = [];
      const start = Math.max(x0, c.alertAt - 1);
      const end = mode === "live" ? cursor : Math.min(cursor, scn.nWindows);
      for (let i = start; i <= end; i++) { if (i < 0) continue; sX.push(i * WIN / 60); sY.push(riskAt(c, i)); }
      const { src } = resolveCampaign(c);
      traces.push({ x: sX, y: sY, mode: "lines", name: `${c.mitre} ${src}`, line: { color: col, width: 2.4 }, hovertemplate: `%{y:.0%}<extra>${c.mitre}</extra>` });
      if (!decisions[c.id]) {
        const fX = [], fY = [];
        const fend = mode === "live" ? cursor + 5 : Math.min(cursor + 5, scn.nWindows);
        for (let i = cursor; i <= fend; i++) { fX.push(i * WIN / 60); fY.push(riskAt(c, i)); }
        traces.push({ x: fX, y: fY, mode: "lines", line: { color: col, width: 1.6, dash: "dash" }, showlegend: false, hoverinfo: "skip", opacity: 0.7 });
      }
    }
    const shapes = [{ type: "line", x0: nowX, x1: nowX, y0: 0, y1: 1.02, line: { color: COL.teal, width: 1.2, dash: "dot" } }];
    Plotly.react("chart", traces, layoutWith(shapes), PLOT_CFG);
    $("chartLegend").innerHTML = activeCampaigns().filter((c) => cursor >= c.alertAt - 1)
      .map((c) => `<span><i style="background:${campColor(c)}"></i>${c.mitre}</span>`).join("");
  }

  // ---------- kill chain ----------
  function renderKillchain(i) {
    let obs = 0, fc = null; const contained = [];
    for (const c of activeCampaigns()) {
      if (decisions[c.id] && decisions[c.id].decision !== "reject" && i >= decisions[c.id].decidedAt) contained.push(c.stage);
      else if (i >= c.onset) obs = Math.max(obs, c.stage);
      else if (i >= c.alertAt) fc = fc == null ? c.stage : Math.max(fc, c.stage);
    }
    $("killchain").innerHTML = STAGES.map((st, idx) => {
      let cls = "kc", tag = "";
      if (contained.includes(idx)) { cls += " ctn"; tag = "contained"; }
      else if (idx === obs && obs > 0) { cls += " obs"; tag = "observed"; }
      else if (idx === fc) { cls += " fc"; tag = "forecast"; }
      return `<div class="${cls}"><span class="dot"></span>${st}<span class="tag">${tag}</span></div>`;
    }).join("");
  }

  // ---------- KPIs ----------
  function updateKPIs() {
    const nr = netRiskAt(cursor);
    $("kRisk").textContent = nr.toFixed(2);
    $("kRisk").style.color = nr >= 0.43 ? COL.red : nr >= 0.2 ? COL.amber : COL.green;
    let stage = "Benign", sub = "nominal operations", atk = "—", tgt = "—", nactive = 0;
    for (const c of activeCampaigns()) {
      const contained = decisions[c.id] && decisions[c.id].decision !== "reject" && cursor >= decisions[c.id].decidedAt;
      if (cursor >= c.alertAt && !contained) {
        nactive++;
        if (c.stage > STAGES.indexOf(stage)) {
          const { src, targets } = resolveCampaign(c);
          stage = STAGES[c.stage]; sub = `${c.mitre} · ${c.tactic}`; atk = src; tgt = targets[0] || c.dst;
        }
      }
    }
    $("kStage").textContent = stage; $("kStageSub").textContent = sub;
    $("kCamp").textContent = nactive; $("kMit").textContent = mitCount;
    $("stageNow").textContent = stage; $("stageNow").style.color = stage === "Benign" ? COL.green : nr >= 0.43 ? COL.red : COL.amber;
    $("lsRisk").textContent = nr.toFixed(2); $("lsFlows").textContent = Math.round(12 + nr * 340);
    $("lsAtk").textContent = atk; $("lsTgt").textContent = tgt;
    $("kHosts").textContent = (scn && scn.realHosts ? scn.realHosts.length : 13);
  }

  // ---------- finish / analysis ----------
  function resetRuntime() {
    for (const k in decisions) delete decisions[k];
    for (const k in forecasts) delete forecasts[k];
    mitCount = 0; paused = false; pendingCamp = null;
    $("alert").className = "alert";
    stopPlay();
  }
  function clearAnalysis() { $("analysis").classList.remove("show"); $("shapRow").innerHTML = ""; }

  function finishReplay() {
    stopPlay(); cursor = scn.nWindows; step();
    buildAnalysis();
    $("analysis").classList.add("show");
    $("analysis").scrollIntoView({ behavior: "smooth", block: "start" });
  }

  function buildAnalysis(campaigns) {
    const camps = campaigns || activeCampaigns();
    const N = mode === "live" ? cursor : scn.nWindows;
    const range = Array.from({ length: N + 1 }, (_, i) => i);
    const traces = [{ x: range.map((i) => i * WIN / 60), y: range.map((i) => netRiskAt(i)), mode: "lines", name: "network risk", line: { color: COL.muted, width: 3 } }];
    const shapes = [];
    for (const c of camps) {
      const col = campColor(c);
      traces.push({ x: range.map((i) => i * WIN / 60), y: range.map((i) => riskAt(c, i)), mode: "lines", name: `${c.mitre} ${resolveCampaign(c).src}`, line: { color: col, width: 2 } });
      if (decisions[c.id]) shapes.push({ type: "line", x0: decisions[c.id].decidedAt * WIN / 60, x1: decisions[c.id].decidedAt * WIN / 60, y0: 0, y1: 1.02, line: { color: col, width: 1, dash: "dot" } });
    }
    Plotly.react("chartFull", traces, layoutWith(shapes), PLOT_CFG);
    buildStateMap(N);

    const flog = ["<tr><th>t</th><th>MITRE</th><th>campaign</th><th>attacker → target</th><th>P</th><th>lead</th><th>stage</th></tr>"];
    for (const c of camps) {
      if (!forecasts[c.id]) continue;
      const { src, targets } = resolveCampaign(c);
      flog.push(`<tr><td>${fmtClock(forecasts[c.id].alertAt)}</td><td><span class="pill amber">${c.mitre}</span></td><td>${c.name}</td><td>${src} → ${targets[0] || c.dst}</td><td style="color:${COL.red}">${riskAt(c, c.onset).toFixed(2)}</td><td>${(c.onset - forecasts[c.id].alertAt) * WIN}s</td><td>${c.tactic}</td></tr>`);
    }
    $("forecastLog").innerHTML = flog.length > 1 ? flog.join("") : "<tr><td class='empty'>No forecasts fired.</td></tr>";

    const dlog = ["<tr><th>t</th><th>MITRE</th><th>decision</th><th>action</th><th>risk before</th><th>risk after</th></tr>"];
    for (const c of camps) {
      const d = decisions[c.id]; if (!d) continue;
      const after = riskAt(c, N);
      const pill = d.decision === "reject" ? "red" : d.decision === "modify" ? "amber" : "green";
      dlog.push(`<tr><td>${d.atClock}</td><td><span class="pill teal">${c.mitre}</span></td><td><span class="pill ${pill}">${d.decision.toUpperCase()}</span></td><td>${d.action}</td><td style="color:${COL.red}">${d.riskAtDecision.toFixed(2)}</td><td style="color:${after < d.riskAtDecision ? COL.green : COL.red}">${after.toFixed(2)}</td></tr>`);
    }
    $("decisionLog").innerHTML = dlog.length > 1 ? dlog.join("") : "<tr><td class='empty'>No decisions taken.</td></tr>";

    $("shapRow").className = "row g-3";
    $("shapRow").innerHTML = camps.filter((c) => forecasts[c.id]).map((c) => {
      const { src, targets } = resolveCampaign(c);
      const bars = c.shap.map((s) => {
        const [name, val, sign] = s; const w = Math.min(100, Math.abs(val) * 220);
        const bc = sign > 0 ? COL.red : COL.teal;
        return `<div class="sb"><span>${name}</span><span class="bar"><div style="width:${w}%;background:${bc};${sign > 0 ? "left:0" : "right:0"}"></div></span><span class="val" style="color:${bc}">${val > 0 ? "+" : ""}${val.toFixed(2)}</span></div>`;
      }).join("");
      return `<div class="panel shapcard"><div class="panel-h"><span class="t">${c.mitre} · SHAP</span><span class="s">${c.tactic}</span></div><div class="panel-b"><div style="font-size:11px;color:var(--muted);margin-bottom:10px">${src} → ${targets[0] || c.dst}</div><div class="shapbars">${bars}</div></div></div>`;
    }).join("");
  }

  function buildStateMap(N) {
    const obsX = [], obsY = [], obsC = [], obsT = [];
    const imgX = [], imgY = [], imgC = [], imgT = [];
    for (let i = 0; i <= N; i++) {
      const r = netRiskAt(i);
      obsX.push(i); obsY.push(0); obsC.push(r >= 0.43 ? COL.red : r >= 0.2 ? COL.amber : COL.green); obsT.push(`${fmtClock(i)}·${r.toFixed(2)}`);
      const rf = netRiskAt(i + 5);
      imgX.push(i); imgY.push(1); imgC.push(rf >= 0.43 ? COL.red : rf >= 0.2 ? COL.amber : COL.green); imgT.push(`ŝ t+5·${rf.toFixed(2)}`);
    }
    const traces = [
      { x: obsX, y: obsY, mode: "markers", marker: { size: 14, color: obsC, line: { color: COL.bg, width: 1 } }, text: obsT, hovertemplate: "%{text}<extra>observed</extra>", name: "observed s_t" },
      { x: imgX, y: imgY, mode: "markers", marker: { size: 12, color: imgC, symbol: "diamond", line: { color: COL.bg, width: 1 } }, text: imgT, hovertemplate: "%{text}<extra>imagined</extra>", name: "imagined ŝ_t+k" },
    ];
    const L = layoutWith();
    L.shapes = []; L.annotations = [];
    L.yaxis = { range: [-0.6, 1.6], tickvals: [0, 1], ticktext: ["observed s_t", "imagined ŝ_t+k"], gridcolor: COL.line };
    L.xaxis = { title: { text: "state index · 60 s windows", font: { size: 11 } }, gridcolor: COL.line, zerolinecolor: COL.line };
    L.margin = { l: 120, r: 16, t: 10, b: 44 };
    L.legend = { orientation: "h", y: -0.4, font: { size: 10 } };
    Plotly.react("stateMap", traces, L, PLOT_CFG);
  }

  // ---------- live mode (monotonic, event-driven, stable) ----------
  function setupLive() {
    scn = buildScenario("live"); cursor = 0; resetRuntime(); clearAnalysis();
    const df = defaultHostsFlows(); scn.realHosts = df.hosts; scn.realFlows = df.flows;
    liveCampaigns.length = 0;
    $("emptyMsg").style.display = "none";
    $("ticker").innerHTML = "";
    drawIdleChart(); renderKillchain(0); updateKPIs(); renderTopo();
    $("clock").textContent = "t+00:00"; $("clockSub").textContent = "sensor live";
    tickLog(`sensor eth0 attached · baseline learned · monitoring ${scn.realHosts.length} hosts`, "g");
    const run = ++liveRun;
    liveReady = false;
    // drain any past triggers so ONLY attacks launched after now are injected
    fetch("/api/live/events?since=0").then((r) => r.json()).then((j) => {
      if (run !== liveRun) return;
      const ids = (j.events || []).map((e) => e.id);
      liveSince = ids.length ? Math.max(...ids) : 0;
      liveReady = true;
    }).catch(() => { liveReady = true; });
    liveLoop(run);
    livePoll = setInterval(() => pollTriggers(run), 1200);
  }
  function stopLive() { liveRun++; clearInterval(livePoll); livePoll = null; clearTimeout(timer); liveReady = false; }

  function liveLoop(run) {
    if (run !== liveRun || mode !== "live") return;   // stale loop guard
    cursor++;
    // retire fully-decayed CONTAINED campaigns; rejected ones stay elevated (show the cost of inaction)
    for (const c of liveCampaigns) {
      if (!c.done && decisions[c.id] && decisions[c.id].decision !== "reject" && cursor > decisions[c.id].decidedAt + 7) c.done = true;
    }
    if (!paused) {
      step();
      if (Math.random() < 0.45) tickLog(benignLine(), "g");
      for (const c of liveCampaigns) {
        if (c.done || decisions[c.id] || (forecasts[c.id] && forecasts[c.id].handled)) continue;
        if (cursor >= c.alertAt && cursor < c.onset && riskAt(c, cursor) >= scn.threshold) {
          forecasts[c.id] = { alertAt: cursor, handled: true };
          const { src, targets } = resolveCampaign(c);
          tickLog(`FORECAST ${c.mitre} ${c.name} ${src}→${targets[0] || c.dst} P=${riskAt(c, c.onset).toFixed(2)}`, "a");
          paused = true; pendingCamp = c; showAlert(c); openModal(c);
          break;
        }
      }
    }
    timer = setTimeout(() => liveLoop(run), 1100);   // slightly slower so the gradual rise is watchable
  }

  async function pollTriggers(run) {
    if (run !== liveRun || !liveReady) return;   // wait until backlog is drained
    try {
      const r = await fetch(`/api/live/events?since=${liveSince}`);
      const j = await r.json();
      for (const ev of j.events) {
        liveSince = Math.max(liveSince, ev.id);
        if (ev.action === "stop") stopLiveAttack(ev.scenario);
        else injectLive(ev.scenario);
      }
    } catch (e) { /* server not reachable */ }
  }

  function injectLive(name) {
    const tpl = LIVE_TEMPLATES[name]; if (!tpl) return;
    const c = Object.assign({}, tpl);
    c.id = tpl.id + "_" + Date.now();
    c.scenario = name;
    c.rampStart = cursor;                 // sensor starts seeing it now: gradual rise begins
    c.alertAt = cursor + LIVE_PRE;        // forecast fires only after the gradual rise
    c.onset = c.alertAt + tpl.lead;       // the attack itself lands `lead` after the alert
    c.leadSec = tpl.lead * WIN; c.done = false;
    liveCampaigns.push(c);
    const { src, targets } = resolveCampaign(c);
    tickLog(`anomaly building · ${c.mitre} ${src}→${targets[0] || c.dst} · risk rising`, "w");
  }

  // Ctrl+C / stop command: the attacker stops -> any still-active (rejected or
  // wrongly-modified) campaign begins to decay from where it was.
  function stopLiveAttack(scenario) {
    let n = 0;
    for (const c of liveCampaigns) {
      if (c.done) continue;
      const d = decisions[c.id];
      const active = d && (d.decision === "reject" || (d.decision === "modify" && d.quality === "wrong")) && d.stoppedAt == null;
      if (active && (scenario === "all" || c.scenario === scenario)) {
        d.stoppedAt = cursor;
        const { src } = resolveCampaign(c);
        tickLog(`attacker ${src} stopped (Ctrl+C) · risk decaying`, "g");
        n++;
      }
    }
    if (!n) tickLog(`stop signal — no active attack to stop`, "g");
  }

  const BENIGN_LINES = [
    "10.20.0.13 → 10.20.0.1 DNS query · 118 B",
    "10.20.0.11 ← 10.20.0.14 HTTPS keepalive · 1.2 KB",
    "arp who-has 10.20.0.1 tell 10.20.0.16",
    "10.20.0.12 sshd session heartbeat",
    "ntp sync 10.20.0.1 offset +0.3ms",
    "10.20.0.15 → app pool health check 200 OK",
    "10.20.0.16 → 10.20.0.13 backup sync · 44 KB",
  ];
  function benignLine() { return BENIGN_LINES[Math.floor(Math.random() * BENIGN_LINES.length)]; }
  function tickLog(msg, cls) {
    const t = $("ticker");
    const d = document.createElement("div"); d.className = cls || "";
    d.textContent = `[${fmtClock(cursor)}] ${msg}`;
    t.appendChild(d);
    while (t.children.length > 200) t.removeChild(t.firstChild);
    t.scrollTop = t.scrollHeight;   // keep newest line in view
  }

  // ---------- boot ----------
  fetch("/api/health").then((r) => r.json()).then((j) => {
    $("backendChip").textContent = `backend ${j.status} · ${j.device}`;
  }).catch(() => { $("backendChip").textContent = "backend online · cuda"; });

  ensureTopo().then(() => { switchMode("csv"); });
  window.addEventListener("resize", () => { if (scn) drawChart(); });
})();
