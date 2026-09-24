// NetraVerse — live 3D network topology.
// Renders the real discovered LAN as a 3D graph, colours each device by its
// forecasted ATT&CK stage / risk, animates the attack, and lets the operator
// pull a two-tier LLM actionable and (later) approve real containment.
import * as THREE from "three";
import { OrbitControls } from "three/examples/jsm/controls/OrbitControls.js";

// Same-origin by default: the Vite dev server proxies /api to the sensor API,
// which avoids CORS / private-network blocks. Override with window.NV_API_BASE.
const API = window.NV_API_BASE != null ? window.NV_API_BASE : "";

const STAGE = {
  0: { name: "Benign",           color: 0x64748b },
  1: { name: "Reconnaissance",   color: 0xf59e0b },
  2: { name: "Initial Access",   color: 0xf97316 },
  3: { name: "Lateral Movement", color: 0xa855f7 },
  4: { name: "Command & Control",color: 0xef4444 },
  5: { name: "Exfiltration",     color: 0xdc2626 },
  6: { name: "Impact",           color: 0xb91c1c },
};
const ROLE_SIZE = { gateway: 4.2, sensor: 3.6, device: 2.6, external: 3.0 };

const api = (path) => fetch(API + path).then((r) => r.json());
const pct = (v) => `${Math.round((Number(v) || 0) * 100)}%`;
const esc = (s) => String(s == null ? "" : s).replace(/[&<>"]/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

// ---------------------------------------------------------------- scene setup
const mount = document.getElementById("nv-topo");
const scene = new THREE.Scene();
scene.background = new THREE.Color(0x0b1220);
scene.fog = new THREE.FogExp2(0x0b1220, 0.006);

const camera = new THREE.PerspectiveCamera(55, 1, 0.1, 2000);
camera.position.set(0, 60, 130);

const renderer = new THREE.WebGLRenderer({ antialias: true });
renderer.setPixelRatio(Math.min(2, window.devicePixelRatio));
mount.appendChild(renderer.domElement);

const controls = new OrbitControls(camera, renderer.domElement);
controls.enableDamping = true;
controls.autoRotate = true;
controls.autoRotateSpeed = 0.5;

scene.add(new THREE.AmbientLight(0xffffff, 0.6));
const key = new THREE.DirectionalLight(0xffffff, 0.8);
key.position.set(50, 120, 80);
scene.add(key);
// subtle ground grid
const grid = new THREE.GridHelper(400, 40, 0x1e293b, 0x172033);
grid.position.y = -20;
scene.add(grid);

function resize() {
  const w = mount.clientWidth, h = mount.clientHeight;
  renderer.setSize(w, h, false);
  camera.aspect = w / h; camera.updateProjectionMatrix();
}
window.addEventListener("resize", resize);

// ---------------------------------------------------------------- node/edge state
const nodes = new Map();     // ip -> { mesh, label, data, basePos }
const fcDevices = new Map();  // ip -> latest forecast device record (incl. off-graph hosts)
const edges = [];            // { line, a, b }
const pulses = [];           // travelling attack particles
const raycaster = new THREE.Raycaster();
const pointer = new THREE.Vector2();
let selected = null;

function makeLabelSprite(text) {
  const cv = document.createElement("canvas");
  const ctx = cv.getContext("2d");
  ctx.font = "600 26px 'IBM Plex Mono', monospace";
  const w = ctx.measureText(text).width + 20;
  cv.width = w; cv.height = 40;
  ctx.font = "600 26px 'IBM Plex Mono', monospace";
  ctx.fillStyle = "rgba(11,18,32,0.7)"; ctx.fillRect(0, 0, w, 40);
  ctx.fillStyle = "#e2e8f0"; ctx.textBaseline = "middle";
  ctx.fillText(text, 10, 22);
  const tex = new THREE.CanvasTexture(cv);
  const spr = new THREE.Sprite(new THREE.SpriteMaterial({ map: tex, depthTest: false, transparent: true }));
  spr.scale.set(w * 0.06, 2.4, 1);
  return spr;
}

function layout(devices, gateway) {
  // Gateway at centre; everything else on a sphere shell around it.
  const positions = new Map();
  positions.set(gateway, new THREE.Vector3(0, 0, 0));
  const others = devices.filter((d) => d.ip !== gateway);
  const n = Math.max(1, others.length);
  others.forEach((d, i) => {
    const phi = Math.acos(1 - 2 * (i + 0.5) / n);       // even sphere distribution
    const theta = Math.PI * (1 + Math.sqrt(5)) * i;
    const R = 46;
    positions.set(d.ip, new THREE.Vector3(
      R * Math.sin(phi) * Math.cos(theta),
      R * Math.cos(phi) * 0.6,
      R * Math.sin(phi) * Math.sin(theta),
    ));
  });
  return positions;
}

function buildGraph(topo) {
  nodes.forEach((n) => { scene.remove(n.mesh); scene.remove(n.label); });
  edges.forEach((e) => scene.remove(e.line));
  nodes.clear(); edges.length = 0;

  const gateway = topo.gateway || (topo.devices[0] && topo.devices[0].ip);
  const pos = layout(topo.devices || [], gateway);

  for (const d of topo.devices || []) {
    const size = ROLE_SIZE[d.role] || ROLE_SIZE.device;
    const geo = new THREE.SphereGeometry(size, 24, 24);
    const mat = new THREE.MeshStandardMaterial({
      color: 0x64748b, emissive: 0x000000, metalness: 0.3, roughness: 0.5,
    });
    const mesh = new THREE.Mesh(geo, mat);
    const p = pos.get(d.ip) || new THREE.Vector3();
    mesh.position.copy(p);
    mesh.userData.ip = d.ip;
    scene.add(mesh);
    const label = makeLabelSprite(d.hostname || d.ip);
    label.position.copy(p).add(new THREE.Vector3(0, size + 2.5, 0));
    scene.add(label);
    nodes.set(d.ip, { mesh, label, data: d, basePos: p.clone(), size });
  }
  for (const l of topo.links || []) {
    const a = nodes.get(l.a), b = nodes.get(l.b);
    if (!a || !b) continue;
    const g = new THREE.BufferGeometry().setFromPoints([a.basePos, b.basePos]);
    const line = new THREE.Line(g, new THREE.LineBasicMaterial({ color: 0x1e3a5f, transparent: true, opacity: 0.5 }));
    scene.add(line);
    edges.push({ line, a: l.a, b: l.b });
  }
  resize();
}

// ---------------------------------------------------------------- live forecast overlay
function applyForecast(fc) {
  const byIp = new Map((fc.devices || []).map((d) => [String(d.ip || d.host), d]));
  fcDevices.clear();
  for (const [ip, d] of byIp) fcDevices.set(ip, d);
  for (const [ip, node] of nodes) {
    const d = byIp.get(ip);
    const stageId = d ? (d.stage_id || 0) : 0;
    const risk = d ? Number(d.peak_risk || 0) : 0;
    const st = STAGE[stageId] || STAGE[0];
    const alerting = d && (d.forecast_state === "CONFIRMED_ALERT" || d.forecast_state === "EARLY_WARNING");
    const hasTel = d && d.has_telemetry;
    node.mesh.material.color.setHex(hasTel ? st.color : 0x334155);
    node.mesh.material.emissive.setHex(alerting ? st.color : 0x000000);
    node.mesh.material.opacity = hasTel ? 1 : 0.6;
    node.mesh.material.transparent = !hasTel;
    node.mesh.scale.setScalar(1 + risk * 0.8);
    node.data = d || node.data;
    node.alerting = alerting;
    node.risk = risk;
  }
  // attack pulses along edges touching an alerting node
  for (const e of edges) {
    const a = nodes.get(e.a), b = nodes.get(e.b);
    const hot = (a && a.alerting) || (b && b.alerting);
    e.line.material.color.setHex(hot ? 0xef4444 : 0x1e3a5f);
    e.line.material.opacity = hot ? 0.9 : 0.4;
    if (hot && Math.random() < 0.05) spawnPulse(a.basePos, b.basePos);
  }
  renderPanel(fc);
}

function spawnPulse(from, to) {
  const geo = new THREE.SphereGeometry(0.8, 8, 8);
  const mat = new THREE.MeshBasicMaterial({ color: 0xfca5a5 });
  const m = new THREE.Mesh(geo, mat);
  scene.add(m);
  pulses.push({ m, from: from.clone(), to: to.clone(), t: 0 });
}

// ---------------------------------------------------------------- side panel
const panel = document.getElementById("nv-topo-panel");
function renderPanel(fc) {
  const wn = fc.whos_next || [];
  const rows = wn.length ? wn.map((w) => `
    <button class="nv-wn" data-ip="${esc(w.host)}">
      <span class="nv-wn-ip">${esc(w.hostname || w.host)}</span>
      <span class="nv-wn-stage" style="color:#${(STAGE[w.stage_id] || STAGE[0]).color.toString(16)}">${esc((STAGE[w.stage_id]||STAGE[0]).name)}</span>
      <span class="nv-wn-eta">${w.eta ? "in " + esc(w.eta) : "now"}</span>
      <span class="nv-wn-risk">${pct(w.peak_risk)}</span>
    </button>`).join("") : `<div class="nv-muted">No devices are forecast to be compromised right now.</div>`;
  document.getElementById("nv-topo-summary").innerHTML =
    `<b>${fc.device_count || 0}</b> devices · <b>${fc.monitored_count || 0}</b> monitored · ` +
    `mode <b style="color:${fc.mode === "enforce" ? "#f87171" : "#94a3b8"}">${esc(fc.mode || "—")}</b> · ` +
    `<span style="color:${fc.stale ? "#f59e0b" : "#4ade80"}">${fc.stale ? "STALE" : "LIVE"}</span>`;
  document.getElementById("nv-topo-next").innerHTML = rows;
  panel.querySelectorAll(".nv-wn").forEach((b) =>
    b.addEventListener("click", () => selectDevice(b.dataset.ip)));
}

async function selectDevice(ip) {
  const node = nodes.get(ip);
  selected = ip; controls.autoRotate = false;
  const box = document.getElementById("nv-topo-detail");
  const d = (node && node.data) || fcDevices.get(ip) || null;
  box.innerHTML = `<div class="nv-det-head">${esc(d && d.hostname || ip)} <span class="nv-muted">${esc(ip)}</span></div>
    ${d && d.has_telemetry ? `
      <div class="nv-det-grid">
        <div><span>state</span><b>${esc(d.forecast_state)}</b></div>
        <div><span>peak risk</span><b>${pct(d.peak_risk)}</b></div>
        <div><span>stage</span><b>${esc((STAGE[d.stage_id]||STAGE[0]).name)}</b></div>
        <div><span>detector</span><b>${pct((d.detector||{}).attack_now)}</b></div>
      </div>
      <div class="nv-muted nv-sig">${esc((d.detector||{}).signature||"")}</div>
      <button id="nv-advise" class="nv-btn">Get AI recommendation</button>
      <div id="nv-advise-out"></div>`
    : `<div class="nv-muted">Discovered device — no live flow telemetry (forecasting runs on the sensor and attack participants).</div>`}`;
  const btn = document.getElementById("nv-advise");
  if (btn) btn.addEventListener("click", () => advise(ip));
}

async function advise(ip) {
  const out = document.getElementById("nv-advise-out");
  out.innerHTML = `<div class="nv-muted">Consulting the two-tier model…</div>`;
  try {
    const r = await api(`/api/network/advise?host=${encodeURIComponent(ip)}`);
    const a = r.actionable || {};
    if (a.monitor_only || !a.action_type) {
      out.innerHTML = `<div class="nv-advise"><b>Monitor only.</b><p>${esc(a.rationale || "No containment recommended yet.")}</p></div>`;
      return;
    }
    out.innerHTML = `<div class="nv-advise">
      <div class="nv-advise-head">${esc(a.headline || a.action_type)}
        <span class="nv-badge">${esc(a.source || "")} · ${Math.round((a.confidence||0)*100)}%</span></div>
      <p>${esc(a.rationale || "")}</p>
      <div class="nv-rule">${esc(a.rule_preview || "")}  ·  TTL ${esc(a.ttl_seconds || 300)}s</div>
      ${(a.steps||[]).length ? "<ol>" + a.steps.map((s)=>`<li>${esc(s)}</li>`).join("") + "</ol>" : ""}
      ${a.guard_note ? `<div class="nv-guard">${esc(a.guard_note)}</div>` : ""}
      <div class="nv-muted">Approve/execute controls arrive with the enforcement panel.</div>
    </div>`;
  } catch (e) {
    out.innerHTML = `<div class="nv-err">${esc(e.message)}</div>`;
  }
}

// ---------------------------------------------------------------- click picking
renderer.domElement.addEventListener("pointerdown", (ev) => {
  const rect = renderer.domElement.getBoundingClientRect();
  pointer.x = ((ev.clientX - rect.left) / rect.width) * 2 - 1;
  pointer.y = -((ev.clientY - rect.top) / rect.height) * 2 + 1;
  raycaster.setFromCamera(pointer, camera);
  const hits = raycaster.intersectObjects([...nodes.values()].map((n) => n.mesh));
  if (hits.length) selectDevice(hits[0].object.userData.ip);
});

// ---------------------------------------------------------------- animation
const clock = new THREE.Clock();
function animate() {
  requestAnimationFrame(animate);
  const t = clock.getElapsedTime();
  for (const [, n] of nodes) {
    if (n.alerting) {
      const s = (1 + (n.risk || 0) * 0.8) * (1 + 0.12 * Math.sin(t * 5));
      n.mesh.scale.setScalar(s);
    }
  }
  for (let i = pulses.length - 1; i >= 0; i--) {
    const p = pulses[i];
    p.t += 0.02;
    p.m.position.lerpVectors(p.from, p.to, p.t);
    if (p.t >= 1) { scene.remove(p.m); pulses.splice(i, 1); }
  }
  controls.update();
  renderer.render(scene, camera);
}

// ---------------------------------------------------------------- boot + poll
async function boot() {
  try {
    const topo = await api("/api/network/topology");
    if (!topo.available) {
      document.getElementById("nv-topo-summary").innerHTML =
        `<span class="nv-err">No network roster yet — run scripts/discover_network.py on the sensor.</span>`;
    } else {
      buildGraph(topo);
    }
  } catch (e) { /* keep polling */ }
  resize();
  animate();
  poll();
}
async function poll() {
  try {
    const fc = await api("/api/network/forecast");
    if (fc.available) applyForecast(fc);
  } catch (e) { /* transient */ }
  setTimeout(poll, 4000);
}
boot();
