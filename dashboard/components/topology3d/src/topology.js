// NetraVerse 3D host topology (ported from the original frontend/src/topology/main.js).
// Rendered inside a Streamlit CCv2 component. Glow, alert pulsing and attack
// particles are kept from the original design; node colours now encode the
// model-derived role (attacker / victim / normal / mitigated).
import * as THREE from "three";
import { OrbitControls } from "three/examples/jsm/controls/OrbitControls.js";

const ROLE = {
  attacker:  0xc0472c,
  victim:    0xc98a2c,
  normal:    0x8a9098,
  mitigated: 0x4b8a5e,
};
const STAGE_NAMES = ["Benign", "Reconnaissance", "Initial Access", "Lateral Movement",
                     "Command & Control", "Exfiltration", "Impact"];
const BG = 0x14161a;
const instances = new WeakMap();

function makeLabel(text) {
  const cv = document.createElement("canvas");
  const ctx = cv.getContext("2d");
  const font = "500 26px 'IBM Plex Mono', 'JetBrains Mono', monospace";
  ctx.font = font;
  const w = Math.ceil(ctx.measureText(text).width) + 20;
  cv.width = w; cv.height = 40;
  ctx.font = font;
  ctx.fillStyle = "rgba(20,22,26,0.78)"; ctx.fillRect(0, 0, w, 40);
  ctx.fillStyle = "#e6e6e6"; ctx.textBaseline = "middle";
  ctx.fillText(text, 10, 22);
  const tex = new THREE.CanvasTexture(cv);
  tex.colorSpace = THREE.SRGBColorSpace;
  const spr = new THREE.Sprite(new THREE.SpriteMaterial({ map: tex, depthTest: false, transparent: true }));
  spr.scale.set(w * 0.055, 2.2, 1);
  spr.renderOrder = 10;
  return spr;
}

function slot(i) {
  // stable Fibonacci-sphere slot for the i-th node ever seen
  const n = 64;
  const k = i % n, shell = Math.floor(i / n);
  const phi = Math.acos(1 - 2 * (k + 0.5) / n);
  const theta = Math.PI * (1 + Math.sqrt(5)) * k;
  const R = 44 + shell * 16;
  return new THREE.Vector3(R * Math.sin(phi) * Math.cos(theta), R * Math.cos(phi) * 0.6,
                           R * Math.sin(phi) * Math.sin(theta));
}

function create(root, setTriggerValue) {
  const mount = root.querySelector("#nv-topo");
  const tip = root.querySelector("#nv-tip");
  const scene = new THREE.Scene();
  scene.background = new THREE.Color(BG);
  scene.fog = new THREE.FogExp2(BG, 0.0055);
  const camera = new THREE.PerspectiveCamera(55, 1, 0.1, 2000);
  camera.position.set(0, 60, 130);
  const renderer = new THREE.WebGLRenderer({ antialias: true });
  renderer.setPixelRatio(Math.min(2, window.devicePixelRatio));
  mount.appendChild(renderer.domElement);
  const controls = new OrbitControls(camera, renderer.domElement);
  controls.enableDamping = true;
  controls.autoRotate = true;
  controls.autoRotateSpeed = 0.35;
  scene.add(new THREE.AmbientLight(0xffffff, 0.6));
  const key = new THREE.DirectionalLight(0xffffff, 0.8);
  key.position.set(50, 120, 80);
  scene.add(key);
  const grid = new THREE.GridHelper(400, 40, 0x2c313a, 0x20242b);
  grid.position.y = -24;
  scene.add(grid);

  const st = {
    scene, camera, renderer, controls, mount, tip, setTriggerValue,
    nodes: new Map(), edges: new Map(), pulses: [], order: new Map(),
    raycaster: new THREE.Raycaster(), pointer: new THREE.Vector2(), alive: true,
    clock: new THREE.Clock(), selected: null,
  };

  const resize = () => {
    const w = mount.clientWidth, h = mount.clientHeight;
    if (!w || !h) return;
    renderer.setSize(w, h, false);
    camera.aspect = w / h; camera.updateProjectionMatrix();
  };
  st.ro = new ResizeObserver(resize);
  st.ro.observe(mount);
  resize();

  const pick = (ev) => {
    const r = renderer.domElement.getBoundingClientRect();
    st.pointer.x = ((ev.clientX - r.left) / r.width) * 2 - 1;
    st.pointer.y = -((ev.clientY - r.top) / r.height) * 2 + 1;
    st.raycaster.setFromCamera(st.pointer, camera);
    const hits = st.raycaster.intersectObjects([...st.nodes.values()].map((n) => n.mesh));
    return hits.length ? hits[0].object.userData.id : null;
  };
  renderer.domElement.addEventListener("pointerdown", (ev) => {
    const id = pick(ev);
    if (id) { controls.autoRotate = false; st.setTriggerValue("clicked", id); }
  });
  renderer.domElement.addEventListener("pointermove", (ev) => {
    const id = pick(ev);
    if (!id) { tip.style.display = "none"; return; }
    const d = st.nodes.get(id).data;
    tip.style.display = "block";
    tip.style.left = `${ev.offsetX + 14}px`;
    tip.style.top = `${ev.offsetY + 10}px`;
    tip.innerHTML = `<b>${d.id}</b><br>role ${d.role}<br>risk ${(d.risk * 100).toFixed(1)}%` +
      `<br>stage ${STAGE_NAMES[d.stage] || "-"}<br>flows now ${d.flows_now}`;
  });

  const animate = () => {
    if (!st.alive) return;
    if (!mount.isConnected) {            // Streamlit unmounted us: release GPU resources
      st.alive = false; st.ro.disconnect(); renderer.dispose(); return;
    }
    requestAnimationFrame(animate);
    const t = st.clock.getElapsedTime();
    for (const [, n] of st.nodes) {
      const base = n.baseScale;
      n.mesh.scale.setScalar(n.alerting ? base * (1 + 0.12 * Math.sin(t * 5)) : base);
      n.halo.visible = n.alerting;
      if (n.alerting) {
        n.halo.scale.setScalar(base * (1.9 + 0.25 * Math.sin(t * 5)));
        n.halo.material.opacity = 0.18 + 0.1 * Math.sin(t * 5);
      }
    }
    for (const [, e] of st.edges) {
      if (e.hot && Math.random() < 0.06) spawnPulse(st, e);
    }
    for (let i = st.pulses.length - 1; i >= 0; i--) {
      const p = st.pulses[i];
      p.t += 0.02;
      p.m.position.lerpVectors(p.from, p.to, p.t);
      if (p.t >= 1) { scene.remove(p.m); p.m.geometry.dispose(); st.pulses.splice(i, 1); }
    }
    controls.update();
    renderer.render(scene, camera);
  };
  animate();
  return st;
}

function spawnPulse(st, e) {
  const a = st.nodes.get(e.a), b = st.nodes.get(e.b);
  if (!a || !b) return;
  const fromAtk = a.data.role === "attacker" || b.data.role !== "attacker";
  const from = (fromAtk ? a : b).mesh.position, to = (fromAtk ? b : a).mesh.position;
  const m = new THREE.Mesh(new THREE.SphereGeometry(0.8, 8, 8), new THREE.MeshBasicMaterial({ color: 0xe0a08a }));
  st.scene.add(m);
  st.pulses.push({ m, from: from.clone(), to: to.clone(), t: 0 });
}

function update(st, data) {
  const nodes = data.nodes || [];
  const seen = new Set();
  for (const d of nodes) {
    seen.add(d.id);
    let n = st.nodes.get(d.id);
    if (!n) {
      if (!st.order.has(d.id)) st.order.set(d.id, st.order.size);
      const pos = slot(st.order.get(d.id));
      const mat = new THREE.MeshStandardMaterial({ color: ROLE.normal, emissive: 0x000000, metalness: 0.3, roughness: 0.5 });
      const mesh = new THREE.Mesh(new THREE.SphereGeometry(2.4, 24, 24), mat);
      mesh.position.copy(pos);
      mesh.userData.id = d.id;
      const halo = new THREE.Mesh(new THREE.SphereGeometry(2.4, 24, 24),
        new THREE.MeshBasicMaterial({ color: ROLE.attacker, transparent: true, opacity: 0.2, depthWrite: false }));
      halo.position.copy(pos);
      const label = makeLabel(d.id);
      st.scene.add(mesh); st.scene.add(halo); st.scene.add(label);
      n = { mesh, halo, label, data: d, baseScale: 1, alerting: false };
      st.nodes.set(d.id, n);
    }
    const col = ROLE[d.role] ?? ROLE.normal;
    n.data = d;
    n.alerting = !!d.alerting || d.role === "attacker";
    n.mesh.material.color.setHex(col);
    n.mesh.material.emissive.setHex(n.alerting ? col : 0x000000);
    n.mesh.material.emissiveIntensity = n.alerting ? 0.9 : 0;
    n.halo.material.color.setHex(col);
    n.baseScale = 1 + Math.min(1, d.risk || 0) * 0.8 + Math.min(0.6, Math.log10(1 + (d.flows_total || 0)) * 0.08);
    const s = n.baseScale * 2.4;
    n.label.position.copy(n.mesh.position).add(new THREE.Vector3(0, s + 2.6, 0));
    const important = d.role !== "normal" || d.alerting || d.id === data.selected;
    n.label.visible = important || nodes.length <= 25;
  }
  for (const [id, n] of st.nodes) {
    if (!seen.has(id)) {
      st.scene.remove(n.mesh); st.scene.remove(n.halo); st.scene.remove(n.label);
      st.nodes.delete(id);
    }
  }
  const eseen = new Set();
  for (const e of data.edges || []) {
    const k = `${e.a}|${e.b}`;
    eseen.add(k);
    const a = st.nodes.get(e.a), b = st.nodes.get(e.b);
    if (!a || !b) continue;
    let ed = st.edges.get(k);
    if (!ed) {
      const g = new THREE.BufferGeometry().setFromPoints([a.mesh.position, b.mesh.position]);
      const line = new THREE.Line(g, new THREE.LineBasicMaterial({ color: 0x3a4250, transparent: true, opacity: 0.45 }));
      st.scene.add(line);
      ed = { line, a: e.a, b: e.b };
      st.edges.set(k, ed);
    }
    ed.hot = !!e.hot;
    ed.line.material.color.setHex(e.hot ? ROLE.attacker : (e.active ? 0x5b6472 : 0x3a4250));
    ed.line.material.opacity = e.hot ? 0.95 : (e.active ? 0.7 : 0.35);
  }
  for (const [k, ed] of st.edges) {
    if (!eseen.has(k)) { st.scene.remove(ed.line); ed.line.geometry.dispose(); st.edges.delete(k); }
  }
  if (data.selected && data.selected !== st.selected) {
    st.selected = data.selected;
    const n = st.nodes.get(data.selected);
    if (n) { st.controls.autoRotate = false; st.controls.target.copy(n.mesh.position); }
  }
}

export function render(component) {
  const { data, parentElement, setTriggerValue } = component;
  let st = instances.get(parentElement);
  if (!st) {
    st = create(parentElement, setTriggerValue);
    instances.set(parentElement, st);
  }
  st.setTriggerValue = setTriggerValue;
  update(st, data || {});
}
