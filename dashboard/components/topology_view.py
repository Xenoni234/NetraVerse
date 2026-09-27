"""3D host-topology view (three.js) as a Streamlit Custom Component v2.

The heavy module (three.js + scene code, bundled offline by esbuild into
components/topology3d/dist/topology3d.js) is served by the local API and
imported once; each rerun only pushes new node/edge data, so the scene, camera
and animation survive replay ticks.
"""
from __future__ import annotations

import streamlit as st

from dashboard.components.api_client import PUBLIC_API_URL

_HTML = """
<div class="nv-wrap">
  <div id="nv-topo"></div>
  <div id="nv-tip"></div>
  <div class="nv-legend">
    <span><i style="background:#C0472C"></i>attacker</span>
    <span><i style="background:#C98A2C"></i>victim</span>
    <span><i style="background:#8A9098"></i>normal</span>
    <span><i style="background:#4B8A5E"></i>mitigated</span>
  </div>
</div>
"""

_CSS = """
.nv-wrap { position: relative; width: 100%; height: var(--nv-h, 520px); background: #14161A;
           border: 1px solid #2C313A; border-radius: 3px; overflow: hidden; }
#nv-topo { position: absolute; inset: 0; }
#nv-topo canvas { display: block; width: 100%; height: 100%; }
#nv-tip { position: absolute; display: none; pointer-events: none; background: #20242B; color: #E6E6E6;
          border: 1px solid #2C313A; padding: 6px 8px; font: 12px/1.4 "IBM Plex Mono", Consolas, monospace; }
.nv-legend { position: absolute; left: 8px; bottom: 8px; display: flex; gap: 12px;
             font: 11px "IBM Plex Mono", Consolas, monospace; color: #9AA0A6;
             background: rgba(20,22,26,.8); padding: 4px 8px; border: 1px solid #2C313A; }
.nv-legend i { display: inline-block; width: 9px; height: 9px; border-radius: 50%; margin-right: 5px;
               vertical-align: -1px; }
"""

_JS = """
let modPromise = null;
export default async function (component) {
  const { data, parentElement } = component;
  const wrap = parentElement.querySelector(".nv-wrap");
  if (wrap && data && data.height) wrap.style.setProperty("--nv-h", data.height + "px");
  if (!modPromise) modPromise = import(data.bundle_url);
  const mod = await modPromise;
  mod.render(component);
}
"""

_COMPONENT = st.components.v2.component("netraverse_topology3d", html=_HTML, css=_CSS, js=_JS)


def topology_view(snapshot: dict, *, key: str, height: int = 520, selected: str | None = None):
    """Render the 3D topology. Returns the clicked host id (trigger) or None."""
    data = {
        "nodes": snapshot.get("nodes", []),
        "edges": snapshot.get("edges", []),
        "selected": selected,
        "height": height,
        "bundle_url": f"{PUBLIC_API_URL}/static/topology3d.js",
    }
    res = _COMPONENT(data=data, key=key, height=height, on_clicked_change=lambda: None)
    return getattr(res, "clicked", None)
