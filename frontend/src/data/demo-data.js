// Demonstration fixtures: this is intentionally local, not a fake backend.
// The Stitch documents remain the presentation source of truth; these route and
// context values are ready to be replaced by API-backed state later.
export const appContext = {
  scenario: { id: "cse-cic-ids2018-port-scan", label: "CSE-CIC-IDS2018 · Port Scan" },
  host: { address: "172.31.64.14" },
  mode: "Offline Replay",
  horizons: [30, 60, 90, 120],
  timestamp: "2024-10-24 14:32:10 UTC"
};

export const pages = {
  home: { title: "Home", document: "/home" },
  simulate: { title: "Simulate", document: "/simulate" },
  forecast: { title: "Forecast", document: "/forecast" },
  attack: { title: "ATT&CK", document: "/attack" },
  investigate: { title: "Investigate", document: "/investigate" },
  network: { title: "Network", document: "/network" },
  validate: { title: "Validate", document: "/validate" },
  model: { title: "Model", document: "/model" }
};
