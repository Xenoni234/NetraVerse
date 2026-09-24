# Demo capture samples (real CIC-IDS2017 slices)

Upload any of these on the Simulate page. Each is a raw slice of a CIC-IDS2017
TrafficLabelling day (original CICFlowMeter columns), keeping a benign lead-in
before the labelled attack. Nothing is synthetic.

## Recommended: Decision-Theater demo — `sample_ddos_multihost.csv`

The best file for the **decision theater** (auto-pause → ranked options →
accept → mitigated continuation → before/after). It is a multi-host slice of the
Friday DDoS capture: the attacker `172.16.0.1` floods for ~20 min alongside four
benign hosts (`192.168.10.3/.12/.15/.50`). Verified on the served
`wm_sih_demo` checkpoint:

- Attacker forecast peak risk **~0.95** (fires the alert; 33 forecast windows of
  runway so the mitigated curve has room to settle).
- Options are **differentiated by real simulated Δrisk**: *Block source IP* and
  *Isolate host* → risk **0.95 → 0.00, attack prevented**; *Rate-limit* →
  **0.95 → 0.96, not prevented** (throttling doesn't stop a flood — honest).

The capture is minute-resolution; each minute's flows are spread across its 60 s
(the flood's flows genuinely arrived throughout the minute) so the model sees the
30 s windows it was trained on. No flows are added or removed.

| File | Attack type | ATT&CK stage | Rows | Attack rows | Benign lead |
|------|-------------|--------------|------|-------------|-------------|
| `portscan_recon.csv` | Port scan | Reconnaissance | 80000 | 158930 | 1463 |
| `botnet_c2.csv` | Botnet | Command & Control | 80000 | 1966 | 24072 |
| `ddos_impact.csv` | DDoS | Impact | 80000 | 128027 | 18883 |
| `dos_hulk_impact.csv` | DoS Hulk | Impact | 80000 | 231073 | 30000 |
| `ftp_bruteforce_initial_access.csv` | FTP brute force | Initial Access | 80000 | 7938 | 11347 |
| `ssh_bruteforce_initial_access.csv` | SSH brute force | Initial Access | 80000 | 5897 | 30000 |
| `infiltration_lateral.csv` | Infiltration | Lateral Movement | 80000 | 36 | 30000 |
| `webattack_initial_access.csv` | Web attack | Initial Access | 80000 | 2180 | 12637 |

> Forecast behaviour (before-onset vs at-onset) is model-dependent; verify by upload.

## Verified behaviour on the current `wm_final` model (auto-selected host)

| File | Top-host peak risk | Fires alert? | Notes |
|------|--------------------|--------------|-------|
| `ftp_bruteforce_initial_access.csv` | ~0.94 | **yes (strong)** | Risk rises 0.51 → 0.77 → 0.94 across horizons. Best demo. |
| `portscan_recon.csv` | ~0.39 | yes | Crosses the 0.28 threshold; short benign lead-in. |
| `botnet_c2.csv` | ~0.00 (this host) | no | The bot victim is not the auto-selected host; pick another, or improve after retrain. |
| `ddos_impact.csv` | ~0.00 | no | DDoS/DoS onset is not forecast by the current model (data ceiling — see roadmap). |
| others | not yet verified | — | Verify by upload; DoS/infiltration/web likely weak until retrain. |

The stage head predicts BENIGN on most of these even when the **risk** head fires — the onset-risk
forecast (the headline) is the strong signal; the stage label is a known weak point. Retraining
(see `scripts/train_world_model.py`) targets broader attack-type coverage.