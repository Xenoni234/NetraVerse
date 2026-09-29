# NetraVerse demo walkthrough

The story arc: baseline → attack escalation → forecast with explanation → decision → re-rollout showing the risk change.

## Analyst console (netraverse_ui)

```bash
cd netraverse_ui && python server.py     # -> http://localhost:8600
```

Open the landing page → **Launch analyst console**. Three modes share one model and one decision loop:

**CSV Upload**
1. Upload a flow CSV (e.g. `demo/samples/netraverse_campaign.csv`) → the pipeline parses it and builds the host graph from the real IPs in the file.
2. Press **▶ Replay** (1x / 2x / 4x). Campaigns are forecast *ahead of onset*; at the first sustained alert playback pauses and the decision modal opens with the MITRE stage, probability, lead time, SHAP evidence and a local-LLM narration.
3. Choose **Accept / Modify / Reject** — Accept mitigates (risk decays), Reject shows the cost of inaction (risk rises to Impact). Later campaigns are forecast independently.
4. When the replay finishes, the analysis appears below the topology: the full forecast chart, the observed-vs-imagined state map, the attack-forecast log, the decision audit (risk before/after) and per-campaign SHAP.

**PCAP Upload** — upload a capture (e.g. `demo/fallback_pcap/netraverse_campaign.pcap`); the packets are parsed to flows, the host graph is rebuilt from the real IPs, and the same forecast → decide flow runs.

**Live Monitor** — a live sensor stream with a stable benign baseline. Drive campaigns from a second terminal:

```bash
python launch_recon_scan.py        # start a campaign (Ctrl+C to stop it)
python launch_brute_force.py
python stop_attack.py              # stop all active campaigns
```

Each launched campaign is forecast in real time; Accept/Modify/Reject behave as in upload mode.

## Backend + Streamlit dashboard

1. Start the backend: `uvicorn src.api.main:app --port 8000`. Then the dashboard: `streamlit run dashboard/app.py`.
2. Pick **CSV Upload**, choose a bundled sample (e.g. `cic2017_webattack_thursday.csv`) and click **Analyse**.
3. Press **▶ Play** at 2x.
   - The 3D host graph shows the network. The forecast curve builds one 60 s window at a time; the dashed segment is the world model's 300 s imagined rollout from the current window.
   - Attacker/victim roles are derived from the forecast plus traffic direction, not hardcoded.
4. At the first sustained alert, playback **pauses**. The decision panel shows the MITRE stage, the recommended action from the rule engine, its rationale and the integrated-gradients evidence.
5. Click **Accept** — the traffic is re-rolled with the action applied. The counterfactual panel compares the risk peak before and after. **Reject** shows the cost of inaction; **Modify** offers the rule engine's alternatives.
6. Optional: **Generate incident report (PDF)** for a one-page summary.

## Live monitoring

For live capture and enforcement (nftables), see [LIVE_SENSOR.md](../docs/LIVE_SENSOR.md). Test only against devices you own; keep a fallback PCAP of the sequence and replay it via **PCAP Upload** or `NV_LIVE_REPLAY_PCAP` if live capture is unavailable.
