# NetraVerse demo script (2 minutes)

The story arc: baseline → attack escalation → detection with explanation → decision → re-rollout showing the risk drop.

## A. File replay (always works, offline)

1. Start the backend with `uvicorn src.api.main:app --port 8000`. Then start the dashboard with `streamlit run dashboard/app.py`.
2. In the sidebar pick **CSV Upload**, then choose the bundled sample `cic2017_webattack_thursday.csv` and click **Analyse**.
3. Press **▶ Play** at 2x.
   - The 3D host graph shows the lab network. The forecast curve on the right builds one 60 s window at a time.
   - The dashed segment is the world model's own 300 s imagined rollout from the current window.
4. Around t+15 min the web brute force starts. The attacker's NAT address (`172.16.0.1`) turns red-orange and the web server (`192.168.10.50`) turns amber. Hot edges carry attack particles.
   - The attacker and victim roles are derived from the forecast plus traffic direction. They are not hardcoded.
5. At the first sustained alert (t+16 min) playback **pauses** on its own. The decision panel shows:
   - the stage (Initial Access, TA0001)
   - the recommended action from the rule engine (block `172.16.0.1 -> 192.168.10.50:80`)
   - its rationale
   - the integrated-gradients evidence
6. Click **Accept**. The recorded traffic is replayed with the block applied from that minute onward.
   - The green curve is the re-simulated future. The grey dotted curve is what actually happened without the action.
   - The counterfactual panel shows the peak before and after.
7. **⏮ Restart**, then **Reject**, shows the cost of inaction on the same timeline. **Modify** offers the rule engine's alternatives (rate-limit, block only the pair, …).

Other samples (all alert except the PortScan and CTU-13 slices):
- `cic2017_bruteforce_tuesday.csv`: FTP/SSH-Patator, Initial Access
- `cic2017_portscan_friday.csv`: the scan peaks at about 0.70 forecast risk, below the 0.85 alert threshold. Its main burst sits in the validation blocks, so the model saw few scans in training. This is shown honestly rather than tuned away.
- `cic2017_dos_wednesday.csv`: slowloris/slowhttptest, Impact
- `cic2017_botnet_friday.csv`: Ares bot, Command and Control
- `ctu13_botnet_scenario10.binetflow`: Rbot ICMP DDoS from 10 infected hosts. The bots' risk stays below the threshold (CTU-13 recall is 0.33 at this operating point).

## B. Live home network (Phase 8/11)

> **Status:** the shipped model does not yet recognise attacks on the home network (see `docs/LIVE_SENSOR.md`). Do the lab retraining first, and use file replay (A) for the demo until then.

1. On the sensor laptop, start `nv-core` exactly as in `docs/LIVE_SENSOR.md`.
2. On the dashboard PC, run `NV_API_URL=http://<sensor>:8000 streamlit run dashboard/app.py`, go to **Live Monitor**, and click **Start sensor**.
3. Run the attack from the attacker machine against your **own** lab VM only (R11): `NV_I_OWN_THIS_TARGET=yes demo/attack_scripts/run_sequence.sh 192.168.0.50`.
4. When the alert fires, click **Accept** (operator token in the sidebar). A real nftables rule is installed on the sensor with a TTL. The live curve then re-measures the real traffic and should fall.
5. **Fallback (R12):** record the same sequence with `tcpdump` into `demo/fallback_pcap/live_demo.pcap`. If live capture fails during judging, replay it in **PCAP Upload** mode. You can also rehearse the live pipeline with `NV_LIVE_REPLAY_PCAP=demo/fallback_pcap/live_demo.pcap`.
