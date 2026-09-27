# Troubleshooting

Problems we hit while building and deploying, and how to fix each one.

| Symptom | Cause | Fix |
|---|---|---|
| Live Monitor says "sensor not running" / "stopped" | The API you are connected to has no capture interface | Start the API on the sensor with `NV_LIVE_IFACE=<iface>`, point the dashboard at it with `NV_API_URL`, then click **Start sensor**. |
| Start sensor on **Windows** fails | Scapy has no libpcap provider | Install Npcap (WinPcap-compatible mode) and set `NV_LIVE_IFACE="Wi-Fi"`. This only sees the PC's own traffic, so use the Linux sensor for the demo. |
| Accept in Live Monitor "does nothing" / 403 in API log | Missing or wrong operator token. It is stored **per browser tab and port**. | Type the token in the sidebar of *that* dashboard. The page now shows the error persistently. |
| `nft failed` / `sudo: a password is required` | sudoers allows only `/usr/sbin/nft` | Already handled: rules run as `sudo -n nft ...` (argv). Make sure the sudoers `NOPASSWD: /usr/sbin/nft` entry exists. |
| `CUDA error: no kernel image is available` / `CUBLAS_STATUS_ARCH_MISMATCH` | The torch wheel doesn't support the GPU (cu13x dropped Pascal, e.g. the GTX 1060) | Automatic CPU fallback (`service.pick_device`). Force it with `NV_DEVICE=cpu`, or install a torch build for your GPU. |
| Narration says "template (local LLM off or unavailable)" | Ollama isn't running, the model isn't pulled, or the first call is still loading it (~1 min cold start) | `ollama serve`, then `ollama pull qwen2.5:3b` (or set `NV_OLLAMA_MODEL`). The API warms the model up at start; later calls take ~1–3 s. Set `NV_NARRATION=0` to silence it. |
| Dashboard: "Unknown upload id" | The API restarted. Uploads live in memory. | Upload or Analyse again. |
| 3D topology is blank | The browser cannot reach `<NV_API_PUBLIC_URL>/static/topology3d.js` | Set `NV_API_PUBLIC_URL` to an address the *browser* can reach (e.g. the Tailscale IP). |
| Play does nothing / stops after one step | Old dashboard session | Reload the page. Play/pause/speed now trigger a full rerun to re-arm the timer. |
| Port 8000/8501 already in use | Another API/dashboard (or Docker) is running | Stop it, or use `--port` / `--server.port`. |
| Laptop `git pull` fails with `Could not resolve host: github.com` | DNS on the laptop | Use the git-bundle deploy in [LIVE_SENSOR.md](LIVE_SENSOR.md#deploy--update). |
| `ssh laptop` times out | Laptop Tailscale offline, or its LAN IP changed (it moved from `.203` to `.101`) | `sudo tailscale up` on the laptop; check `tailscale status`. |
| A sample never alerts (PortScan, CTU-13 scenario 10) | Genuine model limitation at the validated threshold (see TRAINING.md) | Demo with the web-attack / brute-force / DoS / botnet samples. Do not lower the threshold for the demo (R1). |
| `load_checkpoint`: "feature schema does not match" | `schema.py` changed after training | Retrain (`build_dataset`, then `train_world_model`). |
| Polars `is_in` deprecation warnings | Newer Polars | Already fixed with `.implode()`; update the code if new ones appear. |
