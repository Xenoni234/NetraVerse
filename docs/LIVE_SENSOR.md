# Live sensor (Phase 8/11)

## How it works

`src/live/sniffer.py::LiveMonitor` runs inside the API process:

1. A Scapy `AsyncSniffer` on `NV_LIVE_IFACE` feeds `LiveFlowGen`. This is the *same* flow assembler as PCAP upload.
2. Every `NV_LIVE_TICK_S` (15 s), the last 11 minutes of flows are windowed. The windows **end at "now"**, giving a sliding 60 s window with a 15 s stride.
3. The windows go through the same `Service.analyze` as file uploads, stored as the analysis with id `live`. Per-host risk history is kept for the chart.
4. Inference takes about 0.1–0.2 s per tick on the laptop CPU.

Accept/Modify in Live Monitor calls `src/live/action_executor.py`:
- It builds `nft add rule inet netraverse <forward|input|output> ... drop comment "nv:<action>"`.
- It runs each rule as `sudo -n nft ...` (argv, no shell), so a sudoers entry `NOPASSWD: /usr/sbin/nft` is enough.
- It refuses anything in `NV_PROTECTED_IPS`, and only applies rules when `NV_ENFORCE=1`.
- `action_executor.revoke(action_id)` removes the rules. The nftables comment marks each rule with its action id and TTL.

## Our sensor laptop

| | |
|---|---|
| Host | `ssh laptop` (Ubuntu, Tailscale `100.72.80.52`, LAN `192.168.0.101` on `wlp0s20f3`) |
| Repo | `/opt/netraverse`, branch `rebuild`, venv `/opt/netraverse/.venv` (Python 3.12) |
| Capture rights | `/usr/bin/python3.12` has `cap_net_raw,cap_net_admin`, so no root is needed |
| nft | `NOPASSWD: /usr/sbin/nft` in sudoers |
| GPU | GTX 1060 is not supported by the installed torch cu130 build, so it runs on CPU automatically |
| Ollama | local, model `qwen2.5-coder:3b` |

### Deploy / update

```bash
ssh laptop
cd /opt/netraverse && git fetch origin && git checkout rebuild && git pull
.venv/bin/pip install -r requirements.txt     # after dependency changes
```

If the laptop cannot reach GitHub (we saw DNS failures), push a bundle from the dev PC:

```bash
git bundle create nv.bundle rebuild && scp nv.bundle laptop:/tmp/
ssh laptop 'cd /opt/netraverse && git fetch /tmp/nv.bundle rebuild:refs/remotes/origin/rebuild && git merge --ff-only origin/rebuild'
```

### Run as a service

The service is a systemd *user* unit, so it survives the SSH session ending. The old `nv-api` / `nv-live` units belong to the previous code; `nv-api` is disabled.

```bash
systemctl --user stop nv-core; systemctl --user reset-failed nv-core
systemd-run --user --no-block --unit=nv-core --working-directory=/opt/netraverse \
  --setenv=PYTHONUNBUFFERED=1 --setenv=NV_LIVE_IFACE=wlp0s20f3 \
  --setenv=NV_ENFORCE=1 --setenv=NV_OPERATOR_TOKEN=<token> \
  --setenv=NV_OLLAMA_MODEL=qwen2.5-coder:3b \
  --setenv=NV_PROTECTED_IPS=127.0.0.1,100.72.80.52,100.81.46.8,192.168.0.101,192.168.0.1 \
  /opt/netraverse/.venv/bin/python -m uvicorn src.api.main:app --host 0.0.0.0 --port 8000
curl -X POST localhost:8000/live/start        # or the "Start sensor" button
journalctl --user -u nv-core -f               # logs
```

- Set `NV_ENFORCE=0` while rehearsing. Accept then only *shows* the nft rules.
- Put every management address in `NV_PROTECTED_IPS`: sensor, dashboard PC and gateway.
- On the dashboard PC, set `NV_API_URL=http://100.72.80.52:8000`, open **Live Monitor**, and type the operator token in the sidebar. The token is per browser session.

## Current state (read before demoing live)

The shipped model was trained only on public datasets. On the home network it keeps benign traffic at about 0–5% risk. But it **did not flag a real TCP port scan** (168 ports in a minute scored 0%), and it raised occasional false alerts on external servers.

Do not rely on live detection until the model has been retrained with lab captures. See [TRAINING.md, "Retraining on your own lab"](TRAINING.md#retraining-on-your-own-lab-next-step-for-the-team). Until then, demo with **file replay**. It is reliable and shows the whole Accept/Modify/Reject loop.

## Rules for live testing

- Attack only devices you own (R11). The scripts refuse non-RFC1918 targets and require `NV_I_OWN_THIS_TARGET=yes`.
- Always record a fallback PCAP of the exact demo sequence (R12). Replay it with **PCAP Upload** or `NV_LIVE_REPLAY_PCAP`.
