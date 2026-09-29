# Live sensor

## How it works

`src/live/sniffer.py::LiveMonitor` runs inside the API process:

1. A Scapy `AsyncSniffer` on `NV_LIVE_IFACE` feeds `LiveFlowGen`. This is the *same* flow assembler as PCAP upload.
2. Every `NV_LIVE_TICK_S` (15 s), the last 11 minutes of flows are windowed. The windows **end at "now"**, giving a sliding 60 s window with a 15 s stride.
3. The windows go through the same `Service.analyze` as file uploads, stored as the analysis with id `live`. Per-host risk history is kept for the chart.
4. Inference takes about 0.1–0.2 s per tick on a CPU.

Accept/Modify in Live Monitor calls `src/live/action_executor.py`:

- It builds `nft add rule inet netraverse <forward|input|output> ... drop comment "nv:<action>"`.
- It runs each rule as `sudo -n nft ...` (argv, no shell), so a sudoers entry `NOPASSWD: /usr/sbin/nft` is enough.
- It refuses anything in `NV_PROTECTED_IPS`, and only applies rules when `NV_ENFORCE=1` (otherwise it is a dry-run that just shows the rules).
- `action_executor.revoke(action_id)` removes the rules. The nftables comment marks each rule with its action id and TTL.

## Running the sensor

Run the backend on the Linux host that owns the monitored interface:

```bash
NV_LIVE_IFACE=<iface> NV_ENFORCE=1 NV_OPERATOR_TOKEN=<token> \
NV_OLLAMA_MODEL=qwen2.5:3b \
NV_PROTECTED_IPS=127.0.0.1,<sensor-ip>,<dashboard-ip>,<gateway-ip> \
python -m uvicorn src.api.main:app --host 0.0.0.0 --port 8000

curl -X POST localhost:8000/live/start        # or the "Start sensor" button
```

Grant packet-capture rights to the interpreter (`setcap cap_net_raw,cap_net_admin+eip $(readlink -f $(which python))`) so root is not needed.

- Set `NV_ENFORCE=0` while rehearsing. Accept then only *shows* the nft rules.
- Put every management address in `NV_PROTECTED_IPS`: the sensor, the dashboard host and the gateway.
- On the dashboard host, set `NV_API_URL=http://<sensor-ip>:8000`, open **Live Monitor**, and enter the operator token in the sidebar (it is per browser session).

## Rules for live testing

- Test only against devices you own. The scripts refuse non-RFC1918 targets and require `NV_I_OWN_THIS_TARGET=yes`.
- Record a fallback PCAP of the exact sequence and replay it with **PCAP Upload** or `NV_LIVE_REPLAY_PCAP`.
