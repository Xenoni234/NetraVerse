"""Record a PCAP on the sensor for PCAP-upload analysis / the R12 fallback / lab retraining.

    python -m demo.record_pcap --iface wlp0s20f3 --minutes 30 --out demo/fallback_pcap/lab_session.pcap

Uses the same capture rights as the live sensor (cap_net_raw on the python binary, no root).
Packets are streamed to disk, so long captures do not grow memory. Stops after --minutes
or on Ctrl+C / SIGTERM, then prints a short summary.
"""
from __future__ import annotations

import argparse
import signal
import time
from pathlib import Path


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", required=True)
    ap.add_argument("--minutes", type=float, default=30)
    ap.add_argument("--out", default="demo/fallback_pcap/lab_session.pcap")
    ap.add_argument("--bpf", default="ip")
    a = ap.parse_args()

    import scapy.layers.inet  # noqa: F401
    from scapy.sendrecv import AsyncSniffer
    from scapy.utils import PcapWriter

    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    writer = PcapWriter(str(out), append=False, sync=True)
    n = {"pkts": 0}

    def on_pkt(p) -> None:
        writer.write(p)
        n["pkts"] += 1

    sn = AsyncSniffer(iface=a.iface, filter=a.bpf, prn=on_pkt, store=False)
    stop = {"flag": False}
    signal.signal(signal.SIGTERM, lambda *_: stop.update(flag=True))
    sn.start()
    t0 = time.time()
    print(f"[record] {a.iface} -> {out} for {a.minutes} min (started {time.strftime('%H:%M:%S')})", flush=True)
    try:
        while not stop["flag"] and time.time() - t0 < a.minutes * 60:
            time.sleep(5)
            print(f"[record] {int(time.time() - t0)} s, {n['pkts']} packets", flush=True)
    except KeyboardInterrupt:
        pass
    sn.stop()
    writer.close()
    print(f"[record] done: {n['pkts']} packets, {out.stat().st_size / 1e6:.1f} MB -> {out}", flush=True)


if __name__ == "__main__":
    main()
