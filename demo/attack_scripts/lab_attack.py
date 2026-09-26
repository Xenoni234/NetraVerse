"""Staged lab traffic generator for authorised testing of YOUR OWN device (R11).

Cross-platform (pure stdlib), so it runs on the Windows dashboard PC against the
Linux sensor laptop without nmap/hydra. It produces the *network footprint* of a
kill chain - a slow recon sweep (the precursor), then a burst of short SSH
connection attempts (the brute-force pattern) - and appends each stage's exact
time window to a schedule file for src.training.lab_dataset.

It does NOT send credentials or exploit anything: it opens and closes TCP
connections, which is what these stages look like on the wire. Only run it
against a device you own.

    set NV_I_OWN_THIS_TARGET=yes           (PowerShell: $env:NV_I_OWN_THIS_TARGET="yes")
    python -m demo.attack_scripts.lab_attack --target 192.168.0.101 --attacker 192.168.0.227
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import socket
import time
from pathlib import Path


def _private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _probe(target: str, port: int, timeout: float = 0.4) -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect_ex((target, port))
    except OSError:
        pass
    finally:
        s.close()


def recon(target: str, seconds: int) -> None:
    """Slow port sweep - the precursor a forecaster should catch before the brute force."""
    print(f"[recon] slow sweep of {target} for {seconds}s", flush=True)
    t_end = time.time() + seconds
    port = 1
    while time.time() < t_end:
        _probe(target, port)
        port = port + 1 if port < 1024 else 1
        time.sleep(0.7)


def brute_force(target: str, port: int, seconds: int) -> None:
    """Rapid short connections to the SSH port - the brute-force footprint (no credentials sent)."""
    print(f"[brute] hammering {target}:{port} for {seconds}s", flush=True)
    t_end = time.time() + seconds
    while time.time() < t_end:
        _probe(target, port, timeout=0.8)
        time.sleep(0.15)


def record(schedule: Path, label: str, target: str, attacker: str, fn, *args) -> None:
    t0 = time.time()
    fn(*args)
    entry = {"label": label, "attacker": attacker, "targets": [target],
             "start": t0, "end": time.time()}
    with open(schedule, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry) + "\n")
    print(f"[schedule] {label}: {entry['end'] - entry['start']:.0f}s -> {schedule}", flush=True)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True, help="your own device's IP")
    ap.add_argument("--attacker", required=True, help="this machine's LAN IP (goes in the labels)")
    ap.add_argument("--ssh-port", type=int, default=22)
    ap.add_argument("--baseline", type=int, default=180, help="benign lead-in seconds")
    ap.add_argument("--recon", type=int, default=180)
    ap.add_argument("--gap", type=int, default=60, help="quiet gap between stages")
    ap.add_argument("--brute", type=int, default=120)
    ap.add_argument("--schedule", default="data/raw/lab/schedule.jsonl")
    a = ap.parse_args()

    if os.environ.get("NV_I_OWN_THIS_TARGET") != "yes":
        raise SystemExit("Refusing: set NV_I_OWN_THIS_TARGET=yes to confirm you own the target.")
    if not _private(a.target) or not _private(a.attacker):
        raise SystemExit("Refusing: target and attacker must be private (RFC1918) LAN addresses.")

    sched = Path(a.schedule)
    sched.parent.mkdir(parents=True, exist_ok=True)
    print(f"[start] {time.strftime('%H:%M:%S')} target={a.target} attacker={a.attacker}", flush=True)
    print(f"[baseline] {a.baseline}s of no attack traffic", flush=True)
    time.sleep(a.baseline)
    record(sched, "PortScan", a.target, a.attacker, recon, a.target, a.recon)
    print(f"[gap] {a.gap}s quiet", flush=True)
    time.sleep(a.gap)
    record(sched, "SSH-Patator", a.target, a.attacker, brute_force, a.target, a.ssh_port, a.brute)
    print(f"[done] schedule -> {sched}", flush=True)


if __name__ == "__main__":
    main()
