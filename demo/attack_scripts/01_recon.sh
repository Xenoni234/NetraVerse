#!/usr/bin/env bash
# Stage 1 - Reconnaissance: a paced TCP connect scan that ramps up (low parallelism,
# mirrors a stealthy scan and gives the world model a precursor to forecast from).
# usage: NV_I_OWN_THIS_TARGET=yes ./01_recon.sh 192.168.0.50
source "$(dirname "$0")/_guard.sh"; T="${1:?target ip}"; require_private "$T"
echo "[recon] slow sweep of top ports on $T"; nmap -sT -T2 --top-ports 100 "$T"
echo "[recon] full port scan of $T";        nmap -sT -T3 -p- --max-parallelism 20 "$T"
