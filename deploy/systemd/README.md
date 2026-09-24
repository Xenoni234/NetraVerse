# NetraVerse systemd units

Install the **weekly auto-recalibration** (the agent self-tunes its alert
threshold from benign traffic every 7 days):

```bash
mkdir -p ~/.config/systemd/user
cp deploy/systemd/nv-recalibrate.service ~/.config/systemd/user/
cp deploy/systemd/nv-recalibrate.timer   ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now nv-recalibrate.timer
systemctl --user list-timers | grep nv-recalibrate     # confirm next run
```

Run it once immediately (e.g. right after capturing 30–60 min of benign traffic):

```bash
systemctl --user start nv-recalibrate.service
journalctl --user -u nv-recalibrate.service -n 40 --no-pager
```

`nv-recalibrate.service` runs `scripts/auto_recalibrate.py`, which:
1. **Aborts if any host is alerting** (never learns on attack traffic).
2. Requires enough benign flow rows (`--min-rows`).
3. Recalibrates via `scripts/calibrate.py` (p99 × margin) → writes `models/wm_server/best.ckpt`.
4. Restarts `nv-live` + `nv-api` so the new threshold loads.

Point `--flows` (in the `.service`) at the benign capture dir your agent writes
(default `~/nv_flows_benign`). The live forecaster (`nv-live`) and API (`nv-api`)
are the same `systemd --user` units used to run the demo.
