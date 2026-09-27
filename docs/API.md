# Backend API

The backend is FastAPI (`src/api`). Interactive docs are served at `http://<host>:8000/docs`, and schemas are in `src/api/schemas.py`. All modes go through `src/api/service.py`. A *step* is the index of a 60 s window counted from the start of the file (or of the live buffer).

## Health

| | |
|---|---|
| `GET /health` | Returns checkpoint, `trained_on`, calibrated threshold, device, window/horizon and live status. |
| `GET /static/topology3d.js` | The offline three.js bundle the dashboard imports. |

## File mode (CSV / PCAP)

| Method + path | Purpose |
|---|---|
| `POST /upload` (multipart `file`) | Upload a `.csv`, `.binetflow`, `.pcap` or `.pcapng`, which runs fusion, windowing and forecasts for every host. Returns the overview: `id`, hosts with peak risk and first alert step, `focus_host`, `decision_step`, `threshold`. |
| `POST /upload/path?path=demo/samples/x.csv` | Same, for a file already inside the project (bundled samples). |
| `GET /upload/{id}` | Overview again. |
| `GET /upload/{id}/timeline?host=` | Per-step `risk` (P(attack ≤ 300 s)), `risk_now`, `future[step][k]` rollout (+ `lo`/`hi` band), mapped `stage`, `traffic`, `truth_stage` (if labelled), `first_alert_step`, `lead_time_s`. |
| `GET /upload/{id}/explain?host=&step=` | Top-5 integrated-gradients drivers with sentences. |
| `GET /upload/{id}/topology?step=` | Nodes (`role`: attacker, victim, normal or mitigated; `risk`, `alerting`) and edges (`active`, `hot`) for the 3D view. After a decision it reflects the mitigated branch. |
| `GET /upload/{id}/decision?host=&step=` | Decision context: stage, derived roles, recommended action with `alternatives`, drivers, and `narration` (`pending` / `ready` / `fallback`). |
| `GET /upload/{id}/narration?host=&step=` | Poll the local-LLM narration. |
| `POST /upload/{id}/decision` | Body `{"host", "step", "choice": "accept\|modify\|reject", "action": <alternative id for modify>}`. Replays traffic with the action applied and returns `before` / `after` rollouts, `delta` and the `continuation` curve. |
| `GET /upload/{id}/branch?host=` | Re-simulated timeline for any host after a decision. |
| `POST /upload/{id}/reset` | Drop the decision branch (replay again). |

Uploads are kept **in memory** (files are saved under `data/uploads/`). After an API restart, upload again.

## Live mode

| Method + path | Purpose |
|---|---|
| `POST /live/start` / `POST /live/stop` | Start or stop the sensor. Needs `NV_LIVE_IFACE` or `NV_LIVE_REPLAY_PCAP` set on the API host. |
| `GET /live/state` | Sensor status (packets, flows, ticks, inference ms, error), overview of the latest sliding window, per-host risk `series` and the action log. |
| `GET /live/topology` | Current topology. |
| `GET /live/explain?host=` | Current drivers. |
| `GET /live/decision?host=` / `GET /live/narration?host=` | As in file mode, for the latest window. |
| `POST /live/decision` | Header `x-operator-token: <NV_OPERATOR_TOKEN>`. `accept`/`modify` apply a **real** nftables rule (TTL 300 s) when `NV_ENFORCE=1`, otherwise a dry-run. Protected IPs are always refused. Returns 403 on a wrong or missing token. |

Example:

```bash
curl -X POST "localhost:8000/upload/path?path=demo/samples/cic2017_webattack_thursday.csv"
curl "localhost:8000/upload/<id>/timeline?host=172.16.0.1"
curl -X POST localhost:8000/upload/<id>/decision -H "content-type: application/json" \
     -d '{"host":"172.16.0.1","step":16,"choice":"accept"}'
```
