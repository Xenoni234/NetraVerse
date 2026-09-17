# Demo upload samples

Drop these into the demo's **Upload capture** box (CSV path) to exercise the file-upload
forecasting path with real CIC-IDS2017 traffic (not synthetic — the model only reacts to
real flow distributions).

## sample_webattack_192.168.10.8.csv
- Real host `192.168.10.8` from CIC-IDS2017 Thursday (Web-attack / infiltration day).
- ~4,000 flows, 16 per-host 30 s windows (benign lead-in then attack).
- Expected: forecast risk climbs and crosses the alert threshold (peak ~0.92 at +120 s),
  ATT&CK stage advances toward INITIAL_ACCESS, and the SHAP + attention panels populate.
- Format is the raw CIC-IDS2017 CICFlowMeter CSV; `src/inference/live.py` auto-detects the
  column map and builds the same 43-feature windows the model was trained on.

To regenerate or make others, export any real attacked host's flows from a CIC-IDS2017 day
(keep the original CICFlowMeter column headers).
