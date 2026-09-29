# Model, training and evaluation

## Model

- **Input.** Per host, per 60 s window: the 31 features in `src/features/schema.py`. They cover outbound behaviour, inbound exposure, and packet-level stats with "observed" masks.
  - Counts are `log1p`-transformed, then z-scored with training statistics, stored in the checkpoint.
  - A flow counts in the window that contains its **end**, so no window contains information from the future.
- **GraphSAGE** (`models/gnn.py`, `graph/graph_utils.py`). For each host-window it aggregates the scaled features of the hosts it exchanged flows with in the same window (mean + max + log-degree). That embedding is concatenated to the encoder input.
- **RSSM-lite world model** (`models/transition.py`, `world_model.py`):
  - `h_t = GRU(z_{t-1}, h_{t-1})` is the deterministic state.
  - The prior `p(z_t|h_t)` and posterior `q(z_t|h_t, e_t)` are Gaussians.
  - Decoder heads on `[h, z]`: next-window features, **risk** (attack activity involving the host), **stage** (7 ATT&CK classes).
- **Training loss** per sequence of L = 10 history + K = 5 future windows:
  1. filtering over all 15 observed steps: reconstruction + KL(q‖p) with free nats + current risk + current stage;
  2. **imagination**: from step 10 the *prior alone* rolls 5 steps, supervised with real future features, risk and stage.
- **Forecast** (`models/rollout.py`). Filter the last 10 windows, then imagine 5 × 60 s = 300 s. The displayed value is `P(attack within 300 s)` = the peak imagined risk, with 16 MC samples for the 10–90% band.
- **Calibration.** The raw risk head is over-confident, so Platt scaling is fitted on validation and applied by the service. It is monotone, so no ranking metric changes. The threshold is shown on the calibrated scale (0.851).

## Reproduce

```bash
python -m src.training.build_dataset                  # data/raw -> data/processed/*.windows|edges.parquet + reports/dataset_stats.md
python -m src.training.train_world_model              # ~6 min on an RTX 3050 -> models/world_model.pt + reports/wm_main.json
python -m src.training.train_baseline                 # LogReg + persistence + SHAP -> reports/baseline_main.json
python -m src.training.train_world_model --no-gnn --tag nognn        # Phase 5 ablation
python -m src.training.cross_dataset_eval --retrain                  # Phase 6: CIC -> CTU-13 / UNSW zero-shot
python -m src.training.cross_dataset_eval --retrain --capture-norm   # R4 normalisation experiment
python -m src.training.report                         # rebuild reports/benchmarks.md from the JSONs
python -m src.training.train_world_model --eval-only  # re-score an existing checkpoint (e.g. after changing metrics)
```

- Hyper-parameters live in `src/training/configs/world_model.yaml`. A copy is written next to the weights as `models/training_config*.yaml` (R18).
- Seeds are fixed. Expect small run-to-run differences on GPU.

## Results

Test split, target "attack activity involving the host within the next 300 s". Full tables, including the per-dataset baseline and persistence rows, are in [`reports/benchmarks.md`](../reports/benchmarks.md).

| | F1 | PR-AUC | CIC-2017 PR-AUC | CTU-13 PR-AUC |
|---|---|---|---|---|
| **World model** (RSSM-lite + GraphSAGE) | **0.860** | **0.921** | **0.603** | **0.598** |
| Logistic regression, same features | 0.543 | 0.766 | 0.157 | 0.027 |
| World model, no GNN (ablation) | 0.858 | 0.904 | 0.512 | 0.566 |

Other results:
- Current-window detection F1: 0.906.
- Zero-shot cross-dataset PR-AUC, training on CIC:

  | Target | World model | LogReg |
  |---|---|---|
  | CTU-13 | 0.006 | 0.007 |
  | UNSW-NB15 | 0.189 | 0.158 |

## Tuning decisions

Required by R20. Each decision applies identically to the world model and the baselines.

1. **60 s windows, K = 5 (300 s), L = 10.** CIC-IDS2017 timestamps are minute-resolution with AM/PM dropped (hours 1–7 are shifted +12 h). Anything finer would be fabricated precision.
2. **Blocked temporal split.** 1-hour blocks per capture, assigned train/val/test in a 3:1:1 cycle. Sequences never cross a block. No random row shuffling.
   - Consequence: some attack types appear only in train/val blocks. For example, the CIC PortScan burst sits in validation, and CIC-2018's attacks are all outside test.
3. **Label semantics.**
   - A host-window is "attack" if the host initiates attack flows.
   - It is also "attack" if it receives them for recon, initial access, lateral movement or impact.
   - For C2 and exfiltration the destination is infrastructure (DNS, C2 server), so only the source is labelled.
   - The first version labelled every destination. That marked CTU-13's DNS server and Google IPs as attacked, so it was dropped. Its results are in `reports/*_rawlabels.json`.
4. **Attack episodes.** Attack windows of one host separated by ≤ 5 quiet minutes count as one episode.
5. **Class balancing.**
   - Keep all attack sequences and 15% of all-benign ones.
   - Sample so every (dataset, attack/benign) group has equal mass.
   - `pos_weight` is computed under that sampler.
   - A (dataset, MITRE stage) sampler was **tried and rejected**: validation macro PR-AUC 0.742 vs 0.759 (`reports/wm_stagebalanced_rejected.json`).
6. **Onset emphasis.** Sequences that are benign now with an attack inside the horizon get 5× weight on the imagined-risk loss.
7. **Packet-feature dropout, p = 0.5.** CSVs never carry TTL, window or retransmission data. Dropout makes one model valid for CSV and PCAP input.
8. **Per-capture normalisation (R4).** Evaluated, did not improve transfer, so it is **off** (`reports/cross_dataset_cn.json`).
9. **Threshold and calibration.**
   - The threshold maximises the mean F1 across datasets on validation.
   - Platt calibration is fitted on validation.
   - Model selection uses validation macro PR-AUC, never demo behaviour.
11. **Forecast target = any attack stage incl. reconnaissance, with recon up-weighting (early warning).**
    The positive risk target is *any* attack stage, reconnaissance included (`data.compromise_stages:
    [1..6]`). Recon is deliberately a **detectable positive**, not just a precursor: the model must
    raise risk the moment a host starts being scanned, minutes before the break-in. Lead time then
    comes from the recon -> compromise gap.
    - A compromise-only target ([2..6], recon as precursor only) was **tried and rejected**: because
      recon windows carried no positive label, the model stayed at ~0 % risk throughout the scan and
      only fired at the brute-force onset (lead time +0 s on the held-out lab capture). Reverting to
      recon-positive was necessary for any lead time at all.
    - **`recon_boost = 10` (`train.recon_boost`).** Reconnaissance is low-*volume* traffic; by default the
      model keys on volume features. Sequences whose horizon contains recon get 10× loss weight so the
      *structural* scan signal (inbound distinct-port count, SYN ratio, failed-connection ratio, tiny-
      flow ratio -- all volume-independent) is emphasised. This is what lets the model learn recon.
    - **In-distribution lab recon.** Public recon (slow, sparse) does not match a fast scan sweep.
      Staged lab cycles (recon -> brute force) were captured and added to training (`lab`, 50 attack
      windows). The held-out lab session (`lab_test`, never trained on) is scored by `src.training.eval_leadtime`.
    - **Result.** On the held-out lab capture the model alerts on the **first** reconnaissance window and
      the brute force starts four windows later -> **lead time +240 s** (forecast *during* the scan,
      before the compromise). On the public test set the median lead over caught onsets is also 240 s
      (mean 244.6 s) at a quiet false-alarm rate of 0.0003.
    - **Small lab captures go to TRAIN.** A lab capture (~40 windows) is shorter than one split block
      (60 windows), so it cannot serve as a held-out block; all `lab` sequences are forced into train
      (`data.py`) and a separate `lab_test` capture is held out. This is scoped to `lab` only, so the
      public-benchmark splits are unchanged.

10. **Explanation reference.** "Typical" values in explanation sentences are the median of active training windows. The all-window mean was dominated by idle minutes and misled.

## Notes on scope

- **Early warning needs a precursor with signal.** Lead time comes from the reconnaissance that precedes a compromise (see tuning decision 11). A multi-stage attack is where the forecasting edge shows; a cold, single-packet exploit with no precursor is detected at onset.
- **Per-environment calibration.** The Auto-Calibration Engine / `src/training/lab_dataset.py` adapts the model to a new network's benign baseline; always read the per-dataset rows when comparing.
- **Counterfactuals replay recorded traffic minus the blocked flows**, so they cannot model an adaptive attacker.

## Calibrating on your own network

1. Record on the sensor: `tcpdump -i <iface> -w data/raw/lab/session1.pcap`.
2. At the same time, run the attack sequence from the attacker machine against your **own** device:

   ```bash
   NV_I_OWN_THIS_TARGET=yes NV_ATTACKER_IP=<attacker LAN IP> demo/attack_scripts/run_sequence.sh <target>
   ```

   It records 5 minutes of benign baseline, then recon, brute force and an optional lateral probe. Each stage's exact time window is appended to `data/raw/lab/schedule.jsonl`.
3. Record several sessions and plenty of *normal* traffic too, so the model learns what benign looks like on this network.
4. Build and retrain:

   ```bash
   python -m src.training.lab_dataset --stats     # check what the schedule will label
   python -m src.training.lab_dataset             # -> data/processed/lab.windows.parquet
   python -m src.training.train_world_model --datasets cic2017 cic2018 ctu13 unsw lab
   python -m src.training.train_baseline --datasets cic2017 cic2018 ctu13 unsw lab
   python -m src.training.report
   ```

5. Report the `lab` rows separately in `benchmarks.md`. Keep one capture of the exact sequence as the fallback PCAP.

## Demo scenario file

`python -m demo.make_demo_scenario` builds `demo/samples/netraverse_campaign.csv` and
`demo/fallback_pcap/netraverse_campaign.pcap` for the console showcase. Features come verbatim from real
captures. Each campaign pairs a reconnaissance precursor with a compromise, so the model forecasts the
break-in during the scan. Measured leads on the shipped file (alert vs first compromise window):

| campaign (victim)         | composition               | early-warning lead |
|---------------------------|---------------------------|--------------------|
| 10.20.0.11                | recon → SSH brute force   | +180 s             |
| 10.20.0.12                | recon → SSH brute force   | +120 s             |
| 10.20.0.13                | recon → FTP-Patator       | +180 s             |
| 10.20.0.14                | recon → DoS               | +120 s             |

The lead is measured to the **compromise** (stage ≥ 2) with reconnaissance as the precursor
(`service.timeline.compromise_lead_s`).
