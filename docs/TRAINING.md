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
10. **Explanation reference.** "Typical" values in explanation sentences are the median of active training windows. The all-window mean was dominated by idle minutes and misled.

## Known limitations (report these, do not hide them)

- **Detection, not early warning.** Alerts fire at or about one window after onset. Recall on attacks preceded by a fully benign 10-minute history is 0%. The public datasets rarely have a benign precursor at 60 s resolution.
- **Oracle persistence scores higher.** It uses the true current label, which a deployed system never has, and it cannot warn early.
- **UNSW-NB15 is trivially separable per host.** Its attacker hosts never behave benignly. Always read the per-dataset rows.
- **No transfer to unseen networks.** This holds for the other datasets and for the live home network, where a real TCP port scan scored 0%. The fix is lab retraining (below).
- **Counterfactuals replay recorded traffic minus the blocked flows.** They cannot model an adaptive attacker.

## Retraining on your own lab (next step for the team)

This is Phase 11 and R4.

1. Record on the sensor: `tcpdump -i wlp0s20f3 -w data/raw/lab/session1.pcap`.
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

5. Report the `lab` rows separately in `benchmarks.md`. Keep one capture of the exact demo sequence as the fallback PCAP (R12).
