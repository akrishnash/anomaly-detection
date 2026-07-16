# Project Progress — Network Anomaly Detection

Last updated: 2026-07-16 (see "Session Log — 2026-07-16" and "Next Session Starting Point" at the bottom; sections between were written 2026-06-24 and are partially superseded by theory.md / the paper / docs/CICDDOS2019_RESULTS.md)

---

## Environment

- **Python**: `C:\Users\ADRIN-ISRO\anaconda3\envs\yolov8\python.exe`
  - The base anaconda Python is broken (SRE module mismatch from a bomba_backend editable install)
  - Always use the `yolov8` conda env — it has sklearn 1.7.2, numpy, pandas, matplotlib
- **Run commands from**: `E:\Projects Internet room\anamoly_detection\`

---

## Codebase Map

| File | What it does |
|---|---|
| `anomaly_detector_v2.py` | Core Isolation Forest detector. Accepts PCAP or CSV log. Computes 9 features per (5-min window × src_ip). Rule-based type labelling. |
| `run_ctu13.py` | Runs IF on CTU-13 real botnet data. 10 hand-picked CICFlowMeter features. Has ground-truth precision/recall. **Baseline numbers live here.** |
| `run_ctu13_v2.py` | All-57-features version. Showed that naive "use all features" hurts IF due to curse of dimensionality. |
| `agent.py` | OpenAI GPT-4o tool-calling agent over the detector. Calls `analyze_traffic` + `lookup_cve`. Requires `OPENAI_API_KEY`. |
| `cve_db.py` | Static CVE / MITRE ATT&CK lookup table for 6 attack types. |
| `explain_isolation_forest.py` | Educational script. Hand-crafted 13-point dataset. Shows decision paths, path lengths, feature splits for a single tree. Run this to understand IF internals. |
| `generate_sample_log.py` | Generates synthetic `sample_logs/network_traffic.log` |
| `generate_sample_pcap.py` | Generates synthetic PCAP |

---

## Dataset

**CTU-13** (real botnet capture, CICFlowMeter pre-processed)
- `sample_logs/CTU13_Attack_Traffic.csv` — 38,898 flows, Label=1
- `sample_logs/CTU13_Normal_Traffic.csv` — 53,314 flows, Label=0
- 59 columns total (57 features + `Unnamed: 0` + `Label`)
- Each row = one **flow** (already aggregated by CICFlowMeter, not raw packets)
- Features include: byte rates, packet counts, flag counts (SYN/RST/FIN), inter-arrival times, idle/active periods

---

## Feature Engineering — Two Different Approaches

### In `anomaly_detector_v2.py` (raw log/PCAP input)
Features are **computed by us** from raw packet rows via `build_features()`:
```
Raw data columns: timestamp, src_ip, dst_ip, dst_port, bytes, status
Groupby: (5-min window, src_ip)
Output features:
  n_packets     = count of packets
  n_bytes       = sum of bytes
  avg_bytes     = mean bytes per packet
  std_bytes     = std dev of packet sizes
  n_dst_ports   = nunique(dst_port)   ← catches port scans
  n_dst_ips     = nunique(dst_ip)     ← catches lateral movement
  failed_ratio  = failed / total      ← catches brute force
  hour_sin/cos  = cyclical time encoding
```

### In `run_ctu13.py` (CTU-13 CSV input)
Features are **already in the CSV** (CICFlowMeter computed them):
```
flow_byts_s    <- "Flow Byts/s"
flow_pkts_s    <- "Flow Pkts/s"
fwd_bytes      <- "TotLen Fwd Pkts"
bwd_bytes      <- "TotLen Bwd Pkts"
total_pkts     <- "Tot Fwd Pkts" + "Tot Bwd Pkts"
syn_flag       <- "SYN Flag Cnt"
rst_flag       <- "RST Flag Cnt"
fin_flag       <- "FIN Flag Cnt"
flow_duration_s<- "Flow Duration" / 1e6
pkt_len_mean   <- "Pkt Len Mean"
```

---

## Experiments & Results

### Experiment 1 — Baseline: 10 features (`run_ctu13.py`)

```
Sample: 6,000 attack + 6,000 normal = 12,000 flows
Contamination: 0.40 (matching true ratio)
Features: 10 (hand-picked from CICFlowMeter columns)

Precision : 69.5%
Recall    : 55.5%
F1        : 61.7%
Accuracy  : 65.6%

Confusion matrix:
  TN=4,541   FP=1,459
  FN=2,671   TP=3,329
```

**Key observation**: Top-ranked anomalies (lowest IF score) had `Ground Truth: Normal`.
IF flags statistically unusual normal flows (high byte rate video streams, backups) above actual attacks.

### Experiment 2 — All 57 features (`run_ctu13_v2.py`)

```
Same sample, same contamination
Features: 57 (all CICFlowMeter columns, log1p on 54 skewed cols)

Precision : 58.4%   (-11.1 vs baseline)
Recall    : 46.7%   (-8.8 vs baseline)
F1        : 51.9%   (-9.8 vs baseline)
Accuracy  : 56.7%

TN=4,004   FP=1,996
FN=3,196   TP=2,804
```

**Key finding — Curse of Dimensionality:**
More features hurt because IF picks features randomly at each split. With 57 features,
most splits land on correlated or uninformative columns, diluting the signal from the
10 actually discriminative features.

**PR curve optimal threshold (ignoring fixed contamination):**
```
Score cut: -0.3959
Precision: 64.3%   Recall: 100.0%   F1: 78.3%
```
At the right threshold, every attack can be caught — at the cost of more false alarms.
This shows the score signal is there; the threshold is the bottleneck.

### Experiment 3 — Isolation Forest Internals (educational)

Hand-crafted 13-point dataset (10 normal + 3 anomalies), 5 trees, 3 features.

```
Port Scan   (n_dst_ports=847)  : isolated in 1 split   avg depth=1.8
Exfiltration (n_bytes=5000 KB) : isolated in 2 splits  avg depth=1.8
Brute Force (failed_ratio=0.97): isolated in 4 splits  avg depth=3.6
Normal points                  : isolated in 4 splits  avg depth=4.0
```

Brute Force is hard because it only breaks one feature (failed_ratio) with a narrower
range — random cuts are less likely to hit it quickly.

---

## What We Know Doesn't Work

- **Naive "use all features"**: Hurts IF due to curse of dimensionality. Need feature selection first.
- **Fixed contamination parameter**: PR curve shows optimal threshold differs from contamination-implied one.

---

## Roadmap to 90% Precision + Recall

| Step | What | Expected gain | Status |
|---|---|---|---|
| 1 | Use all 57 features + log1p | Tried — made it worse | Done |
| 2 | Feature selection (top 15-20 by mutual info / RF importance) | +8–12 pts recall | Next |
| 3 | Threshold tuning via PR curve instead of fixed contamination | +5–8 pts | Partially shown |
| 4 | Extended Isolation Forest (fixes linear split bias) | +3–5 pts | Not started |
| 5 | Ensemble: IF + LOF vote | +4–6 pts recall | Not started |
| 6 | SHAP explainability (Direction 1 from RESEARCH.md) | Research output | Not started |
| 7 | Semi-supervised: use 10% labels to calibrate threshold | +8–12 pts both | Not started |

**Honest ceiling estimates:**
- Unsupervised only (steps 2–5): ~75–82% on both metrics
- Semi-supervised (step 7): ~87–92%
- Fully supervised (Random Forest baseline): ~96–99%

---

## Research Directions (from RESEARCH.md)

1. **SHAP Explainability** — Most publishable. Medium effort. `pip install shap`.
2. **Benchmarking** — IF vs OC-SVM vs Autoencoder vs LOF on same CTU-13 split.
3. **Federated Detection** — High effort. Best CV story (ISRO/ADRIN angle).
4. **Streaming** — River library. Medium-high effort.

Recommended: Direction 1 + 2 together (same experimental setup, complete paper).

---

## Session Log — 2026-07-16 (branch `anurag`)

Full numbers live in **`docs/CICDDOS2019_RESULTS.md`**; this is the conversation-level
summary so the next session can pick up without re-deriving context.

### What was done (all committed & pushed to `akrishnash/anomaly-detection`, branch `anurag`)

1. **Trained `project/` models on CICDDoS2019** (`5e66191`)
   - New `project/backend/train_cicddos.py`: trains scaler + IF (full training split)
     + AE (benign flows only) via the backend's canonical preprocessing, calibrates
     anchors, evaluates on the held-out `*-testing.parquet` files.
   - Test split includes 5 attack families never seen in training (zero-day eval).
   - Stage 1 @0.5: acc 0.881 / prec 0.996 / recall 0.860 / F1 0.923 / FP 1.6%.
   - Honest framing: macro detection across the 11 families is ~47% (bimodal) —
     Syn, WebDDoS, UDP-lag, DrDoS_UDP are invisible in the 10-feature space
     (KS-ceiling, representation limit, not tunable).

2. **Stage 2 rule fixes** (`0f2aa7c`, `451687a`)
   - Dataset export has NO port/IP columns -> port-based amplification rule could
     never fire; DrDoS_DNS came out "UDP Flood". Added port-less fallback
     (`Amplification Attack (unknown service)`), then extended it for slow-per-flow
     strictly-one-way reflection (TFTP profile: ~4 oversized pkts over ~3 s).
   - Subtype segregation among detected attacks: 55.0% -> **99.7%**, zero benign
     flows mislabeled amplification.

3. **`main_dataset.csv` + full-pipeline evaluation** (`451687a`)
   - `project/backend/eval_main_dataset.py` joins all 10 testing parquets ->
     `data/CICDDos2019/main_dataset.csv` (306,201 rows, 112 MB, gitignored) and
     evaluates the production CSV path end-to-end. Reports in
     `project/models/main_dataset_eval.json` + `cicddos_metrics.json`.

4. **Threshold sweep** (documented in results md): 0.40 -> acc 96.3% / recall 96.1%
   / FP 2.7%; 0.45 -> 94.2% / 93.5% / 2.1%; 0.50 -> 88.1% / 86.0% / 1.6%.
   **Recommended operating point 0.40–0.45** (Settings -> confidence threshold; no
   retrain). Missed families stay missed at any threshold.

5. **UI: plain-language summary for laymen** (`451687a`, `893d8ef`)
   - Verdict banner + per-attack cards (what the attack means, flow count, affected
     file row numbers) on the **Detection Pipeline** page; clicking a card jumps to
     Flow Explorer pre-filtered to that type. Backend returns per-attack
     `row_numbers` (anomalies payload is capped at 50).
   - NOTE: `pages/OfflineDetection.jsx` is legacy and NOT mounted in App.jsx — the
     Sentinel pages (SocDashboard / DetectionPipeline / FlowExplorer /
     DdosClassifier) are the live UI.

6. **Backend scalability** (`acaa0e9`): offline endpoint no longer runs SHAP on
   every flagged flow / builds rich payloads for every row. 306k-row CSV:
   hours -> **~15 s, 0.38 MB payload**. SHAP capped at displayed + 1,000 for
   history DB. Charts/campaigns/DB still cover all rows.

7. **Startup robustness** (`efbbad7`, `893d8ef`): on this machine VS Code
   port-forwards squat 8000 AND 5173 (WinError 10013), and a stale Vite survived a
   failed orchestrator run. `run_all.py` now probes free ports for both servers,
   shares the backend port with the Vite proxy via `AEGIS_BACKEND_PORT`, pins Vite
   with `--strictPort`, and opens the browser at the actual port. "Flow Explorer
   does not open flows" was exactly this: the open page was a dead frontend
   proxying to VS Code instead of the backend.

8. **Docs**: `docs/CICDDOS2019_RESULTS.md` (`4632aed`) — full report.

### Decisions & judgments made in conversation

- 10 features is the binding constraint; feature work strictly dominates data
  volume for the missed classes. The principled expansion is **per-view heads**
  (rate/size, timing/IAT, TCP-state tiers) with union fusion per the miss-product
  law — NOT naive concatenation (measured to hurt: dimensional dilution).
- More training data / isolated-Linux testbeds: useful for *evaluation* and
  attack-side anchors; NOT for benign baselines (quiet testbed "normal" is
  unrealistically clean) and cannot move a representation ceiling.
- For deployment, the highest-leverage step is retraining the benign baseline
  (AE + scaler + anchors) on traffic captured from the target network.
- Push with `git push akrishnash <branch>` — `origin` (anshv4586) 403s for this
  git user.

---

## Next Session Starting Point

**Agreed next task: the feature-ceiling experiment** — compute per-class KS
(ceiling = max achievable Youden J, per Thm 1) for each candidate feature /
feature-tier on the CICDDoS2019 77-column space vs the current 10-column space.
This quantifies, before any training, how much recall on Syn / UDP-lag /
DrDoS_UDP / WebDDoS is recoverable and whether per-view dual heads are justified.
Strongest candidate features being thrown away today: IAT family (Flow/Fwd/Bwd
IAT mean/std/max), Init Fwd/Bwd Win Bytes, Packet Length min/max/std/variance,
Down/Up Ratio, header lengths.

After that (in agreed priority order): per-view heads if the ceilings justify it,
then deployment hardening (benign baseline retraining on target-network traffic,
testbed end-to-end pcap evaluation).

Quick env/context checks:
```
# project app (base anaconda has fastapi+shap; PATH python IS base anaconda)
python run_all.py                       # auto-negotiates ports; VS Code squats 8000/5173
# retrain / re-evaluate
python project/backend/train_cicddos.py
python project/backend/eval_main_dataset.py
```
Research scripts still use the yolov8 env
(`C:\Users\ADRIN-ISRO\anaconda3\envs\yolov8\python.exe`); the deployable
`project/` backend uses base anaconda.
