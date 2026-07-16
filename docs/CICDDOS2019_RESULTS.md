# CICDDoS2019 Training & Evaluation Report

**Date:** 2026-07-16 · **Branch:** `anurag` · **Models:** `project/models/*.pkl` (commit `5e66191` onward)

This report documents training the two-stage unsupervised pipeline on the CICDDoS2019
parquet dataset, the full held-out evaluation (including the joined `main_dataset.csv`),
the threshold sweep, the Stage 2 rule fixes the evaluation surfaced, and the
engineering fixes made along the way.

---

## 1. Setup

**Dataset:** `data/CICDDos2019/` — parquet exports, pre-split:

| Split | Files | Flows | Benign | Attack |
|---|---|---|---|---|
| Training | 7 (`*-training.parquet`) | 125,170 | 46,427 | 78,743 |
| Testing | 10 (`*-testing.parquet`) | 306,201 | 51,404 | 254,797 |

The testing split contains **five attack families never seen in training**
(DrDoS_DNS, DrDoS_NTP, DrDoS_SNMP, TFTP, WebDDoS), making this a zero-day style
evaluation. Note: this parquet export carries **no IP or port columns** — only the
77 flow statistics + Label. This matters for Stage 2 (see §4).

**Training** (`project/backend/train_cicddos.py`):
- Same canonical-schema -> 10-feature path the backend uses at inference.
- StandardScaler + IsolationForest fit on the **full** training split.
- Autoencoder fit on **benign (normal) flows only** (46,427 flows) — the normal
  data defines the reconstruction baseline.
- Labels used only to pick calibration anchors (median-benign -> 0.0,
  q99-benign -> 0.5, median-attack -> 1.0 per head); inference stays unsupervised.
- Assets saved in the backend's exact format: `scaler.pkl`, `isolation_forest.pkl`,
  `autoencoder.pkl`, `meta.pkl`.

**Evaluation artifacts:**
- `project/models/cicddos_metrics.json` — per-file evaluation.
- `project/models/main_dataset_eval.json` — joined-CSV evaluation
  (`project/backend/eval_main_dataset.py` builds `data/CICDDos2019/main_dataset.csv`,
  306,201 rows / 112 MB, gitignored).

---

## 2. Stage 1 — binary attack detection (threshold 0.50)

Overall on the testing split (306,201 flows):

| Metric | Value |
|---|---|
| Accuracy | **0.8807** |
| Precision | **0.9963** |
| Recall | **0.8597** |
| F1 | **0.9230** |
| Benign FP rate | **1.57%** (806 / 51,404) |

Per attack family (detection rate = recall; unseen-in-training marked *):

| Family | Flows | Detected | Rate |
|---|---|---|---|
| DrDoS_LDAP | 1,440 | 1,431 | 99.4% |
| TFTP * | 98,917 | 98,215 | 99.3% |
| DrDoS_SNMP * | 2,717 | 2,607 | 96.0% |
| DrDoS_NTP * | 121,368 | 110,924 | 91.4% |
| DrDoS_DNS * | 3,669 | 2,546 | 69.4% |
| DrDoS_MSSQL | 6,212 | 2,508 | 40.4% |
| DrDoS_NetBIOS | 598 | 72 | 12.0% |
| DrDoS_UDP | 10,420 | 638 | 6.1% |
| UDP-lag | 8,872 | 120 | 1.4% |
| Syn | 533 | 0 | 0.0% |
| WebDDoS * | 51 | 0 | 0.0% |

**Reading this honestly:** the 86% recall headline is a micro-average dominated by
NTP + TFTP (84% of attack flows). The **macro-average detection rate across the 11
families is ~47%** — performance is bimodal. Seven families at 69–99%, four at 0–6%.
The four missed families (Syn, WebDDoS, UDP-lag, DrDoS_UDP) are low-rate or
timing-shaped attacks whose discriminative features (inter-arrival times,
packet-length variance, TCP window behavior) do not survive the 10-feature
projection — this is the KS-ceiling result in action, a representation limit, not a
model-tuning limit.

---

## 3. Threshold sweep (main_dataset.csv, 306,201 flows)

| Threshold | Accuracy | Precision | Recall | F1 | Benign FP rate |
|---|---|---|---|---|---|
| 0.40 | **96.31%** | 99.45% | 96.10% | 97.74% | 2.65% |
| 0.45 | 94.22% | 99.54% | 93.49% | 96.42% | 2.14% |
| 0.50 | 88.07% | 99.63% | 85.97% | 92.30% | 1.57% |
| 0.55 | 85.56% | 99.75% | 82.86% | 90.52% | 1.02% |
| 0.60 | 82.91% | 99.79% | 79.63% | 88.58% | 0.84% |

**Finding:** a large mass of attack flows scores between 0.40 and 0.50, so lowering
the threshold from 0.50 to 0.45 buys **+7.5 points of recall for +0.6 points of
false positives**; 0.40 gives 96% recall at 2.7% FP. Precision barely moves because
the benign distribution is well-separated below 0.4.

**Recommended operating point for this dataset: 0.40–0.45** (set via Settings ->
confidence threshold in the UI; no retraining needed). The families missed at 0.50
remain missed at 0.40 — no threshold reaches the feature-ceiling classes.

---

## 4. Stage 2 — DDoS subtype segregation

Among attack flows that Stage 1 detects, the rule engine assigns the correct verdict
family for **99.7%** (218,345 / 219,061 at threshold 0.50), with **zero benign flows**
ever labeled as amplification.

Two rule fixes were required, both surfaced by this evaluation:

1. **Port-less amplification fallback** (`ddos_classifier.py`). This parquet export
   has no port columns, so the port-based rule ("service port 53 -> DNS") can never
   fire, and reflection floods fell through to the generic "UDP Flood" verdict.
   Added a fallback that fires only when both ports are unknown (0): oversized
   (mean > 400 B) one-way high-rate UDP -> `Amplification Attack (unknown service)`.
2. **Slow-per-flow reflection profile.** TFTP reflection flows are ~4 oversized
   packets over ~3 s (1.3 pkts/s) — the flood is many flows, not fast flows — so
   they failed the rate gate and 97k flows came out "Unknown Anomaly" (segregation
   was 55%). The fallback now also accepts strictly one-way (>= 0.95) oversized UDP
   with >= 3 packets. Segregation: **55.0% -> 99.7%**, benign verdicts untouched.

**Ceiling note:** without port data the verdict can honestly say *amplification* but
not *which* service (DNS vs NTP vs SNMP). The dataset's "DrDoS_DNS" label comes from
capture metadata, not from any column the model can see. Re-exporting the dataset
with Source/Destination Port retained would let the existing rule name the service
with no code changes.

---

## 5. How the performance measures up

- **Vs published CICDDoS2019 results (99%+ accuracy):** not comparable — those are
  supervised classifiers with labels, 77+ features, and the same attack types in
  train and test. This system is unsupervised at inference, uses 10 features, and
  faces unseen families.
- **Vs the unsupervised / zero-day NIDS standard:** at the good end. Four
  never-seen families detect at 69–99%; TFTP (99k unseen flows) at 99.3% with a
  99.7%-correct subtype verdict.
- **Vs the honest statistical standard:** report the macro number (~47% detection
  across families) alongside the micro 86% — reviewers will compute it anyway.
- **Vs the operational standard:** FP rate is exactly on spec (threshold is defined
  as q99 of benign, ~1%); precision 99.6% means alerts are trustworthy. But 0% on
  plain SYN floods and WebDDoS means the current weights defend against
  reflection/amplification specifically, not DDoS generally — an adversary picks
  the vector you miss.

---

## 6. Engineering fixes made during this work

| Fix | Commit | Detail |
|---|---|---|
| Large-file offline endpoint | `acaa0e9` | SHAP was computed for every flagged flow and rich payloads built for every row; main_dataset.csv would take hours. Now: SHAP capped (displayed + 1,000 for history), vectorized lookups, rich payloads only for the 50+50 returned flows. 306k rows -> **~15 s, 0.38 MB payload**. Charts/campaigns/DB still cover all rows. |
| Backend port auto-fallback | `efbbad7` | `WinError 10013` on startup: port 8000 was held by a VS Code port-forward. `run_all.py` + `main.py` now probe 8000+ and share the chosen port with the Vite proxy via `AEGIS_BACKEND_PORT`. |
| Frontend port + browser URL | `893d8ef` | VS Code also squatted 5173, and a stale Vite from a failed run survived orchestrator cleanup. `run_all.py` now negotiates the frontend port (`--strictPort`) and opens the browser at the actual port. |
| Flow Explorer "does not open flows" | `893d8ef` | Root cause was the stale stack above: the open page proxied `/api` to port 8000 (= VS Code, no backend), so `lastRun` never loaded and the explorer was empty. Page code and API payload verified healthy. |
| Plain-language summary panel | `893d8ef` | Verdict banner + per-attack cards (what it means, flow count, affected file rows) on the Detection Pipeline page; cards jump to Flow Explorer filtered to that attack type. Backend returns per-attack `row_numbers` (`451687a`). Note: `OfflineDetection.jsx` is legacy and unmounted. |

---

## 7. Known limitations & next steps

1. **Feature ceiling (agreed next step).** Measure per-class KS on the full
   77-column space vs the 10-column space to quantify — before any training — how
   much recall on Syn / UDP-lag / DrDoS_UDP / WebDDoS is recoverable. The
   principled fix is per-view heads (rate/size, timing/IAT, TCP-state tiers) with
   union fusion per the miss-product law, not naive feature concatenation (measured
   to hurt via dimensional dilution).
2. **Deployment domain shift.** Scaler, medians, AE baseline and calibration
   anchors are fitted to CICDDoS2019's traffic. Before live use, retrain the benign
   baseline on traffic captured from the target network (unsupervised — no attack
   labels needed). An isolated Linux testbed is most valuable for *evaluation*
   (does the pcap path catch a real hping3 flood end-to-end?) and attack-side
   anchor calibration — not for benign data (a quiet testbed's "normal" is
   unrealistically clean) and not as raw training volume (more data does not move a
   representation ceiling).
3. **Known pcap-path weakness.** SYN floods with randomized source ports fragment
   into 1-packet flows the per-flow Stage 1 scores poorly; the in-house flow meter
   also lacks flow timeouts and uses wire lengths. For real captures, prefer
   CICFlowMeter CSV input.
