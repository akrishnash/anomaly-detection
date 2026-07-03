# Project Progress — Network Anomaly Detection

Last updated: 2026-07-01

---

## Environment

- **Python**: `C:\Users\ADRIN-ISRO\anaconda3\envs\yolov8\python.exe`
  - Base anaconda Python is broken (SRE module mismatch — bomba_backend editable install removed)
  - Always use the `yolov8` conda env (sklearn, numpy, pandas, matplotlib, scipy all present)
- **Run from**: `E:\Projects Internet room\anamoly_detection\`

---

## Datasets

| Dataset | File | Rows | Format | Labels |
|---|---|---|---|---|
| CTU-13 Attack | `sample_logs/CTU13_Attack_Traffic.csv` | 38,898 | CICFlowMeter | binary (1) |
| CTU-13 Normal | `sample_logs/CTU13_Normal_Traffic.csv` | 53,314 | CICFlowMeter | binary (0) |
| UNSW-NB15 Train | `sample_logs/unsw_nb15/UNSW_NB15_training-set.csv` | 175,341 | Argus/Bro | multi-class |
| UNSW-NB15 Test | `sample_logs/unsw_nb15/UNSW_NB15_testing-set.csv` | 82,332 | Argus/Bro | multi-class |

CTU-13: university botnet traffic (Neris, Rbot, Menti botnets), 59 CICFlowMeter features.
UNSW-NB15: 9 attack types (Fuzzers, Exploits, DoS, Backdoor, Reconnaissance, Analysis,
Shellcode, Worms, Generic), 39 Argus features. Download: `sample_logs/unsw_nb15/` is gitignored.

---

## Codebase Map

| File | What it does |
|---|---|
| `run_ctu13.py` | IF on CTU-13, 10 features, 6K+6K sample. **Baseline numbers.** |
| `run_ctu13_v2.py` | All-57-features IF. Worse — curse of dimensionality confirmed. |
| `compare_datasets.py` | Attack vs Normal: Cohen's d, ROC, PR, threshold sweep (20K rows each) |
| `diagnose_overlap.py` | KS ceiling diagnostic. Score distribution overlap + CDF gap. |
| `ensemble_detector.py` | IF + LOF + AE comparison. AE dominates. Averaging hurts. |
| `stage2_supervised.py` | Two-stage pipeline: AE flags → XGBoost classifies → zero-day queue |
| `explain_isolation_forest.py` | Educational IF walkthrough on 13-point toy dataset |
| `agent.py` | GPT-4o tool-calling agent (requires OPENAI_API_KEY) |
| `cve_db.py` | CVE + MITRE ATT&CK lookup (used by agent.py) |
| `streamlit_app.py` | Interactive app: score overlap explorer |

---

## All Experiments & Results

### Exp 1 — IF Baseline: 10 features, CTU-13 (`run_ctu13.py`)

```
Sample: 6,000 attack + 6,000 normal | Contamination: 0.40
Precision: 0.695  Recall: 0.555  F1: 0.617  Accuracy: 0.656
TN=4,541  FP=1,459  FN=2,671  TP=3,329
KS ceiling: 0.445  AUC: 0.677
```

Key: IF flags statistically unusual normal flows (high-rate backups, video) above real attacks.
The 60% plateau is structural — no contamination tuning fixes it.

### Exp 2 — All 57 features (`run_ctu13_v2.py`)

```
Precision: 0.584  Recall: 0.467  F1: 0.519  (-9.8 pts vs baseline)
```

Curse of dimensionality confirmed: random feature splits dilute signal.
At optimal PR threshold: Recall=100% at Precision=64.3% — score signal exists, threshold is wrong.

### Exp 3 — Attack vs Normal Comparison, 20K rows (`compare_datasets.py`)

Cohen's d discrimination power (attack - normal / pooled std):
- SYN flags: d=+0.86 (attack > normal — port scanning / C&C setup)
- Pkt Rate:  d=+0.63 (bimodal: near-zero beacons + DDoS spikes)
- Pkt Len:   d=-0.19 (normal has bigger packets — HTTP content)
- Bwd Bytes: d=-0.02 (C&C gets near-empty ACK replies)

At 20K rows: Precision=0.637, Recall=0.509, ROC-AUC=0.706.

### Exp 4 — KS Ceiling Diagnosis (`diagnose_overlap.py`)

```
KS = 0.445  →  max achievable (TPR - FPR) = 0.445
AUC = 0.677
→ Heavy overlap. Ceiling is STRUCTURAL. Fix = change representation, not threshold.
```

This is the core claim of the paper.

### Exp 5 — Ensemble: IF + LOF + AE (`ensemble_detector.py`)

```
IF    KS=0.445  AUC=0.677  Precision=0.584  Recall=0.467
LOF   KS=0.155  AUC=0.537  (weakest — botnet flows cluster, not locally sparse)
AE    KS=0.860  AUC=0.978  Precision=0.977  Recall=0.898  ← dominates
Ensemble (avg)  KS=0.606   (LOF drags it down — averaging hurts)
```

AE trained on normal only. Botnet C&C fails reconstruction: MSE ratio = 23.4x higher
on attack vs normal. Key insight: reconstruction anomaly >> isolation anomaly here.

Proper train/test split verification:
```
AE (95th pct threshold, held-out test):
  Precision=0.950  Recall=0.906  F1=0.928  Accuracy=0.929
  TN=2,285  FP=115  FN=225  TP=2,175
```
No data leakage — numbers hold on unseen data.

### Exp 6 — Cross-Dataset: UNSW-NB15 (`ensemble_detector.py` + inline)

```
Train: 56,000 normal + 119,341 attack (UNSW-NB15 train split)
Test:  37,000 normal + 45,332 attack (UNSW-NB15 test split)
9 attack types: Fuzzers, Exploits, DoS, Backdoor, Recon, Analysis, Shellcode, Worms, Generic
```

| Detector | Precision | Recall | F1 | AUC |
|---|---|---|---|---|
| IF | 0.349 | 0.277 | 0.309 | 0.254 |
| AE (95th pct) | 0.816 | 0.335 | 0.475 | 0.709 |

Per-attack-type recall (AE vs IF):
- Fuzzers (6K):    AE=8%,  IF=29%  ← AE fails on random payload
- Exploits (11K):  AE=47%, IF=48%  ← tie
- Generic (19K):   AE=43%, IF=21%  ← AE wins
- Shellcode (378): AE=2%,  IF=2%   ← both fail
- DoS (4K):        AE=23%, IF=24%  ← tie

**Finding**: best anomaly notion is attack-type dependent.
No single unsupervised detector generalises across all attack families.

### Exp 7 — Two-Stage Pipeline (`stage2_supervised.py`)

CTU-13 (70/30 split): Stage 1 alone F1=0.927, Full pipeline F1=0.945, **87% FP reduction** (84 to 11).
UNSW-NB15: Limited gain — bottleneck is Stage 1 recall (33%), not false positives.

### Exp 7b — Zero-Day Simulation (`zero_day_sim.py`)

Train Stage 2 on 5 known types. Hold out 4 completely: Backdoor, Shellcode, Analysis, Worms.
Zero-day queue: 1,555 flows, 71% precision. Zero Stage 2 misclassifications of hidden types.
End-to-end rate 1-5% — bottleneck is Stage 1 recall, not Stage 2.

### Exp 8 — Temporal & Behavioral Features (`temporal_features.py`)

UNSW-NB15 — flow only vs temporal only vs combined:

| Feature set | Backdoor recall | Analysis recall | Overall recall | KS |
|---|---|---|---|---|
| Flow only (baseline) | 8.1% | 2.7% | 8.6% | 0.414 |
| **Temporal only** | **39.1%** | **34.7%** | **44.0%** | **0.438** |
| Flow + Temporal combined | 11.8% | 5.5% | 31.0% | 0.323 |

Temporal alone lifts Backdoor 4.8x and Analysis 12x. Combining hurts (dimensionality dilution).
Key signal: **TTL values**, not beacon periodicity. sttl d=+2.51 for Backdoor, ct_state_ttl d=+1.51.
Shellcode remains ~1% regardless — single-shot exploit, no temporal signature.

CTU-13 — core vs core+IAT temporal: F1 lifts from 0.577 to 0.857, KS from 0.664 to 0.830.

**Implication**: Stage 1 needs two parallel heads — flow-AE for known attack recall,
temporal-AE for hidden/stealthy attack recall. Naive concatenation doesn't work.

### Exp 9 — Theorem Validation (`theory.md` + `validate_theory.py`)

Three theorems formalised and validated on real data:

**Theorem 1 (KS ceiling)** — sup_t J(t) = KS proven and verified to machine precision
(diff = 0 for AE, 5.6e-17 for IF on CTU-13). Corollaries confirmed:
- BA ceiling (1+KS)/2: AE = 0.931 predicted, 0.929 observed — AE operates AT its ceiling
- Recall bound at 5% FPR budget: IF <= 0.507 (explains the 55% plateau in one line)
- KS >= AUC - 1/2 holds for both detectors

**Theorem 2 (OR-fusion miss-product law)** — under conditional independence,
union miss rate = product of head miss rates. Validated on UNSW-NB15 dual heads:

| Quantity | Predicted (closed form) | Actual |
|---|---|---|
| Union recall | 0.488 | **0.491** |
| Union FPR | 0.152 | 0.143 |
| rho_miss (independence test) | 1.000 if independent | **0.994** |

The flow-AE and temporal-AE heads are *empirically conditionally independent*
(rho_miss = 0.99, conditional MI = 0.28 bits). The dual-head union is not a heuristic —
it follows a law. Per-type rho_miss all in [1.00, 1.13].
Fusion-benefit criterion satisfied with 6x margin.
**Union Stage 1 recall: 49.1% overall vs 8.6% flow-only** — Backdoor 41%, Analysis 35%, Worms 70%.

**Theorem 3 (EVT/GPD thresholds)** — normal-traffic MSE tail fitted with Generalized
Pareto: shape xi = 1.12 (extremely heavy tail — infinite variance). Calibration at
target FPR q=0.001: GPD threshold realizes 0.00049 (on target), percentile threshold
realizes 0.00378 (3.8x over budget). GPD is the principled replacement for the
arbitrary 95th-percentile threshold and extrapolates below data resolution.

---

## What We Know Doesn't Work

- **Naive all-features IF**: Curse of dimensionality — worse than 10-feature baseline
- **Fixed contamination**: PR optimal threshold differs from contamination-implied threshold
- **LOF for botnet**: Botnet flows cluster — not locally sparse — KS=0.155
- **Simple ensemble average**: Weak LOF drags down AE — KS drops 0.860 to 0.606
- **AE alone for Fuzzers/Shellcode**: Random-payload/single-shot — low recall regardless
- **Flow + Temporal combined naively**: Dimensionality dilution — worse than temporal alone

## What Works

- **AE on flow features**: KS=0.860 on CTU-13, F1=0.928 — strong for structured C&C attacks
- **Temporal features alone**: Backdoor 39%, Analysis 35% — TTL and ct_state_ttl are the key signal
- **IAT features on CTU-13**: F1 lifts to 0.857, KS=0.830 — significant gain
- **Two-stage pipeline**: F1=0.945, 87% FP reduction on CTU-13
- **Zero-day queue**: 71% precision — hidden types route automatically, zero false classifications

---

## Current Roadmap

| Step | What | Status |
|---|---|---|
| 1 | IF baseline + KS diagnosis | Done |
| 2 | AE vs IF comparison (CTU-13) | Done |
| 3 | Cross-dataset validation (UNSW-NB15) | Done |
| 4 | Two-stage pipeline + zero-day simulation | Done |
| 5 | Temporal features experiment | Done |
| 6 | Dual-head Stage 1 (flow-AE + temporal-AE) | **Next** |
| 7 | Paper write-up | After step 6 |
