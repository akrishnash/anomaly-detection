# Project Progress — Network Anomaly Detection

Last updated: 2026-07-03

---

## The Story So Far (executive summary)

We set out to build an unsupervised anomaly detector for network traffic and hit the
well-known ~60% recall wall. Instead of tuning past it, we **proved the wall is
structural** (Theorem 1: the KS distance between attack/normal score distributions is a
hard ceiling on any threshold detector), identified the cause (**anomalous != malicious**
— stealthy attacks are engineered to look statistically normal), and then broke the
ceiling by changing the *representation*, not the algorithm:

1. **Reconstruction anomaly beats isolation anomaly** for structured attacks:
   AE trained on normal traffic only → KS 0.445 → 0.860, F1 0.617 → 0.928 on CTU-13.
2. **No single anomaly notion generalises** — AE collapses on UNSW-NB15 Fuzzers (8%)
   where IF gets 29%; both fail on Backdoor/Analysis/Shellcode at the per-flow level.
3. **Temporal/behavioral features fix the stealthy-attack blind spot**: temporal-only AE
   lifts Backdoor 8→39% and Analysis 3→35%. The signal is TTL fingerprints, not timing.
4. **Dual-head fusion follows a law** (Theorem 2): the two AE heads are empirically
   conditionally independent (rho_miss=0.994), so union recall is predicted in closed
   form (0.488 predicted, 0.491 measured). Stage 1 recall: 8.6% → **49.1%**.
5. **Thresholds are now parameter-free** (Theorem 3): a GPD tail fit calibrates the
   false-positive rate at any target, where percentile thresholds overshoot 3.8x.
6. **The two-stage architecture works end-to-end**: Stage 1 (dual-head AE zero-day net)
   → Stage 2 (GBM known-attack classifier) → zero-day candidate queue. CTU-13 F1=0.945
   with 87% FP reduction. Dual-head zero-day simulation: pipeline F1 0.152 → **0.643**,
   Backdoor end-to-end 5% → **27.8%**, queue precision **86.7%**; of flagged hidden-family
   flows, <1% are silently cleared — the rest reach an analyst (queue or misattributed alert).

Target: IEEE TNSM / Computers & Security. Theory + validation are done; the last
experiment before writing is wiring the dual-head Stage 1 into Stage 2.

---

## Environment

- **Python**: `C:\Users\ADRIN-ISRO\anaconda3\envs\yolov8\python.exe`
  - Base anaconda Python is broken (SRE module mismatch — bomba_backend editable install removed)
  - Always use the `yolov8` conda env (sklearn, numpy, pandas, matplotlib, scipy all present)
- **LaTeX**: MiKTeX installed (`pdflatex` on PATH) — paper builds locally or on Overleaf
- **Run from**: `E:\Projects Internet room\anamoly_detection\`
- **GitHub**: https://github.com/akrishnash/anomaly-detection.git (old `anamoly_detection` URL redirects)
- Console is cp1252: keep Python `print` output ASCII (no unicode arrows), avoid `%` in inline PowerShell f-strings

---

## Datasets

| Dataset | File | Rows | Format | Labels |
|---|---|---|---|---|
| CTU-13 Attack | `sample_logs/CTU13_Attack_Traffic.csv` | 38,898 | CICFlowMeter | binary (1) |
| CTU-13 Normal | `sample_logs/CTU13_Normal_Traffic.csv` | 53,314 | CICFlowMeter | binary (0) |
| UNSW-NB15 Train | `sample_logs/unsw_nb15/UNSW_NB15_training-set.csv` | 175,341 | Argus/Bro | multi-class |
| UNSW-NB15 Test | `sample_logs/unsw_nb15/UNSW_NB15_testing-set.csv` | 82,332 | Argus/Bro | multi-class |

CTU-13: real university botnet traffic (Neris, Rbot, Menti), 57 CICFlowMeter features.
UNSW-NB15: 9 attack types (Generic, Exploits, DoS, Fuzzers, Reconnaissance, Backdoor,
Analysis, Shellcode, Worms), 39 Argus features. All dataset files are gitignored.

Standard protocol everywhere: median imputation of inf/NaN, log1p on |skew|>2 columns,
StandardScaler — all fitted on the training partition only (no leakage).

---

## Codebase Map

| File | What it does | Status |
|---|---|---|
| `run_ctu13.py` | IF on CTU-13, 10 features. **Baseline numbers.** | Done |
| `run_ctu13_v2.py` | All-57-features IF — curse of dimensionality demo | Done |
| `compare_datasets.py` | Attack vs Normal: Cohen's d, ROC, PR, threshold sweep | Done |
| `diagnose_overlap.py` | KS ceiling diagnostic: score overlap + CDF gap figure | Done |
| `ensemble_detector.py` | IF + LOF + AE comparison; AE dominates, averaging hurts | Done |
| `stage2_supervised.py` | Two-stage pipeline: AE → GBM → zero-day queue (both datasets) | Done |
| `zero_day_sim.py` | Zero-day hold-out simulation: 4 attack types hidden from Stage 2 | Done |
| `temporal_features.py` | Flow vs temporal vs combined feature sets, both datasets | Done |
| `theory.md` | Three theorems with proofs: KS ceiling, fusion law, EVT thresholds | Done |
| `validate_theory.py` | All three theorems verified on CTU-13 + UNSW-NB15 | Done |
| `paper/main.tex` | IEEE (IEEEtran) journal draft — theory section complete with validated numbers; experiment/discussion sections stubbed pending dual-head result | In progress |
| `ieee_paper_draft.md` | Markdown paper skeleton (local only, deliberately uncommitted) | Parked |
| `dual_head_detector.py` | Fused dual-head Stage 1 wired into Stage 2 + zero-day queue re-run | **Next** |
| `explain_isolation_forest.py` | Educational IF walkthrough on toy data | Done |
| `agent.py` / `cve_db.py` | GPT-4o triage agent + CVE/ATT&CK lookup | Done |
| `streamlit_app.py` | Interactive score-overlap explorer (live on Streamlit Cloud) | Done |

Figures in `graphs/`: `anomaly_report_ctu13.png`, `ctu13_all_features.png`,
`ctu13_comparison.png`, `overlap_ctu13.png`, `ensemble_comparison.png`,
`two_stage_results.png`, `zero_day_sim.png`, `temporal_features.png`,
`theory_validation.png`, `isolation_forest_explained.png`.

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
KS = 0.445  ->  max achievable (TPR - FPR) = 0.445
AUC = 0.677
-> Heavy overlap. Ceiling is STRUCTURAL. Fix = change representation, not threshold.
```

This became the core claim of the paper, later formalised as Theorem 1 (Exp 9).

### Exp 5 — Ensemble: IF + LOF + AE (`ensemble_detector.py`)

```
IF    KS=0.445  AUC=0.677  Precision=0.584  Recall=0.467
LOF   KS=0.155  AUC=0.537  (weakest — botnet flows cluster, not locally sparse)
AE    KS=0.860  AUC=0.978  Precision=0.977  Recall=0.898  <- dominates
Ensemble (avg)  KS=0.606   (LOF drags it down — averaging hurts)
```

AE trained on normal only. Botnet C&C fails reconstruction: MSE ratio = 23.4x higher
on attack vs normal. Key insight: reconstruction anomaly >> isolation anomaly here.

Proper train/test split verification (no leakage):
```
AE (95th pct threshold, held-out test):
  Precision=0.950  Recall=0.906  F1=0.928  Accuracy=0.929
  TN=2,285  FP=115  FN=225  TP=2,175
```

### Exp 6 — Cross-Dataset: UNSW-NB15 (`ensemble_detector.py` + inline)

```
Train: 56,000 normal + 119,341 attack | Test: 37,000 normal + 45,332 attack
```

| Detector | Precision | Recall | F1 | AUC |
|---|---|---|---|---|
| IF | 0.349 | 0.277 | 0.309 | 0.254 |
| AE (95th pct) | 0.816 | 0.335 | 0.475 | 0.709 |

Per-attack-type recall (AE vs IF):
- Fuzzers (6K):    AE=8%,  IF=29%  <- AE fails on random payload
- Exploits (11K):  AE=47%, IF=48%  <- tie
- Generic (19K):   AE=43%, IF=21%  <- AE wins
- Shellcode (378): AE=2%,  IF=2%   <- both fail
- DoS (4K):        AE=23%, IF=24%  <- tie

**Finding**: best anomaly notion is attack-type dependent.
No single unsupervised detector generalises across all attack families.

### Exp 7 — Two-Stage Pipeline (`stage2_supervised.py`)

Architecture: Stage 1 (AE, 95th pct) flags → Stage 2 (GBM) classifies flagged pool →
low-confidence (<0.60) flows go to the zero-day candidate queue.

CTU-13 (70/30 split):

| Component | Precision | Recall | F1 | False positives |
|---|---|---|---|---|
| Stage 1 alone (AE) | 0.951 | 0.904 | 0.927 | 84 |
| Full pipeline | **0.993** | 0.901 | **0.945** | **11** |

**87% FP reduction** at <0.3 pt recall cost.
UNSW-NB15: limited gain — bottleneck is Stage 1 recall (33%), not false positives.

### Exp 7b — Zero-Day Simulation (`zero_day_sim.py`)

Train Stage 2 on 5 known types (Generic, Exploits, DoS, Fuzzers, Recon).
Hold out 4 completely: **Backdoor, Shellcode, Analysis, Worms**.

```
Zero-day queue: 1,555 flows (1.9% of test set) | 71% precision (1,097 real attacks)
Hidden types in queue: Backdoor=31, Analysis=17, Shellcode=4, Worms=1
End-to-end hidden-type rate: 1-5% -> bottleneck is Stage 1 recall, not Stage 2
```

**Correction (found in Exp 10)**: the original claim "zero misclassifications of hidden
types as known types" was an accounting artifact — Stage 2 could never predict a hidden
label, so the per-type 'known' column read zero by construction. Exp 10 measures this
properly: some flagged hidden flows ARE high-confidence classified as known attack types
(misattribution). The honest statement: flagged hidden flows are alerted (queue or
misattributed known-attack alert), almost never silently cleared. See Exp 10.

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

### Exp 9 — Theory Layer (`theory.md` + `validate_theory.py`)

Three theorems formalised with proofs and validated on real data
(figure: `graphs/theory_validation.png`):

**Theorem 1 (KS ceiling)** — sup_t J(t) = KS proven and verified to machine precision
(diff = 0 for AE, 5.6e-17 for IF on CTU-13). Corollaries confirmed:
- BA ceiling (1+KS)/2: AE = 0.931 predicted, 0.929 observed — **AE operates AT its ceiling**
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
realizes 0.00378 (3.8x over budget). GPD replaces the arbitrary 95th-percentile
threshold and extrapolates below data resolution. Zero free parameters at deployment.

### Exp 10 — Dual-Head Two-Stage Detector (`dual_head_detector.py`) — FINAL SYSTEM

The theory wired into one system: Stage 1 = flow-AE UNION temporal-AE (Thm 2),
Stage 2 = GBM trained on 5 known types only, 4 types hidden (same protocol as Exp 7b).

**Stage 1 ablation (UNSW-NB15 test):**

| Config | TPR | FPR | Backdoor | Analysis | Shellcode | Worms |
|---|---|---|---|---|---|---|
| A1 flow only | 0.086 | 0.086 | 0.08 | 0.03 | 0.01 | 0.68 |
| A2 temporal only | 0.440 | 0.073 | 0.39 | 0.35 | 0.02 | 0.18 |
| **A3 UNION** | **0.491** | 0.143 | **0.41** | **0.35** | 0.02 | **0.70** |
| A4 INTERSECTION (control) | 0.034 | 0.016 | 0.06 | 0.02 | 0.00 | 0.16 |

Union recall 0.491 matches the Thm 2 miss-product prediction (0.488). Intersection
control collapses as theory predicts.

**Full pipeline, identical Stage 2, only Stage 1 changes:**

| Metric | flow-only | dual-head |
|---|---|---|
| Pipeline recall | 0.084 | **0.488** (5.8x) |
| Pipeline precision | 0.850 | **0.939** (also UP) |
| Pipeline F1 | 0.152 | **0.643** (4.2x) |
| ZD queue size | 1,135 | 3,624 |
| ZD queue precision | 0.753 | **0.867** |
| Backdoor end-to-end | 5.0% | **27.8%** |
| Analysis end-to-end | 2.2% | **23.8%** |
| Shellcode end-to-end | 0.5% | 2.1% |
| Worms end-to-end | 0.0% | 2.3% |

**Hidden-flow fate accounting (dual-head)**: of 518 hidden-family flows flagged by
Stage 1: 332 -> zero-day queue, 182 -> alerted as (family-misattributed) known attacks,
only 4 (<1%) silently cleared as Normal. Hidden attacks are misattributed, not missed.

**Honest limitations**: (a) family misattribution — the alert fires but with the wrong
attack label; (b) Shellcode stays ~2% — single-shot exploits leave no flow/temporal
footprint, this is the boundary of flow-level detection; (c) GPD thresholds realize
0.046 FPR vs 0.02 target on UNSW test — train/test normal-traffic drift breaks the
stationarity assumption; deployment needs periodic refit (DSPOT-style).

### Paper — `paper/main.tex` (IEEE IEEEtran format)

Created 2026-07-03. Contains: full abstract with all validated numbers, introduction
with 4 contributions, complete Section III (Theoretical Framework — Theorems 1-3 with
proofs, corollaries, propositions, and empirical validation paragraphs), dataset
section, **Section on the two-stage system with ablation + pipeline tables (Exp 10
numbers)**, references. Compiles clean with pdflatex (MiKTeX). Remaining TODOs:
related work expansion, discussion, conclusion.
Markdown precursor `ieee_paper_draft.md` kept local-only by choice (research gates writing).

---

## What We Know Doesn't Work

- **Naive all-features IF**: Curse of dimensionality — worse than 10-feature baseline
- **Fixed contamination**: PR optimal threshold differs from contamination-implied threshold
- **LOF for botnet**: Botnet flows cluster — not locally sparse — KS=0.155
- **Simple ensemble average**: Weak LOF drags down AE — KS drops 0.860 to 0.606
- **AE alone for Fuzzers/Shellcode**: Random-payload/single-shot — low recall regardless
- **Flow + Temporal combined naively**: Dimensionality dilution — worse than temporal alone
- **Percentile thresholds in the deep tail**: 3.8x FPR overshoot at q=0.001 (heavy tail, xi=1.12)

## What Works

- **AE on flow features**: KS=0.860 on CTU-13, F1=0.928 — strong for structured C&C attacks
- **Temporal features alone**: Backdoor 39%, Analysis 35% — TTL and ct_state_ttl are the key signal
- **IAT features on CTU-13**: F1 lifts to 0.857, KS=0.830 — significant gain
- **Dual-head OR-fusion**: Stage 1 recall 8.6% -> 49.1%, predicted by the miss-product law
- **Dual-head full pipeline**: F1 0.152 -> 0.643 with precision UP (0.850 -> 0.939)
- **Two-stage pipeline on CTU-13**: F1=0.945, 87% FP reduction
- **Zero-day queue**: 86.7% precision (dual-head); <1% of flagged hidden flows silently cleared
- **GPD thresholds**: calibrated FPR within-distribution; needs periodic refit under drift

---

## Current Roadmap

| Step | What | Status |
|---|---|---|
| 1 | IF baseline + KS diagnosis | Done |
| 2 | AE vs IF comparison (CTU-13) | Done |
| 3 | Cross-dataset validation (UNSW-NB15) | Done |
| 4 | Two-stage pipeline + zero-day simulation | Done |
| 5 | Temporal features experiment | Done |
| 6 | Theory layer: 3 theorems proven + validated | Done |
| 7 | Dual-head detector + Stage 1 ablation (Exp 10) | Done |
| 8 | IEEE LaTeX draft — theory + system sections with final numbers | In progress |
| 9 | Finish paper: related work, discussion, conclusion | **Next** |
| 10 | Optional hardening: 3rd dataset (CIC-IDS-2018), Stage 2 classifier swap ablation | If time allows |

Open items besides the roadmap: third dataset (CIC-IDS-2018) would harden the
generalisation claim; streaming Stage 1 (RRCF) is the org-deployment track, separate
from the paper.
