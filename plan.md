# Research Plan — Two-Stage Zero-Day Detector

*Started: 2026-06-27. Updated: 2026-07-01.*
*Scope: complete, honest paper on why unsupervised NIDS plateau and how a two-stage
architecture breaks the ceiling — validated on two real-world datasets (CTU-13 + UNSW-NB15).*

---

## The Thesis (updated)

Unsupervised network anomaly detectors plateau at ~60% because **"anomalous ≠ malicious"**:
stealthy C&C beaconing sits inside the normal distribution, while benign high-throughput
flows look anomalous. The failure is structural (KS ceiling = 0.445), not a tuning bug.

The fix is not a better unsupervised algorithm — it is **a two-stage architecture**:
1. **Stage 1 (unsupervised AE)**: catches everything that doesn't look like normal traffic,
   including zero-day attacks the supervised layer has never seen.
2. **Stage 2 (supervised XGBoost)**: classifies the flagged pool into known attack types;
   what remains unclassified is the zero-day candidate queue.

**Working title:**
*"Anomalous ≠ Malicious: A Two-Stage Architecture for Zero-Day Network Intrusion Detection."*

**Three contributions:**
1. **(Diagnosis)** KS-distance decomposition proving the unsupervised ceiling is structural.
2. **(Finding)** Autoencoder reconstruction anomaly outperforms IF on structured attacks
   (CTU-13: +43 pts recall) but degrades on random-payload attacks (UNSW-NB15 Fuzzers).
3. **(Architecture)** Two-stage pipeline: Stage 1 (zero-day net) + Stage 2 (known classifier)
   validated on CTU-13 and UNSW-NB15 — showing per-stage precision/recall and zero-day queue.

---

## Two-Stage Architecture

```
All traffic
    │
    ▼
Stage 1 — Unsupervised AE (trained on normal only)
    │
    ├── Low anomaly score  ──→  NORMAL  (pass through)
    │
    └── High anomaly score ──→  SUSPICIOUS POOL
                                      │
                                      ▼
                              Stage 2 — XGBoost
                              trained on known labeled attacks
                              (CTU-13 + UNSW-NB15)
                                      │
                                      ├── High confidence match ──→  KNOWN ATTACK
                                      │                               (classify + alert)
                                      │
                                      └── Low confidence / no match ──→  ZERO-DAY QUEUE
                                                                          (send to analyst)
```

Key insight: Stage 2 filters Stage 1's false positives (known-normal flows that AE
flagged) while preserving genuinely novel attacks in the zero-day queue.

---

## What We Know (completed experiments)

### Unsupervised baselines (CTU-13, 6K+6K flows)

| Detector | Precision | Recall | F1 | KS ceiling |
|---|---|---|---|---|
| IF (10 features) | 0.695 | 0.555 | 0.617 | 0.445 |
| IF (57 features) | 0.584 | 0.467 | 0.519 | — |
| LOF | 0.529 | 0.423 | 0.470 | 0.155 |
| **AE (normal only)** | **0.977** | **0.898** | **0.868** | **0.860** |
| Ensemble avg | 0.637 | 0.509 | 0.566 | 0.606 |

### Cross-dataset (UNSW-NB15, 175K train / 82K test, 9 attack types)

| Detector | Precision | Recall | F1 | ROC-AUC |
|---|---|---|---|---|
| IF | 0.349 | 0.277 | 0.309 | 0.254 |
| AE (95th pct) | **0.816** | 0.335 | 0.475 | **0.709** |

AE collapses on Fuzzers (8% recall) and Shellcode (2%) — random-payload attacks.
IF beats AE on Fuzzers (29% vs 8%). Neither is a complete detector alone.

### Key finding
Best anomaly notion is attack-type dependent — no single unsupervised detector
generalises across all categories. Two-stage architecture resolves this.

---

## 4-Act Plan

### Act 1 — Diagnosis (DONE)
- [x] Honest baseline: IF at 40% contamination, CTU-13 train/test split
- [x] KS distance ceiling: KS=0.445, AUC=0.677 → structural, not tunable
- [x] Cohen's d per feature → identifies real discriminators (SYN flags d=0.86)
- [x] Overlap diagnosis figure (`diagnose_overlap.py`, `graphs/overlap_ctu13.png`)

### Act 2 — Finding: anomaly notion matters (DONE)
- [x] AE trained on normal only → KS=0.860, Precision=0.977, Recall=0.898 on CTU-13
- [x] Ensemble (IF + LOF + AE) — averaging hurts: LOF drags to KS=0.606
- [x] Cross-dataset test on UNSW-NB15 → AE recall collapses on Fuzzers/Shellcode
- [x] Per-attack-type breakdown confirms attack-type dependency
- **Finding**: reconstruction anomaly >> isolation anomaly for structured attacks;
  neither dominates across all attack families.

### Act 3 — Two-Stage Architecture (DONE)
- [x] Design: Stage 1 (AE) + Stage 2 (GBM on flagged pool)
- [x] `stage2_supervised.py` — CTU-13: F1=0.945, 87% FP reduction
- [x] `zero_day_sim.py` — UNSW-NB15 zero-day simulation: 71% queue precision
- [x] Zero-day queue proven: 4 completely hidden types route to queue automatically
- **Key result**: Stage 2 never misclassifies a hidden attack as a known type.
  Bottleneck = Stage 1 recall on low-volume attacks (2–13% on Backdoor/Shellcode).

### Act 4 — Temporal Features Experiment (DONE)

Go/no-go result from `temporal_features.py`:

**UNSW-NB15:**
- Temporal features *alone* lift Backdoor recall 8% → 39% (4.8x) and Analysis 3% → 35% (12x)
- Combining flow + temporal hurts (dimensionality dilution — same curse as IF + 57 features)
- Key signal: `sttl` (source TTL, d=+2.51) and `ct_state_ttl` (d=+1.51), not beacon timing
- Shellcode remains ~1% — single-shot exploit, no temporal footprint

**CTU-13:**
- Adding IAT temporal features lifts F1 0.577 → 0.857, KS 0.664 → 0.830

**Implication for architecture**: Stage 1 needs two parallel AE heads, not one.
Naive concatenation doesn't work. Selective feature sets, separately trained.

### Act 5 — Dual-Head Stage 1 (NEXT)

**Architecture revision:**

```
All traffic
    │
    ├── Flow-AE (core flow features)        → good at Generic, Exploits, C&C
    │
    └── Temporal-AE (TTL + ct_* features)   → good at Backdoor, Analysis
              │
              └── Union of flags → SUSPICIOUS POOL
                                        │
                                        ▼
                                Stage 2: GBM classifier
                                        │
                              known → alert | unknown → zero-day queue
```

**Build** `dual_head_detector.py`:
  - Head 1: AE on flow features (existing, reuse ensemble_detector.py code)
  - Head 2: AE on temporal features only (sttl, ct_state_ttl, ct_dst_sport_ltm, sinpkt)
  - Union flag: flagged by either head → suspicious pool
  - Stage 2: same GBM as before
  - Expected lift: Backdoor end-to-end from 5% to 30%+; Analysis from 3% to 25%+

**Key metric to report**: end-to-end recall on all 9 UNSW-NB15 attack types,
both heads separately and combined. Show the union beats any single head.

**Ablation** (required for IEEE reviewers):
  - Head 1 only (baseline, already have it)
  - Head 2 only
  - Head 1 + Head 2 union
  - Intersection instead of union (control experiment — should be worse)

### Act 6 — Write (after dual-head result)
- [ ] Section 4: add Exp 8 (temporal) + Exp 9 (dual-head) to tables
- [ ] Section 5 (discussion): update with "TTL signature, not periodicity" finding
- [ ] Section 1 (introduction): write after all results known
- [ ] Abstract: finalise last
- [ ] **Target**: 8-page Computers & Security short paper

---

## Scripts Map

| Script | Role | Status |
|---|---|---|
| `run_ctu13.py` | IF baseline (10 features) | Done |
| `run_ctu13_v2.py` | All-features IF | Done |
| `compare_datasets.py` | Cohen's d + AUC comparison | Done |
| `diagnose_overlap.py` | KS ceiling diagnostic | Done |
| `ensemble_detector.py` | IF + LOF + AE comparison | Done |
| `stage2_supervised.py` | Two-stage pipeline (CTU-13 + UNSW) | Done |
| `zero_day_sim.py` | Zero-day simulation (4 hidden types) | Done |
| `temporal_features.py` | Temporal vs flow feature experiment | Done |
| `explain_isolation_forest.py` | Educational IF walkthrough | Done |
| `theory.md` | Three theorems: KS ceiling, OR-fusion law, EVT thresholds | Done |
| `validate_theory.py` | All theorems verified on CTU-13 + UNSW-NB15 | Done |
| `dual_head_detector.py` | Dual-head Stage 1 wired into Stage 2 + zero-day queue | **Next** |
| `paper_figures.py` | Final publication figures | Planned |

---

## Theory Layer (added 2026-07-03)

The paper now has three theorems, all validated (`validate_theory.py`, `graphs/theory_validation.png`):

1. **KS ceiling theorem**: sup_t J(t) = KS — exact on empirical CDFs. AE runs AT its
   ceiling (0.929 observed vs 0.931 bound) — only representation changes can improve it.
2. **Miss-product law**: dual-head union recall predicted 0.488 in closed form, measured
   0.491. rho_miss = 0.994 — heads are conditionally independent. Union Stage 1 recall
   49.1% vs 8.6% flow-only.
3. **EVT thresholds**: GPD tail fit (xi = 1.12, heavy) gives calibrated FPR at any target;
   percentile thresholds overshoot 3.8x at q=0.001. Removes the last free parameter.

Remaining for the paper: wire dual-head Stage 1 into Stage 2 (`dual_head_detector.py`),
re-run the zero-day simulation with the fused Stage 1, then write.

---

## Venue Targets

- **Computers & Security** (Elsevier, rolling, IF ~5.1) — primary target
- **IEEE TNSM** — secondary
- Workshop @ IEEE S&P or USENIX — fast checkpoint if needed
