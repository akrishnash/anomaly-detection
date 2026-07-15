# DDoS Classifier — Progress Log

Conversion of the deployable `project/` IDS app from a supervised XGBoost detector
into a **fully unsupervised two-stage DDoS classifier** that operates on unlabeled
flow or PCAP data.

_Last updated: 2026-07-15_

---

## Goal

Build a DDoS subtype classifier on top of the existing anomaly detector. Given a
flow or a PCAP, flag anomalous traffic and classify it as SYN Flood, UDP Flood,
ICMP Flood, HTTP Flood, Amplification, etc. Requirements:

- Must work on **unlabeled** flow data (no ground-truth labels at inference).
- Streamline the pipeline; **remove XGBoost** (it was the supervised, CTU-13-trained
  decision maker and defeated the unlabeled-data goal).

## New architecture

```
PCAP  ─> flow_generator ─> feature_extractor ─┐
CSV/XLSX ─> preprocessing (canonical schema) ─┴─> 10 features ─> scaler
   │
   ▼
Stage 1 (unsupervised)  anomaly_detector.py
   Isolation Forest score + Autoencoder reconstruction error
   → each calibrated to [0,1] via anchors in meta.pkl
   → fused with union/max → ensemble anomaly probability
   → probs >= confidence_threshold ⇒ anomaly
   │
   ▼
Stage 2 (subtype typing)  ddos_classifier.py
   per-flow rule engine → attack_type, severity, evidence
   per-target aggregation → campaigns (distributed-attack escalation)
```

---

## What changed

### New files
- **`backend/anomaly_detector.py`** — Stage 1. `score_flows(X_scaled)` returns
  `(probs, if_scores, ae_scores)`. IF and AE raw scores are mapped to `[0,1]` with a
  piecewise-linear ramp (`lo→0.0, mid→0.5, hi→1.0`) whose anchors are fitted at
  training time and stored in `meta.pkl["calibration"]`. The two heads are fused by
  union (`max`) so a flow is anomalous if **either** head fires.
- **`backend/ddos_classifier.py`** — Stage 2 + standalone CLI.
  - `classify_flow(flow)` → `{attack_type, severity, confidence, evidence[]}`.
    Rules cover: SYN Flood, UDP Flood, ICMP Flood, Amplification/Reflection
    (DNS/NTP/SNMP/LDAP/SSDP/Memcached/CharGen/Portmap), HTTP Flood, Slowloris,
    Port Scan/Recon, Brute Force, Data Exfiltration, Volumetric Flood. Falls back to
    **"Unknown Anomaly"** rather than forcing a DDoS label without evidence.
  - `aggregate_campaigns(anomalous_flows)` → groups anomalies per destination,
    computes unique-source count and source-IP entropy, and escalates many-source
    attacks to `DDoS: <subtype> (distributed: N sources)` (Critical). Also detects
    single-source many-port probing as `Port Scan / Recon`. Returns campaigns +
    per-flow label refinements.
  - CLI: `python ddos_classifier.py --input capture.pcap|flows.csv [--threshold 0.5] [--output report.json]`.

### Removed
- **`backend/xgboost_classifier.py`** deleted.
- Model assets `models/xgboost.pkl`, `models/aug_scaler.pkl` removed (train script
  also deletes them if present).
- `xgboost` dropped from `requirements.txt`.

### Modified
- **`backend/train_models.py`** — drops `XGBClassifier`/`aug_scaler`; keeps
  scaler + Isolation Forest + Autoencoder; adds ensemble score calibration
  (per-head `lo/mid/hi` anchors saved into `meta.pkl`).
- **`backend/shap_explainer.py`** — now explains the **Isolation Forest** (10 base
  features) instead of XGBoost; signs flipped so positive impact = more anomalous.
  Input is `X_scaled` (10 cols), not the old `X_aug_scaled` (11 cols).
- **`backend/flow_generator.py` / `feature_extractor.py`** — added ICMP handling,
  ACK-flag counting, and fwd/bwd packet counts (feed the rule engine; the 10-feature
  model contract is unchanged).
- **`backend/api.py`** — offline pipeline uses `anomaly_detector.score_flows` +
  single `ddos_classifier.classify_flow` per anomaly (fixes the old double
  `identify_threat_type` call); adds `campaigns[]` to the response; `xgb_prob` →
  `ensemble_score`; `/metrics` asset list + pipeline label updated.
- **`backend/packet_capture.py`** — same Stage-1/Stage-2 swap for the online path;
  snapshot keys `xgb_prob`/`avg_xgb_prob` → `ensemble_score`/`avg_ensemble_score`;
  emits `campaigns`.
- **`backend/database.py`** — `xgb_prob` column renamed to `ensemble_score`
  (in-place `ALTER TABLE ... RENAME COLUMN` migration for existing DBs).
- **`backend/main.py`** — required assets list updated; forces a retrain if
  `meta.pkl` predates the calibration anchors.
- **Frontend** — `App.jsx`, `Dashboard.jsx` (`xgb_prob` → `ensemble_score`, gauge
  relabeled "Ensemble Anomaly Score"), `Settings.jsx` (model options), and
  `OfflineDetection.jsx` (progress-stage text).
- **`test_backend.py`** — replaced XGBoost tests with `anomaly_detector`
  calibration + `ddos_classifier` rule-engine + campaign-aggregation tests.

---

## Verification

| Check | Result |
|-------|--------|
| Backend unit tests (`python -m unittest test_backend`) | **7/7 pass** |
| CLI on synthetic PCAP | UDP Flood, DNS Amplification, ICMP Flood classified correctly |
| CLI on CTU-13 attack flow CSV | subtypes fire; non-flood botnet flows honestly labeled "Unknown Anomaly" |
| Offline API (`/api/upload` + `/api/start-offline`) | HTTP 200, `ensemble_score` + subtypes + `campaigns` present, `/api/metrics` = Green |
| Benign CTU-13 false-positive rate @0.5 | **2.6%** |

Run the backend with **base anaconda** python (`C:\Users\ADRIN-ISRO\anaconda3\python.exe`)
— it has `shap` + `fastapi`; the `yolov8` env does not have `shap`.

Retrain after pulling: `python project/backend/train_models.py` (regenerates
`scaler.pkl`, `isolation_forest.pkl`, `autoencoder.pkl`, `meta.pkl` with calibration).

---

## Known limitations (pre-existing, in `flow_generator`)

1. **Direction is inferred from sorted-IP order**, not true client→server, so a
   campaign's reported "target" can be the attacker IP. Flood "one-directional"
   tests were made direction-agnostic (`max(fwd,bwd)/total` asymmetry) to compensate.
2. **Raw-pcap SYN floods with spoofed source ports** fragment into single-packet
   flows that Stage 1 does not flag individually, so they are missed on PCAP input.
   The classifier is strongest on **flow-level CSV** (CICFlowMeter/CTU-13-style),
   where each flood is already one flow record with proper SYN counts and directional
   bytes.

**Next (optional):** add a per-`destination:port` aggregation pass in
`flow_generator` so raw-pcap SYN floods are detected as a group.
