# DDoS Classifier — Progress Log

Conversion of the deployable `project/` IDS app from a supervised XGBoost detector
into a **fully unsupervised two-stage DDoS classifier** that operates on unlabeled
flow or PCAP data.

_Last updated: 2026-07-16_

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

## 2026-07-16 — UI traceability & per-attack-type detail

Goal: beyond the pie chart, surface graphs + packet details per DDoS type, and
make every verdict traceable (why was this flow classified as attack X?).

### Backend
- **`anomaly_detector.py`** — new `score_flows_detailed()` also returns the
  per-head **calibrated** probabilities (`if_probs`, `ae_probs`), so callers can
  show which head crossed the threshold. `score_flows()` is now a wrapper.
- **`ddos_classifier.py`** — `aggregate_campaigns` refinements are now 3-tuples
  `(attack_type, severity, reason)`; `reason` is a human-readable sentence
  recording the cross-flow evidence (e.g. "40 unique sources converging on
  10.0.0.5, entropy 1.00"). CLI records `refined_from`/`refinement_reason`.
- **`api.py` `/start-offline`** — each flow now carries:
  - `evidence[]` + `rule_confidence` (structured, no longer only baked into text);
  - `classification_trace` with `stage1_anomaly_detection` (raw + calibrated IF/AE
    scores, threshold, `triggered_by`, decision), `stage2_rule_engine`
    (matched signature, confidence, evidence), `stage3_campaign_refinement`
    (original → refined label + reason, or null).
  Response gains `severities[]`, `score_distribution[]` (10-bin histogram of
  ensemble scores split normal/attack), and `attack_details[]` (per attack type:
  flows, packets, bytes, SYN pkts, avg/peak pps, severity mix, top 5 sources,
  top 5 targets, ports, example evidence).
- **`packet_capture.py`** — consumes the 3-tuple refinements; alerts carry
  `refinement_reason`.

### Frontend (`OfflineDetection.jsx`)
- New charts row: **severity distribution** (status-colored bars) and
  **ensemble score distribution** histogram (benign vs anomalous, stacked).
- **Campaigns panel** — renders the previously-dropped `campaigns[]` (target,
  label, severity, flows, sources, entropy, ports, subtype breakdown).
- **Attack Type Packet Details** cards — per-DDoS-type packets/bytes/rates/top
  sources/targets; clicking a card filters the flow explorer to that type.
- **Classification Trace** panel in each expanded flow: Stage 1 head bars vs
  threshold ("which detector fired"), Stage 2 evidence bullets + rule
  confidence, Stage 3 campaign escalation reason. Severity badge on each row.

### Verified
- `python -m unittest test_backend` → **7/7 pass** (campaign tests extended to
  assert the refinement reason).
- End-to-end TestClient smoke test (40-source synthetic SYN flood CSV through
  `/api/upload` + `/api/start-offline`): all new fields present; flood flows
  trace Stage 1 (both heads fired) → Stage 2 (SYN-flood evidence, 95% rule
  confidence) → Stage 3 (escalated to "DDoS: SYN Flood", Critical).
- `npm run build` (frontend) → success.

---

## 2026-07-16 — Google Stitch "Sentinel AI" UI integration

Integrated the 4 Stitch-designed screens (`ui stitch/`) into `project/frontend`
as fully data-wired React pages, keeping the "Obsidian Sentinel" design system
(glassmorphism, Electric Cyan/Neon Purple, Geist + Space Mono + Material
Symbols). **Zero CDN dependencies** — built for offline machines.

### Offline assets
- Fonts downloaded to `src/assets/fonts/` (Geist variable, Space Mono 400/700,
  Material Symbols Outlined variable ~3.9 MB full icon set) with a local
  `fonts.css`; verified the production bundle contains **no external URLs**.
- Stitch's CDN Tailwind replaced by the existing build-time Tailwind; design
  tokens from `DESIGN.md` merged into `tailwind.config.js`.
- Remote Stitch images (avatar, world map, textures) replaced with local
  SVG/CSS equivalents; the WebGL shader background was ported as a React
  component (`src/sentinel/ShaderBackground.jsx`).

### New frontend structure
- `src/sentinel/` — `SentinelLayout.jsx` (sidebar + topbar shell, live clock,
  model-health indicator, search → Flow Explorer), `ShaderBackground.jsx`,
  `common.jsx` (severity/attack-icon helpers), `sentinel.css`.
- `src/pages/sentinel/SocDashboard.jsx` (**home**) — model health, analyzed
  flows, anomalies, derived threat level; campaign vector SVG (animated
  source→target arcs from real `campaigns[]`/`attack_details[]`); confidence /
  accuracy / benign ring cards; live backend log terminal (`/api/logs`).
- `src/pages/sentinel/DetectionPipeline.jsx` — upload + run wired to
  `/api/upload` + `/api/start-offline`; 8-stage animated pipeline rail;
  real ensemble score-distribution histogram; model-asset health; log terminal.
- `src/pages/sentinel/FlowExplorer.jsx` — filterable flow table (IP/severity/
  protocol/attack type, anomalies-only toggle); expandable rows render the real
  3-stage `classification_trace`; JSON export; footer stats.
- `src/pages/sentinel/DdosClassifier.jsx` — per-subtype cards from
  `attack_details[]` (packets, volume, rates, top attacker, ports, evidence,
  rule confidence) linking into the explorer; anomaly gauge, severity
  distribution, campaign list sidebar.
- `App.jsx` — Sentinel shell hosts everything; legacy pages kept as
  "Analytics (Live)", "Live Capture", "Intelligence Reports", "Settings".

### Backend additions
- `GET /api/last-run` — the last completed offline analysis is kept in memory
  and replayed to all screens after a page refresh.
- `attack_details[]` now includes `avg_rule_confidence` (per-subtype mean of
  Stage 2 rule confidence) for the classifier cards.

### Verified
- `npm run build` ✓ (bundle scanned: no external hosts).
- Backend unit tests 7/7 ✓; smoke test extended to cover `/api/last-run`
  parity + `avg_rule_confidence`.
- Live run: uvicorn + Vite (port 3000), synthetic 112-flow CSV through the
  real API → 3 campaigns (DDoS: SYN Flood, DNS Amplification), all Sentinel
  modules transform HTTP 200 through the dev server.

---

## 2026-07-16 — Parquet ingestion (CICDDoS2019)

- **`api.py`** — `/api/upload` + `/api/start-offline` accept `.parquet`
  (pyarrow metadata read for fast row counts; `to_json` preview handles
  timestamps/NaN). Ground-truth label parsing generalized: any non-benign
  label ("Syn", "DrDoS_DNS", …) counts as attack, and label-column detection
  tolerates CIC's leading-space " Label".
- **`ddos_classifier.py` CLI** — `--input file.parquet` supported.
- **`preprocessing.py`** — alias dictionary extended with CICDDoS2019 parquet
  spellings (`Fwd/Bwd Packets Length Total`, `Total Length of Fwd/Bwd
  Packets`, `Subflow Fwd/Bwd Bytes`) so byte features no longer zero out.
- **Frontend** — both file pickers (Sentinel Detection Pipeline + legacy
  Offline page) accept `.parquet`. `pyarrow` added to `requirements.txt`.
- Verified with `data/CICDDos2019/Syn-testing.parquet`: 907 flows / 78 cols
  ingest cleanly, subtypes fire, labels parsed (533 Syn / 374 Benign).

**Known limitation confirmed on CICDDoS2019:** its SYN-flood rows are 2–4
packet, 0-byte micro-flows with `SYN Flag Count = 0` (CICFlowMeter artifact),
so the CTU-13-calibrated Stage 1 scores them ~0.33 — below threshold →
recall ≈ 0 on this dataset. This is limitation #2 (fragmenting spoofed SYN
floods); fixing it needs either retraining/calibrating on CICDDoS2019 benign
traffic or the planned per-`destination:port` aggregation pass, not a change
to file ingestion.

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
