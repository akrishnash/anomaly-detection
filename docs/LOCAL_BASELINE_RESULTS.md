# Local Baseline Retraining — Results (2026-07-17)

Execution of `docs/LOCAL_BASELINE_DATASET_PLAN.md` on the first capture batch.
Models in `project/models/` are now trained on **this network's benign traffic**;
the previous CICDDoS2019-trained models are preserved in
`project/models_backup_cicddos/` (rollback = plan Phase 6).

## Phase 1 — Capture (partial vs plan)

User-captured with Wireshark on the main LAN NIC, full payloads (no snaplen):

| File | Packets | Duration | Notes |
|---|---|---|---|
| `data/baseline_train/wireshark_data/capture1.pcapng` | 358,786 | ~19 min (10:26–10:45) | truncated mid-packet (Wireshark killed); read up to truncation |
| `data/baseline_train/wireshark_data/capture2.pcapng` | 876,022 | ~39 min (11:11–11:50) | includes streaming session |

Total ~58 min / 1.23 M packets — below the plan's 4–8 h across ≥2 days target.
**Iteration 2 should add an idle-machine session and a different-day session**,
then rerun the same three commands below.

## Phase 2 — pcap → flows (`project/backend/pcap_to_flows.py`, new)

- Streams packets (scapy `PcapReader`; `rdpcap` cannot hold 1.4 GB), restricts
  dissection to L2–L4 for speed (~3.3 k pkt/s), tolerates truncated captures.
- **Slices packets into fixed 30 s windows before flow grouping** (matches the
  live sliding window; prevents train/serve skew), then reuses
  `flow_generator.group_packets_into_flows` + `feature_extractor.extract_flow_features`.

```
python pcap_to_flows.py --pcap-dir "..\..\data\baseline_train\wireshark_data" ^
    --window-sec 30 --out "..\..\data\local_baseline\csv\benign_flows.csv"
```

Result: **18,772 flows** (9,695 TCP / 8,988 UDP / 65 ICMP / 24 Other) across 119 windows.

## Phase 3 — Audit with the OLD (CICDDoS2019) models

- Old models flag **35.7%** of this network's benign flows at threshold 0.5
  (q90 score = 1.0) — quantifies the domain-shift false-positive problem that
  motivated the plan (live FP 15–27% previously observed).
- Top-scoring flows inspected manually: HTTPS/QUIC browsing, Cloudflare
  streaming (~1,440 B packets, port 80/443), Windows Update Delivery
  Optimization LAN peers (port 7680), LDAP/RPC/syslog office chatter.
  **No scan-like patterns; nothing removed.**
- Hygiene + split: 18,772 → `benign_train.csv` (15,018) + `benign_val.csv` (3,754).

## Phase 4 — Retrain (`project/backend/train_local_baseline.py`, new)

- Scaler + IsolationForest (contamination 0.01) + Autoencoder all fit on local
  benign only, through the backend's canonical preprocessing path.
- Calibration anchors: `lo` = benign median, `mid` = benign q99 (→ score 0.5).
- **Finding:** the CICDDoS2019 attack reference's *median* raw score lands
  **below the local benign q99 on both heads** (IF 0.556 < 0.636; AE 0.202 < 0.693),
  so the `hi` anchor fell back to benign extrapolation (`hi = mid + (mid−lo)`).
  CICFlowMeter-exported attack flows are not shaped like our 30 s-window scapy
  flows — a cross-domain reference can position an anchor only weakly. The
  trainer now prints this fallback explicitly.

## Phase 5 — Validation

| Check | Result | Verdict |
|---|---|---|
| Benign val FP rate @0.5 | **1.39%** (52/3,754); train 1.85% | PASS (<2–5%) |
| In-domain synthetic attacks | UDP flood / amplification / SYN floods / scan burst → **1.00**; one-way exfil → 0.67; benign HTTPS/DNS controls → 0.07 / 0.00 | PASS |
| CICDDoS2019 testing split (cross-domain) | macro recall ~37%, bimodal: DrDoS_LDAP 93%, Syn 91%, DrDoS_SNMP 88%, WebDDoS 67%, DrDoS_DNS 55% — but NTP/TFTP/UDP ≈ 0% | Informational (see below) |
| Live sanity (10 min browse, ≤2% detection) | **Not yet run — user step** | PENDING |

Cross-domain interpretation: vs the CICDDoS-trained models the detected-family
*set flipped* (Syn/WebDDoS were invisible before, now detected; NTP/TFTP were
detected before, now invisible). Both configurations sit at the 10-feature
representation ceiling — which families are visible depends on where the benign
baseline sits in that space. The deployment-relevant checks are the first two
rows plus live behavior; the CICDDoS number is not a regression gate.
The old models' cross-domain "Benign" class also flags at 17% here — that
benign is *their* domain, not ours.

Full numbers: `project/models/local_baseline_metrics.json`.

## Settings fixed (plan "Settings to fix")

`project/logs/database.sqlite` settings updated: `confidence_threshold`
0.85 → **0.5**, `context_window` 13 → **30** (matches `--window-sec 30`).
Note `packet_capture_interface` is still "Wifi" — select **Ethernet 5** in the
UI for live validation.

## Remaining user steps

1. Restart the backend (`python run_all.py`) so it loads the new pickles.
2. Live sanity: capture on Ethernet 5, browse normally ~10 min → expect ≈0–2%
   detection, no Critical alerts.
3. Optional attack drill from another LAN machine: `nmap -sS 192.168.1.123`
   → port-scan campaign should fire within one window.
4. Capture more sessions (idle + different day) and rerun Phases 2–4 to reach
   the ≥50 k-flow / ≥2-day target.

## Rollback

```powershell
Remove-Item "project\models" -Recurse -Force
Copy-Item "project\models_backup_cicddos" "project\models" -Recurse
```
