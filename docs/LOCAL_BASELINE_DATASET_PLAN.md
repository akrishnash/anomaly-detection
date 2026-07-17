# Local Baseline Dataset — Capture & Retrain Plan

**Goal:** Replace the CICDDoS2019/CTU-13 "normal" baseline with traffic captured from *this* network, so the
unsupervised ensemble (Isolation Forest + Autoencoder) learns what normal looks like **here**. This fixes the
domain-shift false positives seen in live mode (multicast/broadcast chatter, QUIC, NetBIOS scoring ≥ 0.9).

**Machine inventory (verified 2026-07-16):**

| Requirement | Status |
|---|---|
| Npcap driver | Installed, service running, `AdminOnly=0` (no admin needed) |
| scapy | 2.7.0 |
| dumpcap (Wireshark) | `C:\Program Files\Wireshark\dumpcap.exe` (not on PATH) |
| Main LAN NIC | `Ethernet 5` — Intel X540-T, `192.168.1.123` |
| Secondary NIC | `APN1` — Marvell AQtion, `192.9.110.75` (capture too if real traffic flows here) |

---

## Phase 0 — Preparation (5 min)

Add Wireshark tools to the current PowerShell session and create the dataset directories:

```powershell
$env:Path += ";C:\Program Files\Wireshark"
New-Item -ItemType Directory -Force "E:\Projects Internet room\anamoly_detection\data\local_baseline\pcaps"
New-Item -ItemType Directory -Force "E:\Projects Internet room\anamoly_detection\data\local_baseline\csv"
```

Confirm dumpcap sees the NICs and note the number of `Ethernet 5`:

```powershell
dumpcap -D
```

**Rules for the whole capture period:**
- Do **not** run nmap/scan/attack tests, VM pentest labs, or the traffic simulator while capturing — every packet captured is labeled "normal" by assumption.
- Keep usage natural and varied: idle desktop, browsing, streaming, file copy over LAN, video call, git/npm/pip pulls.

---

## Phase 1 — Capture benign traffic (target: 4–8 hours across ≥ 2 days)

Use `dumpcap` (not Wireshark GUI) — it is the low-overhead capture engine and supports ring buffers.
`-s 256` truncates payloads (flow features only need headers — keeps files small and avoids storing
personal payload data). Files rotate every 15 minutes so no single file is too big for scapy's `rdpcap`.

```powershell
# Session capture on the main LAN NIC (Ctrl+C to stop)
dumpcap -i "Ethernet 5" -s 256 `
  -b duration:900 -b files:200 `
  -w "E:\Projects Internet room\anamoly_detection\data\local_baseline\pcaps\baseline.pcapng"
```

Run several sessions at different times of day. Suggested schedule:

| Session | When | Activity |
|---|---|---|
| 1 | Work hours, 2 h | Normal work: browsing, IDE, git, SSH |
| 2 | ~30 min | Heavy use: streaming video + large download / LAN file copy |
| 3 | 1–2 h | Idle machine (background chatter only — this is what's currently false-positiving) |
| 4 | Different day, 1–2 h | Repeat of session 1 for day-to-day variety |

Optional second NIC (only if it carries real traffic):

```powershell
dumpcap -i "APN1" -s 256 -b duration:900 -b files:50 `
  -w "E:\Projects Internet room\anamoly_detection\data\local_baseline\pcaps\baseline_apn1.pcapng"
```

**Volume check** — aim for ≥ 50,000 flows total (a quick browse session generates thousands; the idle
session matters more than raw volume because it captures the multicast/broadcast patterns):

```powershell
Get-ChildItem "E:\Projects Internet room\anamoly_detection\data\local_baseline\pcaps" |
  Measure-Object -Property Length -Sum | ForEach-Object { "{0:N1} MB total" -f ($_.Sum / 1MB) }
```

---

## Phase 2 — Convert pcaps → flow-feature CSV

**Script to create:** `project/backend/pcap_to_flows.py`. It must reuse the existing pipeline so training
flows are shaped exactly like inference flows:

1. Read each `.pcapng` with `scapy.rdpcap`.
2. **Slice packets into fixed 30-second time windows before grouping** — this is critical. Live inference
   groups packets inside a sliding window (`packet_capture.py`), so a training flow must be "what a flow
   looks like within one window", not a 15-minute aggregate. Skipping this reintroduces train/serve skew
   (e.g. recurring DNS to the same resolver would merge into one long fake flow).
3. Per window: `flow_generator.group_packets_into_flows()` → `feature_extractor.extract_flow_features()`.
   The output columns already match the model's `FEATURE_NAMES` exactly (`flow_byts_s`, `flow_pkts_s`,
   `fwd_bytes`, `bwd_bytes`, `total_pkts`, `syn_flag`, `rst_flag`, `fin_flag`, `flow_duration_s`,
   `pkt_len_mean`) plus identifiers (`src_ip`, `dst_ip`, ports, `protocol`).
4. Append all windows from all files into one CSV.

```powershell
cd "E:\Projects Internet room\anamoly_detection\project\backend"
python pcap_to_flows.py `
  --pcap-dir "..\..\data\local_baseline\pcaps" `
  --window-sec 30 `
  --out "..\..\data\local_baseline\csv\benign_flows.csv"
```

---

## Phase 3 — Clean and audit the dataset

Even a "normal" capture can contain surprises (a background app misbehaving, a neighbor device scanning).
Audit before trusting it as ground-truth benign:

1. **Score the new CSV with the CURRENT models** via the offline pipeline (upload
   `benign_flows.csv` in the UI, or POST to `/api/upload` + `/api/start-offline`). Sort by ensemble score.
2. Manually inspect the top ~50 highest-scoring flows. Expected: multicast/QUIC/broadcast — keep them
   (they are exactly the local normal we want to learn). Remove only rows that are genuinely suspicious
   (unknown external IPs with scan-like patterns).
3. Basic hygiene + train/validation split (script or pandas one-liner):

```powershell
python -c @"
import pandas as pd
df = pd.read_csv(r'..\..\data\local_baseline\csv\benign_flows.csv')
df = df[df['total_pkts'] > 0].drop_duplicates()
val = df.sample(frac=0.2, random_state=42)
train = df.drop(val.index)
train.to_csv(r'..\..\data\local_baseline\csv\benign_train.csv', index=False)
val.to_csv(r'..\..\data\local_baseline\csv\benign_val.csv', index=False)
print(f'train={len(train)}  val={len(val)}')
"@
```

---

## Phase 4 — Retrain on the local baseline

**Script to create:** `project/backend/train_local_baseline.py` (adapted from `train_models.py`):

- **Scaler + Autoencoder:** fit on `benign_train.csv` only (columns already match `FEATURE_NAMES`;
  apply the same median-imputation + `log1p`-on-skewed-columns steps).
- **Isolation Forest:** fit on benign_train with a small contamination (~0.01), since the data is
  assumed clean — unlike `train_models.py` which uses a 50/50 attack mix.
- **Calibration anchors** (`lo`/`mid`/`hi` per head): `lo` = median benign score, `mid` = 99th percentile
  benign (→ score 0.5, ~1% FPR at default threshold). For `hi` (→ score 1.0), score the existing attack
  reference (`data\ctu13\CTU13_Attack_Traffic.csv` mapped through the same features) with the new models
  and take the median. Attack data is used **only** to pick this anchor — inference stays unsupervised.
- Save the same four artifacts (`scaler.pkl`, `isolation_forest.pkl`, `autoencoder.pkl`, `meta.pkl`).

Back up current models first, then train:

```powershell
Copy-Item "E:\Projects Internet room\anamoly_detection\project\models" `
  "E:\Projects Internet room\anamoly_detection\project\models_backup_cicddos" -Recurse
cd "E:\Projects Internet room\anamoly_detection\project\backend"
python train_local_baseline.py `
  --benign "..\..\data\local_baseline\csv\benign_train.csv" `
  --attack-ref "..\..\data\ctu13\CTU13_Attack_Traffic.csv"
```

Restart the backend afterwards so it loads the new pickles.

---

## Phase 5 — Validate (all three must pass)

| Check | How | Pass criterion |
|---|---|---|
| **False-positive rate** | Run `benign_val.csv` through the offline pipeline | < 2–5% flagged at threshold 0.5 |
| **Detection still works** | Run a CICDDoS2019 sample (or attack pcap) through offline | Attack flows still score high (compare to `docs/CICDDOS2019_RESULTS.md`) |
| **Live sanity** | Live capture on `Ethernet 5` (30 s window, threshold 0.5), browse normally 10 min | Detection rate ≈ 0–2%, no Critical alerts |

Optional live attack drill: from **another machine** on the LAN, run `nmap -sS 192.168.1.123` (nmap is not
installed on this machine) — the port-scan campaign correlation should fire within one window.

---

## Phase 6 — Rollback

If detection quality degrades:

```powershell
Remove-Item "E:\Projects Internet room\anamoly_detection\project\models" -Recurse -Force
Copy-Item "E:\Projects Internet room\anamoly_detection\project\models_backup_cicddos" `
  "E:\Projects Internet room\anamoly_detection\project\models" -Recurse
```

…and restart the backend.

---

## Settings to fix before starting live validation

Current live settings that inflate false positives (Settings page or `/api/settings`):

- `confidence_threshold`: currently **0.4** → set to **0.5** (flows at 0.40–0.48 are being flagged today)
- `context_window`: currently **13 s** → set to **30 s** (13 s truncates TCP handshakes → fake "SYN Flood" verdicts), and must match the `--window-sec` used in Phase 2

## Deliverables checklist

> Executed 2026-07-17 on capture batch 1 — results in `docs/LOCAL_BASELINE_RESULTS.md`.

- [ ] Phase 1 pcap sessions captured (≥ 4 h, ≥ 2 days, includes idle session) — **partial: ~58 min, 1 day (batch 1 in `data/baseline_train/wireshark_data/`)**
- [x] `project/backend/pcap_to_flows.py` written (30 s windowing, reuses flow_generator + feature_extractor)
- [x] `benign_train.csv` / `benign_val.csv` produced and audited (18,772 flows; nothing suspicious found)
- [x] `project/backend/train_local_baseline.py` written; old models backed up to `project/models_backup_cicddos/`
- [ ] All three Phase 5 validation checks pass — **FP rate 1.39% PASS; in-domain attack detection PASS (synthetic; CICDDoS cross-domain is informational); live sanity check pending**
