# Architecture & Pipeline Analysis Report

## 1. Overview & Core Features
The anomaly detection backend implements a two-stage unsupervised network traffic anomaly detection system:
- **Stage 1**: Unsupervised ensemble combining **Isolation Forest** and an **Autoencoder** into a calibrated probability in $[0, 1]$.
- **Stage 2**: Rule-based DDoS signature classification and SHAP feature attribution for flagged flows.

### Feature Definitions
The 10 core features are defined in `train_models.py`, `train_cicddos.py`, `train_local_baseline.py`, and stored in `meta.pkl`:
1. `flow_byts_s`: Byte rate ($\text{Total Bytes} / \text{Duration}$)
2. `flow_pkts_s`: Packet rate ($\text{Total Packets} / \text{Duration}$)
3. `fwd_bytes`: Forward payload length in bytes
4. `bwd_bytes`: Backward payload length in bytes
5. `total_pkts`: Total packet count
6. `syn_flag`: TCP SYN flag count
7. `rst_flag`: TCP RST flag count
8. `fin_flag`: TCP FIN flag count
9. `flow_duration_s`: Flow duration in seconds
10. `pkt_len_mean`: Average packet size in bytes

---

## 2. Live Inference Mechanism
1. **Packet Capture** (`packet_capture.py`): Scapy sniffer / PCAP streamer / simulator appends incoming packets into a thread-safe `deque`.
2. **Windowing** (`packet_capture.py`): Every 30 seconds (`sliding_window_sec`), scheduler thread runs `perform_inference()`, evicting packets older than 30 seconds.
3. **Flow Generation** (`flow_generator.py`): Groups active packets into bidirectional 5-tuple flows: `(IP_min, IP_max, Port_min, Port_max, Protocol)`.
4. **Feature Extraction** (`feature_extractor.py`): Calculates duration, forward/backward bytes and packets, SYN/RST/FIN/ACK flag counts, byte/packet rates, and mean packet length.
5. **Preprocessing & Scaling** (`preprocessing.py`): Maps columns to canonical schema, imputes missing values with stored medians from `meta.pkl`, applies `log1p` transform on skewed columns, and normalizes using `StandardScaler` (`scaler.pkl`).
6. **Isolation Forest** (`isolation_forest.py`): Computes raw anomaly scores as $-1 \times \text{score\_samples}(X_{\text{scaled}})$.
7. **Autoencoder** (`preprocessing.py`): Computes reconstruction MSE via `MLPRegressor` ($||X - \hat{X}||^2$).
8. **Ensemble Scoring** (`anomaly_detector.py`):
   - Piecewise-linear interpolation (`np.interp`) maps raw scores to $[0, 1]$ anchored at `lo` (50th percentile normal $\to 0.0$), `mid` (99th percentile normal $\to 0.5$), `hi` (median attack $\to 1.0$).
   - OR-union MAX fusion: $\text{Prob} = \max(\text{Prob}_{\text{IF}}, \text{Prob}_{\text{AE}})$.
   - Flows with $\text{Prob} \ge 0.5$ are flagged as anomalies.

---

## 3. Differences: Offline Training vs. Live Inference
- **Data Source**: Offline scripts (`train_models.py` / `train_cicddos.py`) parse pre-aggregated CSV/Parquet summaries, whereas live inference processes sliding 30s packet windows.
- **Flow Duration**: Offline CSV flows span full connection lifetimes (minutes to hours). Live inference flows are bounded by 30s window boundaries.
- **Label Usage**: Ground-truth labels in offline datasets are used to split normal vs attack flows for Autoencoder fitting and calibration anchor selection. Live inference is 100% unsupervised.

---

## 4. Train/Serve Skew Vulnerabilities
1. **Flow Bounding Skew**: Training on full-session flows creates mismatch with live 30s windowed flows.
2. **Flow Timeout Differences**: Third-party extractors (CICFlowMeter) terminate flows on idle timeouts or FIN/RST flags, unlike 30s window grouping.
3. **Fallback Asymmetry**: Missing `fwd_bytes` or `bwd_bytes` fall back to `bytes / 2.0` in live preprocessing.
4. **Skew Transform Drift**: `log1p` columns determined during training might not match live skew distributions.
5. **Calibration Shift**: Out-of-domain normal traffic can cause raw score drift, leading to false alerts.
