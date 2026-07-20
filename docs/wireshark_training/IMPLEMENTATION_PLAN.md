# Implementation Plan: Direct Wireshark (.pcapng) Baseline Model Training

Train the backend anomaly detection models (`IsolationForest` and `Autoencoder`) directly from locally captured Wireshark network traffic (`wireshark_dataset/training_wireshark/*.pcapng`), maintaining 100% compatibility with live backend inference.

## User Review Required

- Existing model files in `project/models/` are backed up to `project/models_backup_<timestamp>/` before saving newly trained models.
- Models are trained **strictly on benign local Wireshark traffic**. No synthetic or external benign traffic (CTU-13 / CICDDoS2019) is used for model training.
- `CTU13_Attack_Traffic.csv` is used **solely for score calibration** (setting the `hi` anchor for mapping raw anomaly scores to $[0, 1]$ probabilities) and is **not** included in model training.

## Proposed Changes

### Backend Training Pipeline

#### [NEW] [train_from_wireshark.py](file:///d:/Projects/anomaly-detection/project/backend/train_from_wireshark.py)
Create a clean, dedicated pipeline script that automates:
1. **PCAP Ingestion & Windowing**: Stream `.pcapng` files from `wireshark_dataset/training_wireshark/` using Scapy `PcapReader` and slice packets into fixed 30-second time windows (`win_id = int(pkt.time // 30)`).
2. **Flow & Feature Reuse**: Reuses [`flow_generator.group_packets_into_flows()`](file:///d:/Projects/anomaly-detection/project/backend/flow_generator.py#L3) and [`feature_extractor.extract_flow_features()`](file:///d:/Projects/anomaly-detection/project/backend/feature_extractor.py#L4) to convert windowed packets into flow features.
3. **Preprocessing Alignment**:
   - Maps columns via canonical schema (`build_alias_dictionary`, `map_to_canonical_schema`).
   - Imputes missing values with medians.
   - Applies `log1p` transformation to skewed columns.
   - Fits `StandardScaler`.
4. **Model Training**:
   - Fits `IsolationForest(contamination=0.01, random_state=42)` on local benign features.
   - Fits `AutoencoderAnomalyDetector(input_dim=10, latent_dim=4, random_state=42)` on local benign features.
5. **Score Anchor Calibration**:
   - Scores `CTU13_Attack_Traffic.csv` through the trained pipeline (reference only).
   - Computes `lo` (median benign score), `mid` (99th percentile benign score), and `hi` (median attack score) for both IF and AE.
6. **Artifact Persistence & Backup**:
   - Backs up existing `project/models/` contents to `project/models_backup_<timestamp>/`.
   - Saves `scaler.pkl`, `isolation_forest.pkl`, `autoencoder.pkl`, and `meta.pkl` to `project/models/`.

---

## Verification Plan

### Automated Execution & Metrics Verification
- Run `train_from_wireshark.py` via background task.
- Verify model artifacts created in `project/models/`: `scaler.pkl`, `isolation_forest.pkl`, `autoencoder.pkl`, `meta.pkl`.
- Verify `meta.pkl` contains correct `medians`, `skewed_cols`, `features` (10 core `FEATURE_NAMES`), and `calibration` anchors.

### Backend Compatibility Check
- Run a verification script calling `preprocessing.load_preprocessor_assets()` and `anomaly_detector.score_flows()` on sample flow inputs to verify end-to-end compatibility with backend live inference.
