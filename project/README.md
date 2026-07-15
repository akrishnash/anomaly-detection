# Aegis-IDS: Real-Time Cybersecurity Intrusion Detection System

Aegis-IDS is a professional, modular, production-ready Cybersecurity Intrusion Detection System (IDS) interface and API. It uses a fully **unsupervised two-stage pipeline**: Stage 1 flags anomalous flows with an **Isolation Forest + Autoencoder ensemble** (no labels needed at inference), and Stage 2 classifies flagged flows into **DDoS attack subtypes** (SYN Flood, UDP Flood, ICMP Flood, HTTP Flood, Amplification, Slowloris, Port Scan, ...) with a transparent rule engine plus per-target campaign aggregation. Explainability is provided by **TreeSHAP** over the Isolation Forest, and visual dashboards are built using React, Tailwind CSS, Recharts, and Framer Motion.

---

## Folder Structure

```
project/
├── backend/
│   ├── packet_capture.py       # Live Sniffer capture manager (options 1-5)
│   ├── flow_generator.py       # Groups raw scapy packets into bidirectional flows
│   ├── feature_extractor.py    # Computes 10 CICFlowMeter-like flow features
│   ├── preprocessing.py        # Cleans, imputes, and scales features (+ Autoencoder)
│   ├── isolation_forest.py     # Generates negated IF anomaly scores
│   ├── anomaly_detector.py     # Stage 1: calibrated IF + Autoencoder ensemble score
│   ├── ddos_classifier.py      # Stage 2: DDoS subtype rule engine + campaign aggregation + CLI
│   ├── shap_explainer.py       # Computes TreeSHAP feature contributions
│   ├── database.py             # SQLite configuration and history persistence
│   ├── api.py                  # FastAPI route controllers
│   └── main.py                 # FastAPI app entry point & startup model training
├── models/
│   ├── scaler.pkl              # Base StandardScaler (10 features)
│   ├── isolation_forest.pkl    # Trained unsupervised Isolation Forest
│   ├── autoencoder.pkl         # Autoencoder trained on normal traffic baseline
│   └── meta.pkl                # Metadata (skewed columns, medians, ensemble calibration)
├── frontend/
│   ├── src/
│   │   ├── components/         # Navbar, ConsoleLogs, ShapDetails
│   │   ├── pages/              # Dashboard, OfflineDetection, OnlineDetection, History, Settings
│   │   ├── services/           # api.js connection service
│   │   ├── App.jsx             # Main router and state polling manager
│   │   ├── index.css           # Global neon/cyber CSS stylesheet
│   │   └── main.jsx
│   ├── tailwind.config.js      # Cybersecurity theme config
│   ├── postcss.config.js
│   ├── vite.config.js          # Reverse proxy mapping configuration
│   └── package.json
├── datasets/                   # Temporary directory for uploaded offline logs
├── reports/                    # Temporary directory for generated incident PDFs
└── logs/
    └── database.sqlite         # SQLite database file
```

---

## Core Detection Pipeline

```
Incoming Traffic (NIC / Replay / Stream)
   │
   ▼
[Packet Capture] ──► Retains traffic in a 30-second sliding context window
   │
   ▼
[Flow Generation] ──► Groups packets into bidirectional 5-tuple flows
   │
   ▼
[Feature Extraction] ──► Extracts 10 core metrics (Flow Bytes/s, SYN flags, etc.)
   │
   ▼
[Preprocessing] ──► Cleans, imputes medians, log-transforms, and scales
   │
   ▼
[Stage 1: Unsupervised Ensemble] ──► Isolation Forest + Autoencoder scores fused
   │                                  into a calibrated anomaly probability [0, 1]
   ▼
[Stage 2: DDoS Rule Engine] ──► Classifies anomalies into attack subtypes (SYN/UDP/
   │                            ICMP/HTTP Flood, Amplification, Slowloris, Scan, ...)
   ▼
[Campaign Aggregation] ──► Groups anomalies per target; escalates many-source
   │                       attacks to "DDoS: <subtype> (distributed)"
   ▼
[SHAP Explainability] ──► Generates feature contributions & natural language reasonings
   │
   ▼
[Dashboard Update] ──► Live updates indicators, logs, timelines, and Recharts grids
```

---

## Installation & Setup

### Requirements
- Python 3.10+
- Node.js 18+
- Administrator privileges (required if performing live hardware packet capturing via Scapy on Windows/Linux; fallback simulator is automatically loaded if permissions are missing)

### 1. Backend Service
1. Navigate to the workspace root:
   ```bash
   pip install -r requirements.txt
   pip install fpdf2
   ```
2. Start the FastAPI server:
   ```bash
   python project/backend/main.py
   ```
   *Note: On startup, if model pickle files are missing, the server will automatically train models on the CTU-13 dataset splits located in `sample_logs/`.*

### 2. Frontend Client
1. Navigate to the frontend directory:
   ```bash
   cd project/frontend
   npm install
   ```
2. Start the Vite React development server:
   ```bash
   npm run dev
   ```
3. Open your browser and navigate to `http://localhost:3000`. Requests to `/api` are automatically proxied to the FastAPI server at `http://127.0.0.1:8000`.

### 3. Standalone DDoS Classifier CLI

Classify a PCAP or an unlabeled flow CSV directly from the command line (models must be trained first):

```bash
python project/backend/ddos_classifier.py --input capture.pcap
python project/backend/ddos_classifier.py --input flows.csv --threshold 0.5 --output report.json
```

Prints total/anomalous flow counts, an attack-subtype breakdown, and detected campaigns
(per-target aggregation with distributed-attack escalation); `--output` writes the full
per-flow JSON report.

---

## REST API Endpoints

- **Settings**:
  - `GET /api/settings`: Fetch system settings.
  - `POST /api/settings`: Save updated settings.
- **Offline Detection**:
  - `POST /api/upload`: Upload CSV/Excel/PCAP datasets.
  - `POST /api/start-offline`: Execute predictions on uploaded file.
- **Online Sniffer**:
  - `POST /api/start-online`: Bind to port/adapter and start sniffer thread.
  - `POST /api/stop-online`: Terminate the active sniffer thread.
  - `GET /api/online/status`: Retrieve capture manager statuses.
  - `POST /api/online/inject`: External packet queue injection endpoint (Option 5).
- **Diagnostics & Feeds**:
  - `GET /api/prediction`: Retrieve alerts found in the active sliding window.
  - `GET /api/dashboard`: Fetch timeline arrays and protocol breakdowns.
  - `GET /api/metrics`: Retrieve baseline model health scores.
  - `GET /api/shap/{id}`: Retrieve local TreeSHAP explanations.
  - `GET /api/logs`: Fetch recent system audit logs.
- **Data Export**:
  - `GET /api/export-csv`: Export all logged predictions to a CSV file.
  - `GET /api/download-pdf`: Compile and download the top 50 critical incidents as a PDF report.
