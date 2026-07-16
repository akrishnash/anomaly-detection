#!/usr/bin/env python3
"""
Cybersecurity IDS Backend Server
===============================
FastAPI server managing offline upload triage and online real-time sniffing.
"""

import os
import sys
import time
import uuid
import threading
import shutil
from typing import Optional
import numpy as np
import pandas as pd
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse as FastAPIJSONResponse
import math

class SafeJSONResponse(FastAPIJSONResponse):
    def render(self, content: any) -> bytes:
        def sanitize_json_data(obj):
            if isinstance(obj, dict):
                return {k: sanitize_json_data(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [sanitize_json_data(v) for v in obj]
            elif isinstance(obj, tuple):
                return tuple(sanitize_json_data(v) for v in obj)
            elif isinstance(obj, float):
                if math.isnan(obj) or math.isinf(obj):
                    return 0.0
                return obj
            elif isinstance(obj, (np.floating, np.integer)):
                val = obj.item()
                if isinstance(val, float) and (math.isnan(val) or math.isinf(val)):
                    return 0.0
                return val
            elif pd.isna(obj):
                return None
            return obj
        
        sanitized = sanitize_json_data(content)
        return super().render(sanitized)

JSONResponse = SafeJSONResponse

from fastapi.middleware.cors import CORSMiddleware
import uvicorn

# Import our ML pipeline
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from ml_pipeline import IDSPipeline, extract_features_from_packets

app = FastAPI(title="Cybersecurity Intrusion Detection System (IDS) API")

# Enable CORS for local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global variables
pipeline = IDSPipeline()
capture_manager = None
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, "..", "temp_uploads"))
STATIC_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, "static"))
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(STATIC_DIR, exist_ok=True)

def resolve_interface_name(target_iface: Optional[str]) -> Optional[str]:
    if not target_iface:
        return None
    try:
        from scapy.all import IFACES
        # 1. Exact match by key
        if target_iface in IFACES:
            return target_iface
        
        # 2. Case-insensitive / normalized name match or description match
        clean_target = target_iface.lower().replace("-", "").replace(" ", "").replace("_", "")
        # First try exact match after cleaning names
        for key, iface in IFACES.items():
            name_clean = iface.name.lower().replace("-", "").replace(" ", "").replace("_", "")
            desc_clean = (iface.description or "").lower().replace("-", "").replace(" ", "").replace("_", "")
            if clean_target == name_clean or clean_target == desc_clean:
                return key
                
        # Then try substring match
        for key, iface in IFACES.items():
            name_clean = iface.name.lower().replace("-", "").replace(" ", "").replace("_", "")
            desc_clean = (iface.description or "").lower().replace("-", "").replace(" ", "").replace("_", "")
            if clean_target in name_clean or clean_target in desc_clean:
                return key
    except Exception:
        pass
    return target_iface

# ── Online Capture Manager Daemon ─────────────────────────────────────────────
class OnlineCaptureManager:
    def __init__(self, pipeline_obj):
        self.pipeline = pipeline_obj
        self.is_running = False
        self.packets = []
        self.lock = threading.Lock()
        self.thread = None
        self.timer_thread = None
        
        self.interface = None
        self.ip_filter = None
        self.port_filter = None
        self.simulated = False
        self.sliding_window_sec = 30
        
        self.latest_snapshot = {
            "timestamp": time.time(),
            "total_packets": 0,
            "total_flows": 0,
            "threat_ratio": 0.0,
            "anomalies_count": 0,
            "alerts": [],
            "chart_data": {
                "normal_count": 0,
                "anomaly_count": 0
            }
        }
        self.history = []

    def start(self, interface: Optional[str] = None, ip_filter: Optional[str] = None, port_filter: Optional[str] = None, simulated: bool = False, sliding_window_sec: int = 30):
        if self.is_running:
            return
        self.is_running = True
        self.interface = interface
        self.ip_filter = ip_filter
        self.port_filter = port_filter
        self.simulated = simulated
        self.sliding_window_sec = sliding_window_sec
        self.packets = []
        self.history = []
        
        # Start packet sniffer loop
        self.thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self.thread.start()
        
        # Start the 30-second interval inference scheduler
        self.timer_thread = threading.Thread(target=self._scheduler_loop, daemon=True)
        self.timer_thread.start()

    def stop(self):
        self.is_running = False
        if self.thread:
            self.thread.join(timeout=1.0)
        if self.timer_thread:
            self.timer_thread.join(timeout=1.0)

    def _sniff_loop(self):
        print(f"[*] Capture: Starting sniffer on iface={self.interface}, filter={self.ip_filter}:{self.port_filter}, sim={self.simulated}")
        
        # Parse filter
        bpf_filter = ""
        if self.ip_filter:
            bpf_filter += f"host {self.ip_filter}"
        if self.port_filter:
            if bpf_filter:
                bpf_filter += " and "
            bpf_filter += f"port {self.port_filter}"

        if self.simulated:
            while self.is_running:
                self._generate_simulated_packets()
                time.sleep(1.0)
        else:
            try:
                from scapy.all import sniff
                
                target_iface = self.interface
                if target_iface:
                    resolved = resolve_interface_name(target_iface)
                    if resolved:
                        target_iface = resolved

                def pkt_callback(pkt):
                    if not self.is_running:
                        return
                    with self.lock:
                        self.packets.append(pkt)
                        
                while self.is_running:
                    sniff(
                        iface=target_iface,
                        filter=bpf_filter if bpf_filter else None,
                        prn=pkt_callback,
                        timeout=2.0,
                        store=False
                    )
            except Exception as e:
                err_msg = str(e)
                import sys
                from scapy.config import conf
                if "winpcap" in err_msg.lower() or "libpcap" in err_msg.lower() or "npcap" in err_msg.lower() or (sys.platform == "win32" and conf.L2socket is None):
                    print("[-] Scapy sniffer failed: Npcap/WinPcap is not installed or running. Please install Npcap (https://npcap.com/) and run the application as Administrator for live packet capture on Windows. Falling back to simulation.")
                else:
                    print(f"[-] Scapy sniffer failed: {e}. Falling back to simulation.")
                self.simulated = True
                while self.is_running:
                    self._generate_simulated_packets()
                    time.sleep(1.0)

    def _generate_simulated_packets(self):
        # Generates realistic Scapy packet representations
        from scapy.layers.inet import IP, TCP, UDP
        from scapy.all import Raw
        import random
        
        curr_time = time.time()
        num_pkts = random.randint(15, 60)
        
        # Determine if we generate an attack pattern
        is_attack = random.random() < 0.18
        
        pkts_to_add = []
        if is_attack:
            attack_type = random.choice(["scan", "ddos", "exfil"])
            if attack_type == "scan":
                src_ip = f"192.168.1.{random.randint(100, 200)}"
                dst_ip = "192.168.1.1"
                for _ in range(num_pkts):
                    sport = random.randint(1024, 65535)
                    dport = random.randint(1, 1024)
                    p = IP(src=src_ip, dst=dst_ip)/TCP(sport=sport, dport=dport, flags="S")
                    p.time = curr_time + random.uniform(-0.5, 0.5)
                    pkts_to_add.append(p)
            elif attack_type == "ddos":
                dst_ip = "192.168.1.10"
                dport = 80
                for _ in range(num_pkts):
                    src_ip = f"200.12.5.{random.randint(1, 254)}"
                    sport = random.randint(1024, 65535)
                    p = IP(src=src_ip, dst=dst_ip)/TCP(sport=sport, dport=dport, flags="A")
                    p.time = curr_time + random.uniform(-0.5, 0.5)
                    pkts_to_add.append(p)
            elif attack_type == "exfil":
                src_ip = "192.168.1.45"
                dst_ip = "45.10.12.8"
                sport = random.randint(1024, 65535)
                dport = 443
                for _ in range(num_pkts // 2):
                    p = IP(src=src_ip, dst=dst_ip)/TCP(sport=sport, dport=dport, flags="PA")/Raw(load=b"X" * random.randint(1000, 1450))
                    p.time = curr_time + random.uniform(-0.5, 0.5)
                    pkts_to_add.append(p)
        else:
            # Benign
            for _ in range(num_pkts):
                src_ip = f"192.168.1.{random.randint(10, 99)}"
                dst_ip = f"192.168.1.{random.randint(1, 9)}"
                sport = random.randint(1024, 65535)
                dport = random.choice([80, 443, 53, 22])
                
                if dport == 53:
                    p = IP(src=src_ip, dst=dst_ip)/UDP(sport=sport, dport=dport)
                else:
                    flags = random.choice(["A", "PA"])
                    p = IP(src=src_ip, dst=dst_ip)/TCP(sport=sport, dport=dport, flags=flags)
                    if random.random() < 0.4:
                        p = p/Raw(load=b"X" * random.randint(40, 600))
                p.time = curr_time + random.uniform(-0.5, 0.5)
                pkts_to_add.append(p)
                
        with self.lock:
            self.packets.extend(pkts_to_add)

    def _scheduler_loop(self):
        # Runs inference dynamically
        print(f"[*] Scheduler: Sliding window active ({self.sliding_window_sec}s intervals).")
        while self.is_running:
            time.sleep(self.sliding_window_sec)
            if not self.is_running:
                break
            try:
                self.perform_inference()
            except Exception as e:
                print(f"[-] Inference error: {e}")

    def perform_inference(self):
        curr_time = time.time()
        window_start = curr_time - self.sliding_window_sec
        
        with self.lock:
            # Drop packets older than the 30-second sliding context window
            self.packets = [p for p in self.packets if float(p.time) >= window_start]
            active_packets = list(self.packets)
            
        if len(active_packets) == 0:
            self.latest_snapshot = {
                "timestamp": curr_time,
                "total_packets": 0,
                "total_flows": 0,
                "threat_ratio": 0.0,
                "anomalies_count": 0,
                "alerts": [],
                "chart_data": {
                    "normal_count": 0,
                    "anomaly_count": 0
                }
            }
            return
            
        # Extract features
        df_flows = extract_features_from_packets(active_packets)
        if len(df_flows) == 0:
            self.latest_snapshot = {
                "timestamp": curr_time,
                "total_packets": len(active_packets),
                "total_flows": 0,
                "threat_ratio": 0.0,
                "anomalies_count": 0,
                "alerts": [],
                "chart_data": {
                    "normal_count": 0,
                    "anomaly_count": 0
                }
            }
            return
            
        # Run inference
        results, X_aug_scaled, if_scores = self.pipeline.predict_flows(df_flows)
        
        total_flows = len(results)
        anomaly_count = sum(1 for r in results if r["prediction"] == 1)
        threat_ratio = (anomaly_count / total_flows) * 100 if total_flows > 0 else 0.0
        
        alerts = []
        benign_flows = []
        for i, res in enumerate(results):
            # Compute TreeSHAP local explanation for both normal and anomalies
            shap_contrib = self.pipeline.get_shap_explanation(X_aug_scaled[i])
            flow_info = df_flows.iloc[i].to_dict()
            
            is_anomaly = res["prediction"] == 1
            flow_item = {
                "src_ip": flow_info["src_ip"],
                "dst_ip": flow_info["dst_ip"],
                "dst_port": int(flow_info["dst_port"]),
                "threat_type": "Normal Traffic" if not is_anomaly else res["threat_type"],
                "severity": "Low" if not is_anomaly else res["severity"],
                # Probability represents confidence. For normal traffic, show (1 - anomaly_prob). For anomalies, show anomaly_prob.
                "probability": round((1.0 - res["probability"]) * 100, 2) if not is_anomaly else round(res["probability"] * 100, 2),
                "prediction": res["prediction"],
                "if_score": round(res["if_score"], 4),
                "flow_details": {
                    k: (0.0 if (pd.isna(v) or np.isinf(v)) else (round(float(v), 4) if isinstance(v, (float, np.floating)) else int(v)))
                    for k, v in flow_info.items() if k not in ["src_ip", "dst_ip", "protocol"]
                },
                "shap_explanation": shap_contrib
            }
            if is_anomaly:
                alerts.append(flow_item)
            else:
                benign_flows.append(flow_item)
                
        # Sort anomalies by probability desc, benign by probability desc
        alerts = sorted(alerts, key=lambda x: x["probability"], reverse=True)
        benign_flows = sorted(benign_flows, key=lambda x: x["probability"], reverse=True)
        
        self.latest_snapshot = {
            "timestamp": curr_time,
            "total_packets": len(active_packets),
            "total_flows": total_flows,
            "threat_ratio": round(threat_ratio, 2),
            "anomalies_count": anomaly_count,
            "benign_count": total_flows - anomaly_count,
            "alerts": alerts[:25],
            "benign_flows": benign_flows[:25],
            "chart_data": {
                "normal_count": total_flows - anomaly_count,
                "anomaly_count": anomaly_count
            }
        }
        self.history.append(self.latest_snapshot)
        if len(self.history) > 30:
            self.history.pop(0)

# ── API Endpoints ─────────────────────────────────────────────────────────────

@app.on_event("startup")
def startup_event():
    global capture_manager
    # Train the base ML models using CTU-13 dataset
    pipeline.train_baseline()
    capture_manager = OnlineCaptureManager(pipeline)
    print("[+] Server startup: IDS Pipeline loaded.")

@app.get("/", response_class=HTMLResponse)
async def get_dashboard():
    dashboard_path = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(dashboard_path):
        with open(dashboard_path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse(content=f"<h2>Error: Dashboard file not found at {dashboard_path}</h2>")

# ── Mode 1: Offline Upload & Detection ────────────────────────────────────────

@app.post("/api/offline/upload")
async def upload_dataset(file: UploadFile = File(...)):
    filename = file.filename
    file_id = str(uuid.uuid4())
    ext = os.path.splitext(filename)[1].lower()
    
    if ext not in [".csv", ".xlsx", ".xls", ".pcap", ".pcapng"]:
        raise HTTPException(status_code=400, detail="Unsupported file format. Use CSV, Excel, PCAP, or PCAPNG.")
        
    temp_path = os.path.join(UPLOAD_DIR, f"{file_id}{ext}")
    
    with open(temp_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
        
    file_size_mb = os.path.getsize(temp_path) / (1024 * 1024)
    
    # Read info and preview
    num_rows = 0
    num_cols = 0
    preview_data = []
    
    try:
        if ext == ".csv":
            df = pd.read_csv(temp_path, nrows=50)
            # Count actual lines in file without loading fully
            num_rows = sum(1 for _ in open(temp_path, encoding="utf-8", errors="ignore")) - 1
            num_cols = len(df.columns)
            preview_data = df.head(10).fillna("").to_dict(orient="records")
        elif ext in [".xlsx", ".xls"]:
            df = pd.read_excel(temp_path, nrows=50)
            num_rows = len(pd.read_excel(temp_path))
            num_cols = len(df.columns)
            preview_data = df.head(10).fillna("").to_dict(orient="records")
        elif ext in [".pcap", ".pcapng"]:
            # For PCAP/PCAPNG files, load flows or summary using Scapy
            from scapy.all import rdpcap
            pkts = rdpcap(temp_path)
            num_rows = len(pkts)
            num_cols = 0  # no columns in raw PCAP packets
            preview_data = [{"packet_no": idx, "summary": str(pkt)} for idx, pkt in enumerate(pkts[:10])]
    except Exception as e:
        os.remove(temp_path)
        raise HTTPException(status_code=500, detail=f"Failed to read file structure: {str(e)}")
        
    return JSONResponse(content={
        "file_id": file_id,
        "filename": filename,
        "size_mb": round(file_size_mb, 2),
        "num_rows": num_rows,
        "num_cols": num_cols,
        "preview": preview_data,
        "extension": ext
    })

@app.post("/api/offline/analyze")
async def analyze_dataset(file_id: str = Form(...), extension: str = Form(...)):
    temp_path = os.path.join(UPLOAD_DIR, f"{file_id}{extension}")
    if not os.path.exists(temp_path):
        raise HTTPException(status_code=404, detail="Uploaded file session not found.")
        
    try:
        # Load dataset
        if extension == ".csv":
            df_full = pd.read_csv(temp_path)
        elif extension in [".xlsx", ".xls"]:
            df_full = pd.read_excel(temp_path)
        elif extension in [".pcap", ".pcapng"]:
            from scapy.all import rdpcap
            pkts = rdpcap(temp_path)
            df_full = extract_features_from_packets(pkts)
            
        # Clean up columns to map them to the 10 core features
        # If user uploaded raw CTU-13 data, map columns
        df_feats = pd.DataFrame()
        
        # Check if columns are already featurized or require mapping
        mapping = {
            "flow_byts_s": ["flow_byts_s", "Flow Byts/s"],
            "flow_pkts_s": ["flow_pkts_s", "Flow Pkts/s"],
            "fwd_bytes": ["fwd_bytes", "TotLen Fwd Pkts"],
            "bwd_bytes": ["bwd_bytes", "TotLen Bwd Pkts"],
            "total_pkts": ["total_pkts"],
            "syn_flag": ["syn_flag", "SYN Flag Cnt"],
            "rst_flag": ["rst_flag", "RST Flag Cnt"],
            "fin_flag": ["fin_flag", "FIN Flag Cnt"],
            "flow_duration_s": ["flow_duration_s", "Flow Duration"],
            "pkt_len_mean": ["pkt_len_mean", "Pkt Len Mean"]
        }
        
        for feat_name, candidates in mapping.items():
            found = False
            for col in df_full.columns:
                if col in candidates:
                    df_feats[feat_name] = pd.to_numeric(df_full[col], errors="coerce").fillna(0)
                    if col == "Flow Duration":
                        df_feats[feat_name] /= 1e6
                    found = True
                    break
            if not found:
                # If not found, check sum combinations
                if feat_name == "total_pkts":
                    fwd_col = next((c for c in df_full.columns if c in ["Tot Fwd Pkts", "total_fwd_pkts"]), None)
                    bwd_col = next((c for c in df_full.columns if c in ["Tot Bwd Pkts", "total_bwd_pkts"]), None)
                    if fwd_col and bwd_col:
                        df_feats[feat_name] = pd.to_numeric(df_full[fwd_col], errors="coerce").fillna(0) + pd.to_numeric(df_full[bwd_col], errors="coerce").fillna(0)
                        found = True
                if not found:
                    df_feats[feat_name] = 0.0 # fallback
                    
        # Ground truth check (if available)
        label_col = next((c for c in df_full.columns if c.lower() in ["label", "true_label", "class"]), None)
        y_true = None
        if label_col:
            y_true = df_full[label_col].apply(lambda x: 1 if str(x).strip().lower() in ["1", "attack", "anomaly", "malicious"] else 0).values
            
        # Run inference
        results, X_aug_scaled, if_scores = pipeline.predict_flows(df_feats)
        
        total_flows = len(results)
        anomaly_count = sum(1 for r in results if r["prediction"] == 1)
        threat_ratio = (anomaly_count / total_flows) * 100 if total_flows > 0 else 0.0
        
        # Calculate standard metrics if ground truth is available
        classification_report = {}
        if y_true is not None:
            y_pred = [r["prediction"] for r in results]
            from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
            classification_report = {
                "accuracy": round(accuracy_score(y_true, y_pred) * 100, 2),
                "precision": round(precision_score(y_true, y_pred, zero_division=0) * 100, 2),
                "recall": round(recall_score(y_true, y_pred, zero_division=0) * 100, 2),
                "f1_score": round(f1_score(y_true, y_pred, zero_division=0) * 100, 2)
            }
            
        # Extract anomalies list and benign list with SHAP explanations
        anomalies_list = []
        benign_list = []
        protocol_counts = {}
        attack_counts = {}

        for i, res in enumerate(results):
            shap_contrib = pipeline.get_shap_explanation(X_aug_scaled[i])
            row_raw = df_feats.iloc[i].to_dict()
            
            # Try to get IPs from original data if present, otherwise placeholders
            src_ip = df_full.iloc[i].get("src_ip", df_full.iloc[i].get("Source IP", "192.168.1.X"))
            dst_ip = df_full.iloc[i].get("dst_ip", df_full.iloc[i].get("Destination IP", "10.0.0.X"))
            dst_port = df_full.iloc[i].get("dst_port", df_full.iloc[i].get("Destination Port", 0))
            protocol = str(df_full.iloc[i].get("protocol", df_full.iloc[i].get("Protocol", "TCP")))
            
            # Process protocol share
            p_str = protocol.upper()
            if p_str in ["6", "6.0"]:
                p_str = "TCP"
            elif p_str in ["17", "17.0"]:
                p_str = "UDP"
            elif p_str in ["1", "1.0"]:
                p_str = "ICMP"
            protocol_counts[p_str] = protocol_counts.get(p_str, 0) + 1
            
            is_anomaly = res["prediction"] == 1
            if is_anomaly:
                a_type = res.get("threat_type", "Unknown")
                attack_counts[a_type] = attack_counts.get(a_type, 0) + 1

            flow_item = {
                "src_ip": str(src_ip),
                "dst_ip": str(dst_ip),
                "dst_port": int(dst_port) if pd.notna(dst_port) else 0,
                "protocol": p_str,
                "threat_type": "Normal Traffic" if not is_anomaly else res["threat_type"],
                "severity": "Low" if not is_anomaly else res["severity"],
                "probability": round((1.0 - res["probability"]) * 100, 2) if not is_anomaly else round(res["probability"] * 100, 2),
                "prediction": res["prediction"],
                "if_score": round(res["if_score"], 4),
                "flow_details": {k: (0.0 if (pd.isna(v) or np.isinf(v)) else (round(float(v), 4) if isinstance(v, (float, np.floating)) else int(v))) for k, v in row_raw.items()},
                "shap_explanation": shap_contrib
            }
            if is_anomaly:
                anomalies_list.append(flow_item)
            else:
                benign_list.append(flow_item)
                
        # Sort and limit preview size to avoid large payloads
        anomalies_list = sorted(anomalies_list, key=lambda x: x["probability"], reverse=True)[:25]
        benign_list = sorted(benign_list, key=lambda x: x["probability"], reverse=True)[:25]
        
        # Generate 12-point timeline for the chart
        num_timeline_points = 12
        bin_size = max(1, total_flows // num_timeline_points)
        timeline_data = []
        for b in range(num_timeline_points):
            start_idx = b * bin_size
            end_idx = min(total_flows, (b + 1) * bin_size)
            if start_idx >= total_flows:
                break
            
            bin_results = results[start_idx:end_idx]
            bin_attacks = sum(1 for r in bin_results if r["prediction"] == 1)
            bin_total = end_idx - start_idx
            bin_normal = bin_total - bin_attacks
            bin_ratio = round((bin_attacks / bin_total) * 100, 2) if bin_total > 0 else 0.0
            
            timeline_data.append({
                "time": f"Bin {b+1}",
                "normal": bin_normal,
                "attacks": bin_attacks,
                "detection_rate": bin_ratio
            })

        # Cleanup temporary uploaded file
        os.remove(temp_path)
        
        return JSONResponse(content={
            "status": "success",
            "total_flows": total_flows,
            "anomalies_count": anomaly_count,
            "benign_count": total_flows - anomaly_count,
            "threat_ratio": round(threat_ratio, 2),
            "classification_report": classification_report,
            "anomalies": anomalies_list,
            "benign": benign_list,
            "protocols": [{"name": k, "value": v} for k, v in protocol_counts.items()],
            "attacks": [{"name": k, "value": v} for k, v in attack_counts.items()],
            "timeline": timeline_data
        })
    except Exception as e:
        import traceback
        traceback.print_exc()
        if os.path.exists(temp_path):
            os.remove(temp_path)
        raise HTTPException(status_code=500, detail=f"Inference process failed: {str(e)}")

# ── Mode 2: Online Sniffing & WebSocket Updates ────────────────────────────────

@app.post("/api/online/start")
async def start_online_detection(
    interface: Optional[str] = Form(None),
    ip_filter: Optional[str] = Form(None),
    port_filter: Optional[str] = Form(None),
    simulated: bool = Form(False),
    sliding_window: int = Form(30)
):
    global capture_manager
    if capture_manager.is_running:
        return JSONResponse(content={"status": "already_running"})
        
    capture_manager.start(
        interface=interface,
        ip_filter=ip_filter,
        port_filter=port_filter,
        simulated=simulated,
        sliding_window_sec=sliding_window
    )
    return JSONResponse(content={"status": "started", "simulated": capture_manager.simulated})

@app.post("/api/online/stop")
async def stop_online_detection():
    global capture_manager
    if not capture_manager.is_running:
        return JSONResponse(content={"status": "already_stopped"})
        
    capture_manager.stop()
    return JSONResponse(content={"status": "stopped"})

@app.get("/api/online/status")
async def get_online_status():
    global capture_manager
    return JSONResponse(content={
        "is_running": capture_manager.is_running,
        "interface": capture_manager.interface,
        "ip_filter": capture_manager.ip_filter,
        "port_filter": capture_manager.port_filter,
        "simulated": capture_manager.simulated,
        "packet_count": len(capture_manager.packets),
        "sliding_window_sec": capture_manager.sliding_window_sec
    })

@app.get("/api/online/data")
async def get_online_data():
    global capture_manager
    # Instantly returns the latest calculated 30-second context window snapshot
    return JSONResponse(content={
        "snapshot": capture_manager.latest_snapshot,
        "history": capture_manager.history,
        "current_buffer_packets": len(capture_manager.packets)
    })

# Mount the static files directory
app.mount("/", StaticFiles(directory=STATIC_DIR), name="static")

if __name__ == "__main__":
    uvicorn.run("server:app", host="127.0.0.1", port=8000, reload=True)
