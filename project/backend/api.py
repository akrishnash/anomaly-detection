import os
import uuid
import shutil
import json
import time
from datetime import datetime
from typing import Optional
import pandas as pd
import numpy as np
from fastapi import APIRouter, UploadFile, File, Form, HTTPException
from fastapi.responses import JSONResponse as FastAPIJSONResponse, FileResponse, StreamingResponse
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

from pydantic import BaseModel

import database
import preprocessing
import anomaly_detector
import ddos_classifier
import shap_explainer
from packet_capture import PacketCaptureManager

router = APIRouter(prefix="/api")

# Directory configurations
UPLOAD_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "datasets"))
REPORTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "reports"))
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)

# Global packet capture manager instance
capture_manager = PacketCaptureManager()

# Last completed offline analysis, kept in memory so every dashboard screen
# (SOC home, flow explorer, DDoS classifier) can render real data after a
# page refresh without re-running the pipeline.
LAST_RUN = {"available": False, "timestamp": None, "report": None}

class SettingsUpdate(BaseModel):
    context_window: str
    model_selection: str
    confidence_threshold: str
    packet_capture_interface: Optional[str] = ""
    auto_refresh: str
    dark_mode: str

class PacketPayload(BaseModel):
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    length: int
    syn_flag: Optional[int] = 0
    rst_flag: Optional[int] = 0
    fin_flag: Optional[int] = 0

# ── Settings Endpoints ────────────────────────────────────────────────────────

@router.get("/settings")
def get_settings():
    try:
        settings = database.get_settings()
        return JSONResponse(content=settings)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/settings")
def update_settings(settings: SettingsUpdate):
    try:
        database.save_setting("context_window", settings.context_window)
        database.save_setting("model_selection", settings.model_selection)
        database.save_setting("confidence_threshold", settings.confidence_threshold)
        database.save_setting("packet_capture_interface", settings.packet_capture_interface or "")
        database.save_setting("auto_refresh", settings.auto_refresh)
        database.save_setting("dark_mode", settings.dark_mode)
        
        # If capture manager is running, we might want to update context window dynamically
        if capture_manager.is_running:
            capture_manager.sliding_window_sec = int(settings.context_window)
            
        return {"status": "success", "message": "Settings updated successfully."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/interfaces")
def get_interfaces():
    try:
        try:
            from scapy.all import IFACES
        except ImportError:
            return JSONResponse(content=[])
            
        ifaces_list = []
        for key, iface in IFACES.items():
            ipv4_addr = None
            if iface.ips and 4 in iface.ips and len(iface.ips[4]) > 0:
                ipv4_addr = iface.ips[4][0]
                
            ifaces_list.append({
                "key": key,
                "name": iface.name,
                "description": iface.description or "",
                "ip": ipv4_addr or "",
                "mac": iface.mac or ""
            })
        return JSONResponse(content=ifaces_list)
    except Exception as e:
        return JSONResponse(content=[])

# ── Offline Detection Endpoints ───────────────────────────────────────────────

@router.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    filename = file.filename
    file_id = str(uuid.uuid4())
    ext = os.path.splitext(filename)[1].lower()
    
    if ext not in [".csv", ".xlsx", ".xls", ".parquet", ".pcap", ".pcapng"]:
        raise HTTPException(status_code=400, detail="Unsupported file format. Please upload CSV, Excel, Parquet, PCAP, or PCAPNG.")
        
    temp_path = os.path.join(UPLOAD_DIR, f"{file_id}{ext}")
    
    try:
        with open(temp_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
            
        file_size_bytes = os.path.getsize(temp_path)
        file_size_mb = file_size_bytes / (1024 * 1024)
        
        num_rows = 0
        num_cols = 0
        preview_data = []
        
        if ext == ".csv":
            df = pd.read_csv(temp_path, nrows=10)
            # Fast row count
            num_rows = sum(1 for _ in open(temp_path, errors="ignore")) - 1
            num_cols = len(df.columns)
            preview_data = df.fillna("").to_dict(orient="records")
        elif ext in [".xlsx", ".xls"]:
            df = pd.read_excel(temp_path, nrows=10)
            df_full = pd.read_excel(temp_path)
            num_rows = len(df_full)
            num_cols = len(df.columns)
            preview_data = df.fillna("").to_dict(orient="records")
        elif ext == ".parquet":
            try:
                # Cheap metadata read: row count without loading the whole file
                import pyarrow.parquet as pq
                pf = pq.ParquetFile(temp_path)
                num_rows = pf.metadata.num_rows
                num_cols = pf.metadata.num_columns
                df = next(pf.iter_batches(batch_size=10)).to_pandas()
            except ImportError:
                df_full = pd.read_parquet(temp_path)
                num_rows = len(df_full)
                num_cols = len(df_full.columns)
                df = df_full.head(10)
            # to_json handles timestamps/NaN that plain dict conversion would not
            preview_data = json.loads(df.to_json(orient="records", date_format="iso"))
        elif ext in [".pcap", ".pcapng"]:
            from scapy.all import rdpcap
            pkts = rdpcap(temp_path)
            num_rows = len(pkts)
            num_cols = 0
            preview_data = [{"packet_no": idx, "summary": str(pkt), "length": len(pkt)} for idx, pkt in enumerate(pkts[:10])]
            
        database.add_log("INFO", f"Dataset uploaded: {filename} ({file_size_mb:.2f} MB), type={ext}")
        
        return JSONResponse(content={
            "file_id": file_id,
            "filename": filename,
            "size_mb": round(file_size_mb, 2),
            "num_rows": num_rows,
            "num_cols": num_cols,
            "preview": preview_data,
            "extension": ext
        })
    except Exception as e:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        database.add_log("ERROR", f"File upload/parse error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"File parse error: {str(e)}")

@router.post("/start-offline")
def start_offline_detection(file_id: str = Form(...), extension: str = Form(...)):
    temp_path = os.path.join(UPLOAD_DIR, f"{file_id}{extension}")
    if not os.path.exists(temp_path):
        raise HTTPException(status_code=404, detail="Session file not found.")
        
    try:
        database.add_log("INFO", f"Starting offline intrusion detection pipeline on file session {file_id}")
        
        # 1. Load data
        if extension == ".csv":
            df_full = pd.read_csv(temp_path)
        elif extension in [".xlsx", ".xls"]:
            df_full = pd.read_excel(temp_path)
        elif extension == ".parquet":
            df_full = pd.read_parquet(temp_path)
        elif extension in [".pcap", ".pcapng"]:
            from scapy.all import rdpcap
            import flow_generator
            import feature_extractor
            pkts = rdpcap(temp_path)
            flows_grouped = flow_generator.group_packets_into_flows(pkts)
            df_full = feature_extractor.extract_flow_features(flows_grouped)
            
        total_rows = len(df_full)
        if total_rows == 0:
            raise ValueError("The uploaded dataset contains zero rows or packets.")
            
        # 2. Preprocess & Scale (Canonical Feature preprocessing)
        X_scaled, feature_names, df_canonical = preprocessing.preprocess_dataset(df_full)
        df_feats = preprocessing.extract_features(df_canonical)
        
        # Ground truth check
        label_col = next((c for c in df_full.columns if str(c).strip().lower() in ["label", "true_label", "class"]), None)
        y_true = None
        if label_col:
            # Anything that is not an explicit benign marker counts as attack, so
            # named subtypes ("Syn", "DrDoS_DNS", ...) from CICDDoS2019 work too.
            y_true = df_full[label_col].apply(
                lambda x: 0 if str(x).strip().lower() in ["0", "benign", "normal", "background"] else 1
            ).values
            
        # 3. Running prediction pipeline (unsupervised IF + Autoencoder ensemble)
        score_detail = anomaly_detector.score_flows_detailed(X_scaled)
        probs = score_detail["probs"]
        if_scores = score_detail["if_scores"]
        ae_scores = score_detail["ae_scores"]
        if_probs = score_detail["if_probs"]
        ae_probs = score_detail["ae_probs"]

        # 4. Aggregating results
        total_flows = len(probs)
        
        # Load confidence threshold from settings
        conf_thresh = float(database.get_setting("confidence_threshold", "0.5"))
        
        # Vectorized canonical lookups (per-row .iloc costs minutes on large files)
        def _canon_col(name, default):
            if name in df_canonical.columns:
                return df_canonical[name].to_numpy()
            return np.full(total_flows, default, dtype=object)

        src_ip_arr = _canon_col("src_ip", "192.168.1.100")
        dst_ip_arr = _canon_col("dst_ip", "10.0.0.1")
        src_port_arr = _canon_col("src_port", 0)
        dst_port_arr = _canon_col("dst_port", 0)
        proto_arr = _canon_col("protocol", "TCP")

        feat_cols = list(df_feats.columns)
        feat_vals = df_feats.to_numpy()

        def _feat_dict(i):
            return dict(zip(feat_cols, feat_vals[i]))

        # Evaluate rule engine for all flows to catch signature attacks (SYN Flood, UDP Flood, Port Scan, etc.)
        rule_attack_flags = np.zeros(total_flows, dtype=bool)
        for i in range(total_flows):
            rule_input = _feat_dict(i)
            rule_input["protocol"] = proto_arr[i]
            rule_input["src_port"] = src_port_arr[i]
            rule_input["dst_port"] = dst_port_arr[i]
            v = ddos_classifier.classify_flow(rule_input)
            if v["attack_type"] not in ["Normal", "Unknown Anomaly"] and v["confidence"] >= 0.4:
                rule_attack_flags[i] = True

        # Combine ML score and rule engine detection
        is_anomaly_array = (probs >= conf_thresh) | rule_attack_flags
        anomaly_indices = np.where(is_anomaly_array)[0]
        
        anomaly_count = int(np.sum(is_anomaly_array))
        threat_ratio = (anomaly_count / total_flows) * 100 if total_flows > 0 else 0.0
        
        anomalies_list = []   # rich display payloads (capped at DISPLAY_LIMIT)
        benign_list = []
        normal_count = total_flows - anomaly_count

        # Large-file scalability: rich per-flow payloads (raw row, traces, SHAP)
        # are only built for the flows actually returned to the UI; statistics,
        # campaigns and the history DB still cover every row.
        DISPLAY_LIMIT = 50
        SHAP_MAX_FLOWS = 1000  # cap SHAP batch on huge files (306k-row CSVs would take hours)

        benign_indices = np.where(~is_anomaly_array)[0]

        # Vectorized canonical lookups (per-row .iloc costs minutes on large files)
        def _canon_col(name, default):
            if name in df_canonical.columns:
                return df_canonical[name].to_numpy()
            return np.full(total_flows, default, dtype=object)

        src_ip_arr = _canon_col("src_ip", "192.168.1.100")
        dst_ip_arr = _canon_col("dst_ip", "10.0.0.1")
        src_port_arr = _canon_col("src_port", 0)
        dst_port_arr = _canon_col("dst_port", 0)
        proto_arr = _canon_col("protocol", "TCP")

        feat_cols = list(df_feats.columns)
        feat_vals = df_feats.to_numpy()

        def _feat_dict(i):
            return dict(zip(feat_cols, feat_vals[i]))

        def _dst_port(i):
            dp = dst_port_arr[i]
            return 0 if pd.isna(dp) else int(dp)

        row_offset = 2 if extension in [".csv", ".xlsx", ".xls"] else 1
        file_row_arr = df_full.index.to_numpy() + row_offset

        # Protocol chart counts (vectorized)
        _proto_map = {"6": "TCP", "6.0": "TCP", "17": "UDP", "17.0": "UDP", "1": "ICMP", "1.0": "ICMP"}
        proto_norm = pd.Series(proto_arr).astype(str).str.upper().replace(_proto_map)
        protocol_counts = proto_norm.value_counts().to_dict()

        attack_counts = {}
        db_predictions = []

        # Stage 2: rule-engine verdict for EVERY flagged flow (cheap dict logic),
        # kept as light records; rich payloads are built later only for display.
        anomaly_records = []
        for i in anomaly_indices:
            i = int(i)
            rule_input = _feat_dict(i)
            rule_input["protocol"] = proto_arr[i]
            rule_input["src_port"] = src_port_arr[i]
            rule_input["dst_port"] = dst_port_arr[i]
            v = ddos_classifier.classify_flow(rule_input)
            anomaly_records.append({
                "id": i,
                "file_row_number": int(file_row_arr[i]),
                "src_ip": str(src_ip_arr[i]),
                "dst_ip": str(dst_ip_arr[i]),
                "dst_port": _dst_port(i),
                "protocol": str(proto_arr[i]),
                "attack_type": v["attack_type"],
                "rule_attack_type": v["attack_type"],  # pre-refinement verdict for the stage-2 trace
                "severity": v["severity"],
                "evidence": v["evidence"],
                "rule_confidence": v["confidence"],
                "total_pkts": int(rule_input.get("total_pkts", 0) or 0),
                "total_bytes": float(rule_input.get("fwd_bytes", 0.0) or 0.0) + float(rule_input.get("bwd_bytes", 0.0) or 0.0),
                "syn_pkts": int(rule_input.get("syn_flag", 0) or 0),
                "pps": float(rule_input.get("flow_pkts_s", 0.0) or 0.0),
                "stage3": None
            })
        rec_by_id = {r["id"]: r for r in anomaly_records}

        # Stage 2b: aggregate anomalies into campaigns (distributed attacks, port scans)
        # and apply cross-flow label refinements to per-flow verdicts
        campaigns, refinements = ddos_classifier.aggregate_campaigns(anomaly_records)
        for rec in anomaly_records:
            if rec["id"] in refinements:
                new_type, new_severity, reason = refinements[rec["id"]]
                rec["stage3"] = {
                    "original_type": rec["attack_type"],
                    "refined_type": new_type,
                    "reason": reason
                }
                rec["attack_type"], rec["severity"] = new_type, new_severity

        # Attack subtype counts for charts (after refinement)
        for rec in anomaly_records:
            attack_counts[rec["attack_type"]] = attack_counts.get(rec["attack_type"], 0) + 1

        # Stratified display sample: round-robin across attack types (rarest
        # first) so every detected type reaches the UI, instead of the first
        # DISPLAY_LIMIT rows which a dominant vector can fully occupy.
        ids_by_type = {}
        for rec in anomaly_records:
            ids_by_type.setdefault(rec["attack_type"], []).append(rec["id"])
        buckets = sorted(ids_by_type.values(), key=len)
        display_anomaly_ids = []
        depth = 0
        while len(display_anomaly_ids) < DISPLAY_LIMIT and any(depth < len(b) for b in buckets):
            for b in buckets:
                if depth < len(b):
                    display_anomaly_ids.append(b[depth])
                    if len(display_anomaly_ids) >= DISPLAY_LIMIT:
                        break
            depth += 1
        display_anomaly_ids.sort()

        # SHAP for the displayed anomalies plus up to SHAP_MAX_FLOWS for the history DB
        shap_idx = list(dict.fromkeys(display_anomaly_ids + [int(i) for i in anomaly_indices[:SHAP_MAX_FLOWS]]))
        shap_results = {}
        if len(shap_idx) > 0:
            batch_shap = shap_explainer.explain_predictions_batch(X_scaled[shap_idx])
            for idx, res in zip(shap_idx, batch_shap):
                shap_results[int(idx)] = res

        # Batch database insert covering every row (light fields only)
        for i in range(total_flows):
            is_a = bool(is_anomaly_array[i])
            rec = rec_by_id.get(i)
            prob = float(probs[i])
            db_predictions.append({
                "mode": "Offline",
                "file_row_number": int(file_row_arr[i]),
                "src_ip": str(src_ip_arr[i]),
                "dst_ip": str(dst_ip_arr[i]),
                "protocol": str(proto_arr[i]),
                "dst_port": rec["dst_port"] if rec else _dst_port(i),
                "prediction": 1 if is_a else 0,
                "confidence": prob * 100 if is_a else (1 - prob) * 100,
                "attack_type": rec["attack_type"] if rec else "Normal",
                "if_score": float(if_scores[i]),
                "ensemble_score": prob,
                "shap_explanation": shap_results.get(i, ([], ""))[0] if is_a else []
            })

        # Rich display payloads for the flows actually returned to the UI
        def _build_display_item(i):
            i = int(i)
            prob = float(probs[i])
            if_score = float(if_scores[i])
            ae_score = float(ae_scores[i])
            if_prob = float(if_probs[i])
            ae_prob = float(ae_probs[i])
            is_anomaly = bool(is_anomaly_array[i])
            rec = rec_by_id.get(i)

            # Stage 1 traceability: record which unsupervised head(s) crossed the threshold
            fired_heads = []
            if if_prob >= conf_thresh:
                fired_heads.append("Isolation Forest")
            if ae_prob >= conf_thresh:
                fired_heads.append("Autoencoder")
            stage1_trace = {
                "if_raw": round(if_score, 4),
                "if_prob": round(if_prob, 4),
                "ae_raw": round(ae_score, 4),
                "ae_prob": round(ae_prob, 4),
                "ensemble_score": round(prob, 4),
                "threshold": conf_thresh,
                "triggered_by": " + ".join(fired_heads) if fired_heads else "none",
                "decision": "ANOMALY" if is_anomaly else "NORMAL"
            }

            if rec:
                shap_contrib, explanation_text = shap_results.get(i, ([], "Threat signature detected."))
                if rec["evidence"]:
                    explanation_text += " Signature evidence: " + "; ".join(rec["evidence"]) + "."
                stage2_trace = {
                    "attack_type": rec["rule_attack_type"],
                    "rule_confidence": rec["rule_confidence"],
                    "evidence": rec["evidence"]
                }
            else:
                shap_contrib = []
                explanation_text = "Traffic flow matched the benign baseline signature. No threat detected."
                stage2_trace = None

            # Original raw row values, cleaned for JSON
            raw_row = df_full.iloc[i].to_dict()
            raw_row_cleaned = {}
            for k, v in raw_row.items():
                if pd.isna(v):
                    raw_row_cleaned[k] = None
                elif isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
                    raw_row_cleaned[k] = 0.0
                elif isinstance(v, (np.floating, np.integer)):
                    raw_row_cleaned[k] = v.item()
                else:
                    raw_row_cleaned[k] = str(v) if not isinstance(v, (str, int, float, bool, type(None))) else v

            flow_info = _feat_dict(i)
            return {
                "id": i,
                "file_row_number": int(file_row_arr[i]),
                "src_ip": str(src_ip_arr[i]),
                "dst_ip": str(dst_ip_arr[i]),
                "protocol": str(proto_arr[i]),
                "dst_port": rec["dst_port"] if rec else _dst_port(i),
                "prediction": 1 if is_anomaly else 0,
                "confidence": round(prob * 100, 2) if is_anomaly else round((1 - prob) * 100, 2),
                "attack_type": rec["attack_type"] if rec else "Normal",
                "severity": rec["severity"] if rec else "Low",
                "if_score": round(if_score, 4),
                "ensemble_score": round(prob, 4),
                "ae_score": round(ae_score, 4),  # Autoencoder reconstruction error
                "evidence": rec["evidence"] if rec else [],
                "rule_confidence": rec["rule_confidence"] if rec else 0.0,
                "classification_trace": {
                    "stage1_anomaly_detection": stage1_trace,
                    "stage2_rule_engine": stage2_trace,
                    "stage3_campaign_refinement": rec["stage3"] if rec else None
                },
                "shap_explanation": shap_contrib,
                "explanation_text": explanation_text,
                "flow_details": {k: (0.0 if (pd.isna(v) or np.isinf(v)) else (round(float(v), 4) if isinstance(v, (float, np.floating)) else int(v))) for k, v in flow_info.items()},
                "raw_row": raw_row_cleaned
            }

        anomalies_list = [_build_display_item(i) for i in display_anomaly_ids]
        benign_list = [_build_display_item(i) for i in benign_indices[:DISPLAY_LIMIT]]

        # Per-attack-type packet/traffic detail aggregation (after refinement)
        severity_counts = {}
        attack_detail_map = {}
        for item in anomaly_records:
            severity_counts[item["severity"]] = severity_counts.get(item["severity"], 0) + 1
            d = attack_detail_map.setdefault(item["attack_type"], {
                "name": item["attack_type"],
                "flows": 0,
                "total_pkts": 0,
                "total_bytes": 0.0,
                "syn_pkts": 0,
                "peak_pps": 0.0,
                "sum_pps": 0.0,
                "sum_conf": 0.0,
                "severities": {},
                "src_counter": {},
                "target_counter": {},
                "dst_ports": set(),
                "protocols": set(),
                "example_evidence": [],
                "rows": []
            })
            d["rows"].append(item.get("file_row_number"))
            d["flows"] += 1
            d["total_pkts"] += item["total_pkts"]
            d["total_bytes"] += item["total_bytes"]
            d["syn_pkts"] += item["syn_pkts"]
            pps = item["pps"]
            d["peak_pps"] = max(d["peak_pps"], pps)
            d["sum_pps"] += pps
            d["sum_conf"] += float(item.get("rule_confidence", 0.0))
            d["severities"][item["severity"]] = d["severities"].get(item["severity"], 0) + 1
            d["src_counter"][item["src_ip"]] = d["src_counter"].get(item["src_ip"], 0) + 1
            target = f"{item['dst_ip']}:{item['dst_port']}"
            d["target_counter"][target] = d["target_counter"].get(target, 0) + 1
            d["dst_ports"].add(int(item["dst_port"]))
            d["protocols"].add(item["protocol"])
            if item["evidence"] and len(d["example_evidence"]) < 3:
                ev = item["evidence"][0]
                if ev not in d["example_evidence"]:
                    d["example_evidence"].append(ev)

        attack_details = []
        for d in sorted(attack_detail_map.values(), key=lambda x: -x["flows"]):
            attack_details.append({
                "name": d["name"],
                "flows": d["flows"],
                "total_pkts": d["total_pkts"],
                "total_bytes": round(d["total_bytes"], 0),
                "syn_pkts": d["syn_pkts"],
                "avg_pps": round(d["sum_pps"] / d["flows"], 2) if d["flows"] else 0.0,
                "peak_pps": round(d["peak_pps"], 2),
                "avg_rule_confidence": round(d["sum_conf"] / d["flows"], 2) if d["flows"] else 0.0,
                "severities": d["severities"],
                "protocols": sorted(d["protocols"]),
                "top_sources": [{"ip": ip, "flows": c} for ip, c in
                                sorted(d["src_counter"].items(), key=lambda x: -x[1])[:5]],
                "top_targets": [{"target": t, "flows": c} for t, c in
                                sorted(d["target_counter"].items(), key=lambda x: -x[1])[:5]],
                "unique_sources": len(d["src_counter"]),
                "dst_ports": sorted(d["dst_ports"])[:20],
                "example_evidence": d["example_evidence"],
                # Affected file rows/flows for the plain-language summary panel
                # (anomalies payload is capped at 50, so row pointers ride here)
                "row_numbers": sorted(r for r in d["rows"] if r is not None)[:40]
            })

        severities = [
            {"name": s, "value": severity_counts[s]}
            for s in ["Critical", "High", "Medium", "Low"] if s in severity_counts
        ]

        # Ensemble score distribution histogram (10 bins), split normal vs attack
        score_distribution = []
        for b in range(10):
            lo_edge, hi_edge = b / 10.0, (b + 1) / 10.0
            in_bin = (probs >= lo_edge) & (probs < hi_edge) if b < 9 else (probs >= lo_edge) & (probs <= 1.0)
            score_distribution.append({
                "bin": f"{lo_edge:.1f}-{hi_edge:.1f}",
                "normal": int(np.sum(in_bin & ~is_anomaly_array)),
                "attack": int(np.sum(in_bin & is_anomaly_array))
            })

        # Perform a single batch database transaction for all predictions (extremely fast)
        database.add_predictions_batch(db_predictions)
                
        # Generate 12-point timeline for the chart
        num_timeline_points = 12
        bin_size = max(1, total_flows // num_timeline_points)
        timeline_data = []
        for b in range(num_timeline_points):
            start_idx = b * bin_size
            end_idx = min(total_flows, (b + 1) * bin_size)
            if start_idx >= total_flows:
                break
            
            bin_attacks = int(np.sum(is_anomaly_array[start_idx:end_idx]))
            bin_total = end_idx - start_idx
            bin_normal = bin_total - bin_attacks
            bin_ratio = round((bin_attacks / bin_total) * 100, 2) if bin_total > 0 else 0.0
            
            timeline_data.append({
                "time": f"Bin {b+1}",
                "normal": bin_normal,
                "attacks": bin_attacks,
                "detection_rate": bin_ratio
            })
            
        # Metrics reporting
        classification_report = {}
        if y_true is not None:
            from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix
            y_pred_thresholded = is_anomaly_array.astype(int)
            try:
                roc_auc = round(roc_auc_score(y_true, probs) * 100, 2)
            except Exception:
                roc_auc = 0.0
            cm = confusion_matrix(y_true, y_pred_thresholded).tolist()
            classification_report = {
                "accuracy": round(accuracy_score(y_true, y_pred_thresholded) * 100, 2),
                "precision": round(precision_score(y_true, y_pred_thresholded, zero_division=0) * 100, 2),
                "recall": round(recall_score(y_true, y_pred_thresholded, zero_division=0) * 100, 2),
                "f1_score": round(f1_score(y_true, y_pred_thresholded, zero_division=0) * 100, 2),
                "roc_auc": roc_auc,
                "confusion_matrix": cm
            }
            
        # Clean up file
        if os.path.exists(temp_path):
            os.remove(temp_path)
            
        database.add_log("INFO", f"Offline detection finished: {total_flows} flows analyzed. Detected {anomaly_count} attacks.")

        report = {
            "status": "success",
            "total_flows": total_flows,
            "anomalies_count": anomaly_count,
            "normal_count": normal_count,
            "threat_ratio": round(threat_ratio, 2),
            "classification_report": classification_report,
            "anomalies": anomalies_list[:50],  # Return top 50 anomalies to prevent payload bloat
            "benign": benign_list[:50],         # Return top 50 benign to prevent payload bloat
            "protocols": [{"name": k, "value": v} for k, v in protocol_counts.items()],
            "attacks": [{"name": k, "value": v} for k, v in attack_counts.items()],
            "severities": severities,
            "score_distribution": score_distribution,
            "attack_details": attack_details,
            "campaigns": campaigns,
            "timeline": timeline_data
        }

        LAST_RUN["available"] = True
        LAST_RUN["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        LAST_RUN["report"] = report

        return JSONResponse(content=report)
    except ValueError as e:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        database.add_log("ERROR", f"Validation error: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        database.add_log("ERROR", f"Offline pipeline error: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Pipeline error: {str(e)}")

@router.get("/last-run")
def get_last_run():
    """Returns the most recent completed offline analysis (kept in memory)."""
    return JSONResponse(content={
        "available": LAST_RUN["available"],
        "timestamp": LAST_RUN["timestamp"],
        "report": LAST_RUN["report"]
    })

# ── Online Detection Endpoints ────────────────────────────────────────────────

@router.post("/start-online")
def start_online(
    option: int = Form(...),
    interface: Optional[str] = Form(None),
    ip_filter: Optional[str] = Form(None),
    port_filter: Optional[str] = Form(None),
    interface_name: Optional[str] = Form(None),
    pcap_file: Optional[UploadFile] = File(None)
):
    try:
        pcap_temp_path = None
        if option == 4 and pcap_file is not None:
            # Save uploaded PCAP for live streaming replay
            pcap_id = str(uuid.uuid4())
            pcap_temp_path = os.path.join(UPLOAD_DIR, f"{pcap_id}.pcap")
            with open(pcap_temp_path, "wb") as buffer:
                shutil.copyfileobj(pcap_file.file, buffer)
                
        sliding_window = int(database.get_setting("context_window", "30"))
        
        capture_manager.start(
            mode_option=option,
            interface=interface,
            ip_filter=ip_filter,
            port_filter=port_filter,
            interface_name=interface_name,
            pcap_file_path=pcap_temp_path,
            sliding_window_sec=sliding_window
        )
        
        return {"status": "started", "simulated": capture_manager.simulated}
    except Exception as e:
        database.add_log("ERROR", f"Failed to start online detection: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/stop-online")
def stop_online():
    try:
        if capture_manager.is_running:
            capture_manager.stop()
            return {"status": "stopped"}
        return {"status": "already_stopped"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/online/status")
def get_online_status():
    return {
        "is_running": capture_manager.is_running,
        "interface": capture_manager.interface,
        "ip_filter": capture_manager.ip_filter,
        "port_filter": capture_manager.port_filter,
        "interface_name": capture_manager.interface_name,
        "simulated": capture_manager.simulated,
        "packet_count": len(capture_manager.packets),
        "sliding_window_sec": capture_manager.sliding_window_sec
    }

@router.post("/online/inject")
def inject_packet(payload: PacketPayload):
    """Option 5: external endpoint streaming packet injection"""
    try:
        capture_manager.inject_packet_data(payload.dict())
        return {"status": "success", "message": "Packet injected."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ── Prediction & Metrics Endpoints ────────────────────────────────────────────

@router.get("/prediction")
def get_latest_prediction():
    """Returns the latest captured alerts"""
    if not capture_manager.is_running:
        return JSONResponse(content={"status": "idle", "alerts": []})
    return JSONResponse(content={
        "status": "running",
        "alerts": capture_manager.latest_snapshot["alerts"]
    })

@router.get("/dashboard")
def get_dashboard_data():
    """Aggregates metrics and statistics across the current sliding window history"""
    snapshot = capture_manager.latest_snapshot
    history = capture_manager.history
    
    # Standard values if capture manager is not active
    if not capture_manager.is_running and len(history) == 0:
        return JSONResponse(content={
            "running": False,
            "stats": {
                "total_packets": 0,
                "total_flows": 0,
                "normal_flows": 0,
                "suspicious_flows": 0,
                "attack_flows": 0,
                "detection_rate": 0.0,
                "confidence_score": 0.0,
                "if_score": 0.0,
                "ensemble_score": 0.0
            },
            "timeline": [],
            "protocols": [],
            "attacks": [],
            "campaigns": [],
            "top_src_ips": [],
            "top_dst_ips": []
        })

    stats = {
        "total_packets": snapshot["total_packets"],
        "total_flows": snapshot["total_flows"],
        "normal_flows": snapshot["normal_flows"],
        "suspicious_flows": snapshot["suspicious_flows"],
        "attack_flows": snapshot["attack_flows"],
        "detection_rate": snapshot["detection_rate"],
        "confidence_score": snapshot["avg_confidence"],
        "if_score": snapshot["avg_if_score"],
        "ensemble_score": snapshot["avg_ensemble_score"]
    }
    
    # Flatten history for timeline graphs
    timeline = []
    for h in history:
        t_label = time.strftime("%H:%M:%S", time.localtime(h["timestamp"]))
        timeline.append({
            "time": t_label,
            "packets": h["total_packets"],
            "flows": h["total_flows"],
            "normal": h["normal_flows"],
            "attacks": h["attack_flows"],
            "detection_rate": h["detection_rate"]
        })
        
    # Protocols array
    protocols = [{"name": k, "value": v} for k, v in snapshot["charts"]["protocols"].items() if v > 0]
    
    # Attacks array
    attacks = [{"name": k, "value": v} for k, v in snapshot["charts"]["attacks"].items()]
    
    # IPs
    top_src = [{"ip": k, "count": v} for k, v in snapshot["charts"]["top_src_ips"].items()]
    top_dst = [{"ip": k, "count": v} for k, v in snapshot["charts"]["top_dst_ips"].items()]
    
    return JSONResponse(content={
        "running": capture_manager.is_running,
        "stats": stats,
        "timeline": timeline,
        "protocols": protocols,
        "attacks": attacks,
        "campaigns": snapshot.get("campaigns", []),
        "top_src_ips": top_src,
        "top_dst_ips": top_dst
    })

@router.get("/metrics")
def get_model_health():
    """Gets model status indicators"""
    models_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "models"))
    assets = ["scaler.pkl", "isolation_forest.pkl", "autoencoder.pkl", "meta.pkl"]
    health = {}

    all_ok = True
    for asset in assets:
        exists = os.path.exists(os.path.join(models_dir, asset))
        health[asset] = "Healthy" if exists else "Missing"
        if not exists:
            all_ok = False

    return {
        "status": "Green" if all_ok else "Red",
        "health_monitor": health,
        "pipeline_type": "Unsupervised Ensemble (Isolation Forest + Autoencoder) + DDoS Rule Engine"
    }

# ── History & Export Endpoints ────────────────────────────────────────────────

@router.get("/history")
def get_prediction_history(
    search: Optional[str] = None,
    mode: Optional[str] = None,
    prediction: Optional[int] = None,
    protocol: Optional[str] = None,
    limit: int = 25,
    offset: int = 0,
    sort_by: str = "timestamp",
    sort_order: str = "DESC"
):
    try:
        records, total_count = database.get_history(
            search=search,
            mode=mode,
            prediction=prediction,
            protocol=protocol,
            limit=limit,
            offset=offset,
            sort_by=sort_by,
            sort_order=sort_order
        )
        return JSONResponse(content={
            "records": records,
            "total": total_count,
            "limit": limit,
            "offset": offset
        })
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/shap/{history_id}")
def get_shap_explanation(history_id: int):
    conn = database.get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT shap_explanation, attack_type FROM history WHERE id = ?", (history_id,))
    row = cursor.fetchone()
    conn.close()
    
    if not row:
        raise HTTPException(status_code=404, detail="Prediction record not found.")
        
    try:
        shap_contrib = json.loads(row["shap_explanation"])
    except Exception:
        shap_contrib = []
        
    attack_type = row["attack_type"]
    
    # Generate text summary explanation dynamically based on features
    positive_impacts = [c for c in shap_contrib if c.get("impact", 0) > 0.01]
    if len(positive_impacts) > 0:
        top_features = [c.get("display_name", c.get("feature")) for c in sorted(positive_impacts, key=lambda x: x["impact"], reverse=True)[:4]]
        if len(top_features) > 1:
            features_text = ", ".join(top_features[:-1]) + f", and {top_features[-1]}"
        else:
            features_text = top_features[0]
        text_explanation = f"The attack ({attack_type}) was detected mainly because {features_text} contributed the most to the model classification."
    else:
        text_explanation = "The anomaly was detected due to a combination of subtle deviations from the baseline traffic profile."
        
    return JSONResponse(content={
        "shap_explanation": shap_contrib,
        "text_explanation": text_explanation,
        "attack_type": attack_type
    })

@router.get("/history/stats")
def get_history_stats(mode: Optional[str] = None):
    try:
        stats = database.get_history_stats(mode=mode)
        stats["is_running"] = capture_manager.is_running
        stats["sliding_window_sec"] = capture_manager.sliding_window_sec
        return JSONResponse(content=stats)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/export-json")
def export_json(
    mode: Optional[str] = None,
    search: Optional[str] = None,
    prediction: Optional[int] = None,
    protocol: Optional[str] = None
):
    try:
        conn = database.get_db_connection()
        query = "SELECT id, timestamp, mode, file_row_number, src_ip, dst_ip, protocol, dst_port, prediction, confidence, attack_type, if_score, ensemble_score FROM history WHERE 1=1"
        params = []
        
        if search:
            query += " AND (src_ip LIKE ? OR dst_ip LIKE ? OR attack_type LIKE ?)"
            search_param = f"%{search}%"
            params.extend([search_param, search_param, search_param])
        if mode:
            query += " AND mode = ?"
            params.append(mode)
        if prediction is not None:
            query += " AND prediction = ?"
            params.append(prediction)
        if protocol:
            query += " AND protocol = ?"
            params.append(protocol)
            
        query += " ORDER BY id DESC"
        
        df = pd.read_sql_query(query, conn, params=params)
        conn.close()
        
        json_data = df.to_json(orient="records", indent=2)
        filename = f"ids_captured_history_{mode.lower() if mode else 'all'}.json"
        
        response = StreamingResponse(iter([json_data]), media_type="application/json")
        response.headers["Content-Disposition"] = f"attachment; filename={filename}"
        return response
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/export-csv")
def export_csv(
    mode: Optional[str] = None,
    search: Optional[str] = None,
    prediction: Optional[int] = None,
    protocol: Optional[str] = None
):
    try:
        conn = database.get_db_connection()
        query = "SELECT id, timestamp, mode, file_row_number, src_ip, dst_ip, protocol, dst_port, prediction, confidence, attack_type, if_score, ensemble_score FROM history WHERE 1=1"
        params = []
        
        if search:
            query += " AND (src_ip LIKE ? OR dst_ip LIKE ? OR attack_type LIKE ?)"
            search_param = f"%{search}%"
            params.extend([search_param, search_param, search_param])
        if mode:
            query += " AND mode = ?"
            params.append(mode)
        if prediction is not None:
            query += " AND prediction = ?"
            params.append(prediction)
        if protocol:
            query += " AND protocol = ?"
            params.append(protocol)
            
        query += " ORDER BY id DESC"
        
        df = pd.read_sql_query(query, conn, params=params)
        conn.close()
        
        csv_data = df.to_csv(index=False)
        filename = f"ids_captured_history_{mode.lower() if mode else 'all'}.csv"
        
        response = StreamingResponse(iter([csv_data]), media_type="text/csv")
        response.headers["Content-Disposition"] = f"attachment; filename={filename}"
        return response
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/download-pdf")
def export_pdf(
    mode: Optional[str] = None,
    search: Optional[str] = None,
    prediction: Optional[int] = None,
    protocol: Optional[str] = None
):
    try:
        from fpdf import FPDF
        
        stats = database.get_history_stats(mode=mode)
        
        conn = database.get_db_connection()
        cursor = conn.cursor()
        query = "SELECT id, timestamp, mode, src_ip, dst_ip, protocol, dst_port, prediction, confidence, attack_type FROM history WHERE 1=1"
        params = []
        
        if search:
            query += " AND (src_ip LIKE ? OR dst_ip LIKE ? OR attack_type LIKE ?)"
            search_param = f"%{search}%"
            params.extend([search_param, search_param, search_param])
        if mode:
            query += " AND mode = ?"
            params.append(mode)
        if prediction is not None:
            query += " AND prediction = ?"
            params.append(prediction)
        if protocol:
            query += " AND protocol = ?"
            params.append(protocol)
            
        query += " ORDER BY id DESC LIMIT 100"
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()
        
        interval_text = f"Interval: {stats['first_captured']} to {stats['latest_captured']} ({stats['formatted_duration']})" if stats['total_records'] > 0 else "Interval: No data captured"
        
        class IDSPDFReport(FPDF):
            def header(self):
                self.set_fill_color(30, 41, 59) # Slate color
                self.rect(0, 0, 210, 36, "F")
                self.set_text_color(6, 182, 212) # Cyan
                self.set_font("Arial", "B", 14)
                self.cell(0, 8, "CYBERSECURITY IDS INCIDENT & LIVE CAPTURE HISTORY REPORT", 0, 1, "C")
                self.set_font("Arial", "", 8)
                self.set_text_color(255, 255, 255)
                self.cell(0, 5, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Target: {mode or 'All Modes'} | Records: {len(rows)}", 0, 1, "C")
                self.cell(0, 5, interval_text, 0, 1, "C")
                self.ln(8)
                
            def footer(self):
                self.set_y(-15)
                self.set_font("Arial", "I", 8)
                self.set_text_color(128, 128, 128)
                self.cell(0, 10, f"Page {self.page_no()}", 0, 0, "C")
                
        pdf = IDSPDFReport()
        pdf.add_page()
        pdf.set_font("Arial", "", 8)
        
        # Grid header
        pdf.set_fill_color(226, 232, 240)
        pdf.set_text_color(15, 23, 42)
        pdf.set_font("Arial", "B", 8)
        headers = ["ID", "Timestamp", "Mode", "Source IP", "Destination IP", "Proto", "Port", "Class", "Confidence", "Threat Type"]
        widths = [8, 28, 14, 26, 26, 12, 10, 12, 18, 36]
        
        for h, w in zip(headers, widths):
            pdf.cell(w, 7, h, 1, 0, "C", True)
        pdf.ln()
        
        pdf.set_font("Arial", "", 8)
        for row in rows:
            # Alternating row colors
            pdf.set_fill_color(255, 255, 255)
            r = dict(row)
            
            # If it's an attack, highlight threat type in light red
            is_attack = r["prediction"] == 1
            if is_attack:
                pdf.set_fill_color(254, 226, 226) # Light Red
                
            pdf.cell(widths[0], 6, str(r["id"]), 1, 0, "C", True)
            pdf.cell(widths[1], 6, str(r["timestamp"]), 1, 0, "C", True)
            pdf.cell(widths[2], 6, str(r["mode"]), 1, 0, "C", True)
            pdf.cell(widths[3], 6, str(r["src_ip"]), 1, 0, "L", True)
            pdf.cell(widths[4], 6, str(r["dst_ip"]), 1, 0, "L", True)
            pdf.cell(widths[5], 6, str(r["protocol"]), 1, 0, "C", True)
            pdf.cell(widths[6], 6, str(r["dst_port"]), 1, 0, "C", True)
            pdf.cell(widths[7], 6, "ATTACK" if is_attack else "NORMAL", 1, 0, "C", True)
            pdf.cell(widths[8], 6, f"{r['confidence']:.2f}%", 1, 0, "R", True)
            pdf.cell(widths[9], 6, str(r["attack_type"]), 1, 0, "L", True)
            pdf.ln()
            
        pdf_filename = f"report_{str(uuid.uuid4())[:8]}.pdf"
        pdf_path = os.path.join(REPORTS_DIR, pdf_filename)
        pdf.output(pdf_path)
        
        return FileResponse(pdf_path, filename=f"ids_captured_report_{mode.lower() if mode else 'all'}.pdf", media_type="application/pdf")
    except Exception as e:
        database.add_log("ERROR", f"PDF generation error: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/export-xml")
def export_xml(
    mode: Optional[str] = None,
    search: Optional[str] = None,
    prediction: Optional[int] = None,
    protocol: Optional[str] = None
):
    try:
        conn = database.get_db_connection()
        query = "SELECT id, timestamp, mode, file_row_number, src_ip, dst_ip, protocol, dst_port, prediction, confidence, attack_type, if_score, ensemble_score FROM history WHERE 1=1"
        params = []
        
        if search:
            query += " AND (src_ip LIKE ? OR dst_ip LIKE ? OR attack_type LIKE ?)"
            search_param = f"%{search}%"
            params.extend([search_param, search_param, search_param])
        if mode:
            query += " AND mode = ?"
            params.append(mode)
        if prediction is not None:
            query += " AND prediction = ?"
            params.append(prediction)
        if protocol:
            query += " AND protocol = ?"
            params.append(protocol)
            
        query += " ORDER BY id DESC"
        
        df = pd.read_sql_query(query, conn, params=params)
        conn.close()
        
        xml_lines = ['<?xml version="1.0" encoding="UTF-8"?>', '<live_captured_history>']
        for _, row in df.iterrows():
            xml_lines.append("  <flow_record>")
            for col, val in row.items():
                xml_lines.append(f"    <{col}>{val if pd.notna(val) else ''}</{col}>")
            xml_lines.append("  </flow_record>")
        xml_lines.append("</live_captured_history>")
        
        xml_data = "\n".join(xml_lines)
        filename = f"ids_captured_history_{mode.lower() if mode else 'all'}.xml"
        
        response = StreamingResponse(iter([xml_data]), media_type="application/xml")
        response.headers["Content-Disposition"] = f"attachment; filename={filename}"
        return response
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/export-txt")
def export_txt(
    mode: Optional[str] = None,
    search: Optional[str] = None,
    prediction: Optional[int] = None,
    protocol: Optional[str] = None
):
    try:
        conn = database.get_db_connection()
        query = "SELECT id, timestamp, mode, file_row_number, src_ip, dst_ip, protocol, dst_port, prediction, confidence, attack_type FROM history WHERE 1=1"
        params = []
        
        if search:
            query += " AND (src_ip LIKE ? OR dst_ip LIKE ? OR attack_type LIKE ?)"
            search_param = f"%{search}%"
            params.extend([search_param, search_param, search_param])
        if mode:
            query += " AND mode = ?"
            params.append(mode)
        if prediction is not None:
            query += " AND prediction = ?"
            params.append(prediction)
        if protocol:
            query += " AND protocol = ?"
            params.append(protocol)
            
        query += " ORDER BY id DESC"
        
        df = pd.read_sql_query(query, conn, params=params)
        conn.close()
        
        stats = database.get_history_stats(mode=mode)
        
        header = [
            "================================================================================",
            "              CYBERSECURITY IDS LIVE CAPTURED DATA HISTORY DIGEST               ",
            "================================================================================",
            f"Generated At      : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Mode Filter       : {mode or 'ALL'}",
            f"Captured Interval : {stats.get('first_captured', 'N/A')} to {stats.get('latest_captured', 'N/A')}",
            f"Interval Duration : {stats.get('formatted_duration', 'N/A')}",
            f"Total Flow Records: {len(df)}",
            "--------------------------------------------------------------------------------",
            f"{'ID':<6} {'TIMESTAMP':<20} {'MODE':<8} {'SRC_IP':<16} {'DST_IP':<16} {'PROTO':<6} {'CLASS':<8} {'ATTACK_TYPE'}",
            "--------------------------------------------------------------------------------"
        ]
        
        lines = header.copy()
        for _, row in df.iterrows():
            verdict = "ATTACK" if row['prediction'] == 1 else "NORMAL"
            lines.append(f"{row['id']:<6} {str(row['timestamp']):<20} {str(row['mode']):<8} {str(row['src_ip']):<16} {str(row['dst_ip']):<16} {str(row['protocol']):<6} {verdict:<8} {str(row['attack_type'])}")
        
        txt_data = "\n".join(lines)
        filename = f"ids_captured_history_{mode.lower() if mode else 'all'}.txt"
        
        response = StreamingResponse(iter([txt_data]), media_type="text/plain")
        response.headers["Content-Disposition"] = f"attachment; filename={filename}"
        return response
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))



@router.get("/logs")
def get_system_logs(limit: int = 50):
    try:
        logs = database.get_logs(limit=limit)
        return JSONResponse(content=logs)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
