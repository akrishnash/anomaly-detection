"""
Train anomaly detection models directly from local Wireshark .pcapng captures.

Pipeline Workflow:
1. Streams all .pcapng files from wireshark_dataset/training_wireshark/ using Scapy PcapReader.
2. Slices packets into fixed 30-second windows.
3. Groups packets into flows using flow_generator.group_packets_into_flows().
4. Extracts 10 core flow features using feature_extractor.extract_flow_features().
5. Preprocesses features (canonical mapping, median imputation, log1p transformation, StandardScaler).
6. Fits IsolationForest (contamination=0.01) and Autoencoder on local benign flows only.
7. Calibrates score anchors (lo, mid, hi) using optional attack reference if present, or benign extrapolation.
8. Creates a timestamped backup of existing project/models/ artifacts.
9. Persists scaler.pkl, isolation_forest.pkl, autoencoder.pkl, and meta.pkl into project/models/.
10. Generates a comprehensive training metrics report JSON.
"""
import os
import sys
import glob
import time
import json
import shutil
import pickle
import argparse
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest

# Add parent path to ensure backend imports work seamlessly
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import flow_generator
import feature_extractor
import database
from preprocessing import (
    AutoencoderAnomalyDetector,
    build_alias_dictionary,
    map_to_canonical_schema,
    run_feature_engineering,
    extract_features,
)

MODELS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "models"))
DEFAULT_PCAP_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "wireshark_dataset", "training_wireshark"))
ATTACK_REF_CSV = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "data", "ctu13", "CTU13_Attack_Traffic.csv"))

FEATURE_NAMES = [
    "flow_byts_s", "flow_pkts_s", "fwd_bytes", "bwd_bytes", "total_pkts",
    "syn_flag", "rst_flag", "fin_flag", "flow_duration_s", "pkt_len_mean"
]

def restrict_dissection():
    """Restricts Scapy dissection to L2-L4 layers for significant speedup."""
    try:
        from scapy.config import conf
        from scapy.layers.l2 import Ether, ARP
        from scapy.layers.inet import IP, TCP, UDP, ICMP
        from scapy.layers.inet6 import IPv6
        conf.layers.filter([Ether, ARP, IP, IPv6, TCP, UDP, ICMP])
    except Exception as e:
        print(f"[!] Could not filter Scapy layers ({e}); continuing with full dissection.")

def process_pcapng_files(pcap_dir: str, window_sec: int = 30):
    """
    Streams packets from all .pcapng files, slices them into 30s windows,
    groups flows via flow_generator, and extracts features via feature_extractor.
    """
    from scapy.all import PcapReader
    
    files = sorted(
        glob.glob(os.path.join(pcap_dir, "*.pcapng")) +
        glob.glob(os.path.join(pcap_dir, "*.pcap"))
    )
    if not files:
        raise FileNotFoundError(f"No .pcapng or .pcap files found in {pcap_dir}")
        
    print(f"[+] Found {len(files)} capture files in {pcap_dir}")
    database.add_log("INFO", f"Starting direct Wireshark pipeline for {len(files)} .pcapng files...")
    
    all_flow_dfs = []
    total_packets = 0
    total_windows_count = 0
    
    for fpath in files:
        fname = os.path.basename(fpath)
        print(f"\n[+] Streaming {fname} ...")
        t0 = time.time()
        
        windows = {} # win_id -> list of packets
        file_packets = 0
        file_flows = 0
        max_win = None
        
        reader = PcapReader(fpath)
        try:
            for pkt in reader:
                file_packets += 1
                total_packets += 1
                win_id = int(float(pkt.time) // window_sec)
                windows.setdefault(win_id, []).append(pkt)
                
                if max_win is None or win_id > max_win:
                    max_win = win_id
                    # Flush windows at least 2 steps behind newest to keep RAM bounded
                    for wid in [w for w in windows if w < max_win - 1]:
                        pkts_win = windows.pop(wid)
                        total_windows_count += 1
                        grouped = flow_generator.group_packets_into_flows(pkts_win)
                        if grouped:
                            df_win = feature_extractor.extract_flow_features(grouped)
                            if not df_win.empty:
                                all_flow_dfs.append(df_win)
                                file_flows += len(df_win)
                                
                if file_packets % 500000 == 0:
                    rate = file_packets / (time.time() - t0)
                    print(f"    {file_packets:,} packets processed ({rate:.0f} pkt/s)...")
        except (EOFError, StopIteration):
            pass
        except Exception as e:
            print(f"[!] Warning reading {fname}: {e}")
        finally:
            try:
                reader.close()
            except Exception:
                pass
                
        # Flush remaining windows for this file
        for wid in sorted(windows):
            pkts_win = windows.pop(wid)
            total_windows_count += 1
            grouped = flow_generator.group_packets_into_flows(pkts_win)
            if grouped:
                df_win = feature_extractor.extract_flow_features(grouped)
                if not df_win.empty:
                    all_flow_dfs.append(df_win)
                    file_flows += len(df_win)
                    
        dt = time.time() - t0
        print(f"[+] {fname}: {file_packets:,} packets -> {file_flows:,} flows across 30s windows in {dt:.1f}s")
        
    if not all_flow_dfs:
        raise ValueError("No flows could be extracted from the Wireshark capture files.")
        
    df_combined = pd.concat(all_flow_dfs, ignore_index=True)
    total_flows = len(df_combined)
    print(f"\n[+] Total Wireshark Dataset Summary: {len(files)} files, {total_packets:,} packets, {total_windows_count} 30s windows -> {total_flows:,} flows.")
    
    return df_combined, len(files), total_packets, total_windows_count, total_flows

def build_and_preprocess_features(df_raw: pd.DataFrame):
    """
    Applies exact backend preprocessing: canonical schema mapping, median imputation,
    log1p transforms for skewed columns, and StandardScaler fitting.
    """
    alias_dict = build_alias_dictionary()
    df_canonical, _ = map_to_canonical_schema(df_raw, alias_dict)
    df_canonical = run_feature_engineering(df_canonical)
    feats = extract_features(df_canonical)
    
    feats = feats.replace([np.inf, -np.inf], np.nan)
    medians = feats.median()
    
    # Identify skewed columns (skew > 2)
    skew = feats.skew()
    skewed_cols = skew[skew > 2].index.tolist()
    
    feats = feats.fillna(medians)
    for col in skewed_cols:
        feats[col] = np.log1p(feats[col].clip(lower=0))
        
    X_df = feats[FEATURE_NAMES]
    
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_df)
    
    return X_df, X_scaled, scaler, medians, skewed_cols

def load_attack_reference_scores(scaler, medians, skewed_cols, if_model, ae_model):
    """Optionally loads attack reference flows to establish empirical score anchors."""
    if not os.path.exists(ATTACK_REF_CSV):
        print(f"[!] Attack reference file not found at {ATTACK_REF_CSV}. Using benign extrapolation for 'hi' anchor.")
        return None, None
        
    try:
        print(f"[+] Loading attack reference dataset from {ATTACK_REF_CSV}...")
        df_atk = pd.read_csv(ATTACK_REF_CSV, nrows=20000, engine="python")
        
        # Build features matching backend
        alias_dict = build_alias_dictionary()
        df_can, _ = map_to_canonical_schema(df_atk, alias_dict)
        df_can = run_feature_engineering(df_can)
        feats_atk = extract_features(df_can)
        feats_atk = feats_atk.replace([np.inf, -np.inf], np.nan).fillna(medians)
        for col in skewed_cols:
            if col in feats_atk.columns:
                feats_atk[col] = np.log1p(feats_atk[col].clip(lower=0))
                
        X_atk = scaler.transform(feats_atk[FEATURE_NAMES])
        if_atk = -if_model.score_samples(X_atk)
        ae_atk = ae_model.reconstruction_error(X_atk)
        return if_atk, ae_atk
    except Exception as e:
        print(f"[!] Optional attack reference loading failed ({e}); falling back to benign extrapolation.")
        return None, None

def calibrate_ensemble_anchors(X_scaled, if_model, ae_model, if_atk=None, ae_atk=None):
    """
    Calibrates lo, mid, hi score anchors for IF and AE.
    lo  = median benign score (maps to 0.0)
    mid = 99th percentile benign score (maps to 0.5)
    hi  = median attack score or extrapolated benign score (maps to 1.0)
    """
    if_benign = -if_model.score_samples(X_scaled)
    ae_benign = ae_model.reconstruction_error(X_scaled)
    
    calibration = {}
    score_pairs = {
        "if": (if_benign, if_atk),
        "ae": (ae_benign, ae_atk)
    }
    
    for name, (b_scores, a_scores) in score_pairs.items():
        lo = float(np.quantile(b_scores, 0.50))
        mid = float(np.quantile(b_scores, 0.99))
        
        if a_scores is not None and len(a_scores) > 0:
            hi = float(np.median(a_scores))
        else:
            hi = mid + (mid - lo) + 1e-6
            
        if mid <= lo:
            mid = lo + 1e-6
        if hi <= mid:
            hi = mid + (mid - lo) + 1e-6
            
        calibration[name] = {"lo": round(lo, 6), "mid": round(mid, 6), "hi": round(hi, 6)}
        print(f"[+] Calibrated '{name}' score anchors: lo={lo:.6f}, mid={mid:.6f}, hi={hi:.6f}")
        
    return calibration

def backup_existing_models():
    """Creates a timestamped backup of current project/models/ artifacts."""
    if not os.path.exists(MODELS_DIR):
        os.makedirs(MODELS_DIR, exist_ok=True)
        return None
        
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    backup_dir = os.path.abspath(os.path.join(MODELS_DIR, "..", f"models_backup_{timestamp}"))
    
    files_to_backup = [f for f in os.listdir(MODELS_DIR) if f.endswith(".pkl") or f.endswith(".json")]
    if not files_to_backup:
        return None
        
    os.makedirs(backup_dir, exist_ok=True)
    for fname in files_to_backup:
        src = os.path.join(MODELS_DIR, fname)
        dst = os.path.join(backup_dir, fname)
        shutil.copy2(src, dst)
        
    print(f"[+] Backed up {len(files_to_backup)} model files to {backup_dir}")
    database.add_log("INFO", f"Backed up current model artifacts to {backup_dir}")
    return backup_dir

def train_wireshark_baseline(pcap_dir: str = DEFAULT_PCAP_DIR, contamination: float = 0.01):
    """Main training routine."""
    start_time = time.time()
    try:
        database.init_db()
    except Exception:
        pass
    restrict_dissection()
    
    # 1. Backup existing model files
    backup_path = backup_existing_models()
    
    # 2. Ingest PCAPNG files & extract features
    df_flows, num_files, total_pkts, total_windows, total_flows = process_pcapng_files(pcap_dir)
    
    # 3. Preprocess features
    print("\n[+] Preprocessing feature matrix...")
    X_df, X_scaled, scaler, medians, skewed_cols = build_and_preprocess_features(df_flows)
    
    # 4. Train Isolation Forest (contamination = 0.01)
    print(f"[+] Training Isolation Forest on {total_flows:,} benign local flows (contamination={contamination})...")
    if_model = IsolationForest(n_estimators=100, contamination=contamination, random_state=42, n_jobs=-1)
    if_model.fit(X_scaled)
    
    # 5. Train Autoencoder on benign flows
    print(f"[+] Training Autoencoder (input_dim=10, latent_dim=4) on benign local flows...")
    ae_model = AutoencoderAnomalyDetector(input_dim=len(FEATURE_NAMES), latent_dim=4, random_state=42)
    ae_model.fit(X_scaled)
    
    # 6. Score Anchors Calibration
    if_atk, ae_atk = load_attack_reference_scores(scaler, medians, skewed_cols, if_model, ae_model)
    calibration = calibrate_ensemble_anchors(X_scaled, if_model, ae_model, if_atk, ae_atk)
    
    # 7. Persist Artifacts
    os.makedirs(MODELS_DIR, exist_ok=True)
    models_data = {
        "scaler.pkl": scaler,
        "isolation_forest.pkl": if_model,
        "autoencoder.pkl": ae_model,
        "meta.pkl": {
            "medians": medians.to_dict(),
            "skewed_cols": skewed_cols,
            "features": FEATURE_NAMES,
            "calibration": calibration,
            "training_source": "Wireshark_Local_Baseline",
            "training_flows": total_flows
        }
    }
    
    saved_locations = {}
    for name, obj in models_data.items():
        path = os.path.join(MODELS_DIR, name)
        with open(path, "wb") as f:
            pickle.dump(obj, f)
        saved_locations[name] = os.path.abspath(path)
        print(f"[+] Saved asset {name} -> {path}")
        
    training_duration = round(time.time() - start_time, 2)
    
    # 8. Generate Training Metrics Report
    report = {
        "dataset_source": os.path.abspath(pcap_dir),
        "number_of_pcapng_files_processed": num_files,
        "total_packets_processed": total_pkts,
        "total_30s_windows": total_windows,
        "total_flows_generated": total_flows,
        "training_execution_time_seconds": training_duration,
        "model_parameters": {
            "isolation_forest": {
                "n_estimators": 100,
                "contamination": contamination,
                "random_state": 42
            },
            "autoencoder": {
                "input_dim": 10,
                "latent_dim": 4,
                "activation": "relu",
                "max_iter": 100,
                "random_state": 42
            }
        },
        "score_calibration_anchors": calibration,
        "backup_directory": backup_path,
        "saved_model_locations": saved_locations,
        "feature_names": FEATURE_NAMES,
        "skewed_columns_transformed": skewed_cols
    }
    
    report_path = os.path.join(MODELS_DIR, "wireshark_training_report.json")
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n[+] Training report successfully generated: {report_path}")
    database.add_log("INFO", f"Wireshark baseline training completed in {training_duration}s across {total_flows} flows.")
    
    return report

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train anomaly models directly from Wireshark .pcapng captures.")
    parser.add_argument("--pcap-dir", default=DEFAULT_PCAP_DIR, help="Path to folder containing .pcapng files")
    parser.add_argument("--contamination", type=float, default=0.01, help="Isolation Forest contamination rate (default: 0.01)")
    args = parser.parse_args()
    
    train_wireshark_baseline(pcap_dir=args.pcap_dir, contamination=args.contamination)
