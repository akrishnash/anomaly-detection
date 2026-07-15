import os
import sys
import pickle
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest

# Add parent path to import correctly
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import database
from preprocessing import AutoencoderAnomalyDetector

MODELS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "models"))
ATTACK_CSV = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "data", "ctu13", "CTU13_Attack_Traffic.csv"))
NORMAL_CSV = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "data", "ctu13", "CTU13_Normal_Traffic.csv"))

FEATURE_NAMES = [
    "flow_byts_s", "flow_pkts_s", "fwd_bytes", "bwd_bytes", "total_pkts",
    "syn_flag", "rst_flag", "fin_flag", "flow_duration_s", "pkt_len_mean"
]

def load_and_preprocess_training_data(n_samples=5000):
    database.add_log("INFO", "Starting model training: loading CTU-13 training datasets...")
    
    if not os.path.exists(ATTACK_CSV) or not os.path.exists(NORMAL_CSV):
        err_msg = f"Training data files missing. Attack CSV: {ATTACK_CSV}, Normal CSV: {NORMAL_CSV}"
        database.add_log("ERROR", err_msg)
        raise FileNotFoundError(err_msg)
        
    # Read normal and attack datasets
    atk = pd.read_csv(ATTACK_CSV, nrows=n_samples * 2, engine="python")
    nrm = pd.read_csv(NORMAL_CSV, nrows=n_samples * 2, engine="python")
    
    # Sample to balance classes
    atk = atk.sample(n=min(n_samples, len(atk)), random_state=42)
    nrm = nrm.sample(n=min(n_samples, len(nrm)), random_state=42)
    
    atk["true_label"] = 1
    nrm["true_label"] = 0
    df = pd.concat([atk, nrm], ignore_index=True)
    
    # Map features
    X_df = pd.DataFrame()
    X_df["flow_byts_s"]     = pd.to_numeric(df["Flow Byts/s"], errors="coerce").fillna(0).clip(0)
    X_df["flow_pkts_s"]     = pd.to_numeric(df["Flow Pkts/s"], errors="coerce").fillna(0).clip(0)
    X_df["fwd_bytes"]       = pd.to_numeric(df["TotLen Fwd Pkts"], errors="coerce").fillna(0)
    X_df["bwd_bytes"]       = pd.to_numeric(df["TotLen Bwd Pkts"], errors="coerce").fillna(0)
    X_df["total_pkts"]      = (pd.to_numeric(df["Tot Fwd Pkts"], errors="coerce").fillna(0) +
                               pd.to_numeric(df["Tot Bwd Pkts"], errors="coerce").fillna(0))
    X_df["syn_flag"]        = pd.to_numeric(df["SYN Flag Cnt"], errors="coerce").fillna(0)
    X_df["rst_flag"]        = pd.to_numeric(df["RST Flag Cnt"], errors="coerce").fillna(0)
    X_df["fin_flag"]        = pd.to_numeric(df["FIN Flag Cnt"], errors="coerce").fillna(0)
    X_df["flow_duration_s"] = pd.to_numeric(df["Flow Duration"], errors="coerce").fillna(0) / 1e6
    X_df["pkt_len_mean"]    = pd.to_numeric(df["Pkt Len Mean"], errors="coerce").fillna(0)
    
    y = df["true_label"].values
    
    # Impute infs and NaNs
    X_df.replace([np.inf, -np.inf], np.nan, inplace=True)
    medians = X_df.median()
    X_df.fillna(medians, inplace=True)
    
    # Apply log1p transform to highly skewed variables to match comparison pipeline
    skew = X_df.skew()
    skewed_cols = skew[skew > 2].index.tolist()
    X_df[skewed_cols] = np.log1p(X_df[skewed_cols].clip(lower=0))
    
    # Keep standard medians for future inference imputations
    medians_dict = medians.to_dict()
    
    return X_df, y, medians_dict, skewed_cols

def train_and_save_models():
    os.makedirs(MODELS_DIR, exist_ok=True)
    
    try:
        X_df, y, medians, skewed_cols = load_and_preprocess_training_data()
        
        # 1. Fit Base Scaler
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X_df)
        
        # 2. Fit Isolation Forest
        contam = float(np.mean(y))
        if contam <= 0 or contam >= 1:
            contam = 0.45
            
        database.add_log("INFO", f"Training Isolation Forest model (contamination={contam:.4f})...")
        if_model = IsolationForest(n_estimators=100, contamination=contam, random_state=42, n_jobs=-1)
        if_model.fit(X_scaled)
        
        # 3. Fit Autoencoder on normal samples
        database.add_log("INFO", "Training Autoencoder model on normal traffic baseline...")
        X_normal_scaled = X_scaled[y == 0]
        if len(X_normal_scaled) == 0:
            X_normal_scaled = X_scaled
        ae_model = AutoencoderAnomalyDetector(input_dim=10, latent_dim=4, random_state=42)
        ae_model.fit(X_normal_scaled)

        # 4. Calibrate the unsupervised ensemble score anchors.
        # Each raw score (IF anomaly score, AE reconstruction error) is mapped to a
        # [0, 1] pseudo-probability with a piecewise-linear ramp anchored so that
        # the median normal flow scores ~0.0, the 99th percentile of normal flows
        # scores 0.5 (default alert threshold => ~1% benign false positives), and
        # the median attack flow scores 1.0. Labels are used ONLY here at training
        # time to pick anchors; inference is fully unsupervised.
        database.add_log("INFO", "Calibrating unsupervised ensemble score anchors...")
        calibration = {}
        score_sets = {
            "if": -if_model.score_samples(X_scaled),
            "ae": ae_model.reconstruction_error(X_scaled)
        }
        for name, scores in score_sets.items():
            normal_scores = scores[y == 0] if (y == 0).any() else scores
            attack_scores = scores[y == 1] if (y == 1).any() else scores
            lo = float(np.quantile(normal_scores, 0.50))
            mid = float(np.quantile(normal_scores, 0.99))
            hi = float(np.median(attack_scores))
            # Guarantee strictly increasing anchors for np.interp
            if mid <= lo:
                mid = lo + 1e-6
            if hi <= mid:
                hi = mid + (mid - lo) + 1e-6
            calibration[name] = {"lo": lo, "mid": mid, "hi": hi}
            database.add_log("INFO", f"Calibrated '{name}' score anchors: lo={lo:.4f}, mid={mid:.4f}, hi={hi:.4f}")

        # 5. Save Pickle Files
        models_data = {
            "scaler.pkl": scaler,
            "isolation_forest.pkl": if_model,
            "autoencoder.pkl": ae_model,
            "meta.pkl": {
                "medians": medians,
                "skewed_cols": skewed_cols,
                "features": FEATURE_NAMES,
                "calibration": calibration
            }
        }
        
        for name, obj in models_data.items():
            path = os.path.join(MODELS_DIR, name)
            with open(path, "wb") as f:
                pickle.dump(obj, f)
            database.add_log("INFO", f"Saved model asset to {path}")

        # Remove deprecated supervised-pipeline assets from previous versions
        for stale in ["xgboost.pkl", "aug_scaler.pkl"]:
            stale_path = os.path.join(MODELS_DIR, stale)
            if os.path.exists(stale_path):
                os.remove(stale_path)
                database.add_log("INFO", f"Removed deprecated model asset {stale_path}")
            
        database.add_log("INFO", "Baseline ML models training and persistence completed successfully.")
        return True
    except Exception as e:
        database.add_log("ERROR", f"Error during model training: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    train_and_save_models()
