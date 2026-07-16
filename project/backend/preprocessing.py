import os
import sys
import pickle
import numpy as np
import pandas as pd
from sklearn.neural_network import MLPRegressor

# Directory containing the baseline model assets
MODELS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "models"))

# Global model/scaler caches
_scaler = None
_meta = None
_autoencoder = None

class AutoencoderAnomalyDetector:
    """
    Unsupervised Autoencoder using scikit-learn's MLPRegressor.
    
    Why Autoencoders are used:
    An Autoencoder compresses input data into a lower-dimensional latent space
    and attempts to reconstruct it. Because it is trained primarily on normal
    patterns, anomalous data (which diverges from normal patterns) will produce
    high reconstruction error. This error serves as an unsupervised anomaly score.
    """
    def __init__(self, input_dim=10, latent_dim=4, random_state=42):
        self.input_dim = input_dim
        self.latent_dim = latent_dim
        # Single hidden layer acts as the bottle-neck (latent representation)
        self.model = MLPRegressor(
            hidden_layer_sizes=(latent_dim,),
            activation='relu',
            max_iter=100,
            random_state=random_state,
            early_stopping=True,
            validation_fraction=0.1
        )
        
    def fit(self, X):
        # Target is the input itself (unsupervised self-reconstruction)
        self.model.fit(X, X)
        return self
        
    def reconstruction_error(self, X):
        try:
            X_pred = self.model.predict(X)
            # Calculate Mean Squared Error row-wise
            return np.mean((X - X_pred) ** 2, axis=1)
        except Exception as e:
            print(f"[-] Autoencoder reconstruction score calculation failed: {e}", file=sys.stderr)
            return np.zeros(len(X))

def load_preprocessor_assets():
    """Loads scaler, metadata, and Autoencoder assets from disk."""
    global _scaler, _meta, _autoencoder
    if _scaler is not None and _meta is not None:
        return _scaler, _meta, _autoencoder
        
    scaler_path = os.path.join(MODELS_DIR, "scaler.pkl")
    meta_path = os.path.join(MODELS_DIR, "meta.pkl")
    ae_path = os.path.join(MODELS_DIR, "autoencoder.pkl")
    
    if not os.path.exists(scaler_path) or not os.path.exists(meta_path):
        raise FileNotFoundError("Preprocessor assets missing. Please run model training first.")
        
    with open(scaler_path, "rb") as f:
        _scaler = pickle.load(f)
        
    with open(meta_path, "rb") as f:
        _meta = pickle.load(f)
        
    if os.path.exists(ae_path):
        with open(ae_path, "rb") as f:
            _autoencoder = pickle.load(f)
            
    return _scaler, _meta, _autoencoder

def normalize_columns(columns: list) -> list:
    """
    Standardizes raw column names to prevent mismatched key lookups.
    - Converts to lowercase.
    - Strips leading and trailing whitespaces.
    - Replaces spaces, hyphens, dots, and slashes with underscores.
    """
    normalized = []
    for col in columns:
        if not isinstance(col, str):
            col = str(col)
        norm = col.strip().lower()
        norm = norm.replace(" ", "_").replace("-", "_").replace(".", "_").replace("/", "_")
        normalized.append(norm)
    return normalized

def build_alias_dictionary() -> dict:
    """
    Maps canonical network flow feature names to their potential dataset column aliases.
    
    1. WHY CANONICAL SCHEMAS ARE USED:
       Different network flow datasets (e.g., CICIDS2017, UNSW-NB15, ToN-IoT, CSE-CIC-IDS2018) or live
       packet captures report flow metrics with highly inconsistent column names (e.g. "Source IP",
       "src_ip", "ip.src", "srcip"). Rather than customizing downstream feature engineering, scaling,
       and models for each dataset, we convert every incoming schema into a single, standardized "Canonical Schema".
       This completely decouples our ML pipeline from the underlying datasets. Adding support for a new
       dataset format only requires updating this alias dictionary rather than modifying the pipeline code.
    
    2. HOW ALIAS DETECTION WORKS:
       Before matching, all raw column names from the uploaded CSV are normalized (converted to lowercase,
       trimmed of whitespace, and characters like spaces, hyphens, and dots replaced with underscores).
       We then search through this alias dictionary for candidate matches. By normalizing both the keys/aliases
       and the source columns, matching is extremely robust to casing, spacing, dots, and hyphens.
    """
    return {
        "src_ip": ["source_ip", "src_ip", "srcip", "ip_src", "ip.src", "sourceip", "src", "source"],
        "dst_ip": ["destination_ip", "dst_ip", "dstip", "ip_dst", "ip.dst", "destinationip", "dst", "destination"],
        "src_port": ["source_port", "src_port", "srcport", "port_src", "port.src", "sourceport", "sport", "src_prt", "source_prt"],
        "dst_port": ["destination_port", "dst_port", "dstport", "port_dst", "port.dst", "destinationport", "dport", "dst_prt", "destination_prt"],
        "protocol": ["protocol", "proto", "prot", "prtcl", "protocol_type"],
        "duration": ["duration", "flow_duration", "flow_duration_s", "flowduration", "td", "duration_s", "flow.duration", "session_duration", "session_dur"],
        "packets": ["packets", "total_packets", "tot_pkts", "total_pkts", "total_fwd_packets", "total_backward_packets", "pkt_count", "total.packets"],
        "bytes": ["bytes", "total_bytes", "tot_bytes", "fwd_bytes", "bwd_bytes", "totlen_fwd_pkts", "totlen_bwd_pkts", "total_fwd_bytes", "total_backward_bytes", "byt_count", "total.bytes", "network_packet_size", "packet_size", "fwd_packets_length_total", "total_length_of_fwd_packets"],
        "packet_rate": ["packet_rate", "flow_pkts_s", "flow_packets_s", "packets_per_second", "packetrate", "flow_packets_per_second", "pkt_rate", "packet.rate"],
        "byte_rate": ["byte_rate", "flow_byts_s", "flow_bytes_s", "bytes_per_second", "byterate", "flow_bytes_per_second", "byt_rate", "byte.rate"],
        "avg_packet_size": ["avg_packet_size", "pkt_len_mean", "average_packet_size", "mean_packet_length", "avg_pkt_len", "avg_pkt_size", "pkt_size_avg", "packet_size_mean", "average.packet.size"],
        "syn_count": ["syn_count", "syn_flag_cnt", "syn_flag", "syn_count", "syn_flags", "syn_flag_count", "syn_flags_count"],
        "ack_count": ["ack_count", "ack_flag_cnt", "ack_flag", "ack_count", "ack_flags", "ack_flag_count", "ack_flags_count"],
        "rst_count": ["rst_count", "rst_flag_cnt", "rst_flag", "rst_count", "rst_flags", "rst_flag_count", "rst_flags_count"],
        "fin_count": ["fin_count", "fin_flag_cnt", "fin_flag", "fin_count", "fin_flags", "fin_flag_count", "fin_flags_count"],
        "flow_id": ["flow_id", "flowid", "id", "flow_identifier", "session_id"],
        "timestamp": ["timestamp", "time", "ts", "epoch", "tstamp"],
        
        # Extra helper keys to keep fwd and bwd bytes in the canonical schema for feature extraction
        # (includes CICDDoS2019 parquet spellings: "Fwd/Bwd Packets Length Total",
        #  "Total Length of Fwd/Bwd Packets", "Subflow Fwd/Bwd Bytes")
        "fwd_bytes": ["fwd_bytes", "totlen_fwd_pkts", "total_fwd_pkts", "total_fwd_bytes",
                      "fwd_packets_length_total", "total_length_of_fwd_packets", "subflow_fwd_bytes"],
        "bwd_bytes": ["bwd_bytes", "totlen_bwd_pkts", "total_bwd_pkts", "total_backward_bytes",
                      "bwd_packets_length_total", "total_length_of_bwd_packets", "subflow_bwd_bytes"],
        "fwd_packets": ["fwd_packets", "tot_fwd_pkts", "total_fwd_packets", "fwd_pkts"],
        "bwd_packets": ["bwd_packets", "tot_bwd_pkts", "total_backward_packets", "bwd_pkts"]
    }

def map_to_canonical_schema(df: pd.DataFrame, alias_dict: dict) -> tuple[pd.DataFrame, list[str]]:
    """
    Maps raw DataFrame column names to the canonical schema using alias dictionary.
    
    3. WHY THIS PREVENTS EMPTY DATAFRAMES:
       We explicitly initialize the target DataFrame using the source DataFrame's index:
           df_canonical = pd.DataFrame(index=df.index)
       This locks in the correct index structure and row counts immediately. If we were to construct the
       DataFrame dynamically or drop columns without preserving the index, any missing feature lookup
       could result in an empty DataFrame or misaligned rows.
    
    4. WHY STANDARD SCALER WILL NO LONGER RECEIVE AN EMPTY DATASET:
       When a canonical feature cannot be mapped from the source CSV, instead of raising an exception or
       omitting rows, we dynamically create the column and populate it with a sensible default value
       (e.g., 0.0 or "TCP"). This maintains the dimensional shape and row index alignment.
       Additionally, any NaNs or Infinities are cleaned and imputed using training-set medians.
       This ensures the final array passed to `scaler.transform()` has the exact shape (n_samples, 10),
       meaning the StandardScaler never receives empty/null inputs.
    """
    # Normalize raw columns for lookup
    raw_normalized_cols = normalize_columns(df.columns)
    col_mapping = dict(zip(raw_normalized_cols, df.columns))
    
    # Initialize using the raw dataset index to prevent empty DataFrames
    df_canonical = pd.DataFrame(index=df.index)
    
    # Sensible default values for missing columns
    defaults = {
        "src_ip": "192.168.1.X",
        "dst_ip": "10.0.0.X",
        "src_port": 0,
        "dst_port": 0,
        "protocol": "TCP",
        "duration": 0.0,
        "packets": 0,
        "bytes": 0,
        "packet_rate": 0.0,
        "byte_rate": 0.0,
        "avg_packet_size": 0.0,
        "syn_count": 0,
        "ack_count": 0,
        "rst_count": 0,
        "fin_count": 0,
        "flow_id": "",
        "timestamp": 0.0,
        "fwd_bytes": 0,
        "bwd_bytes": 0
    }
    
    missing_features = []
    
    # Map raw columns to the canonical schema
    for key, aliases in alias_dict.items():
        found = False
        candidates = [key] + aliases
        for cand in candidates:
            # Normalize candidate key
            cand_norm = normalize_columns([cand])[0]
            if cand_norm in col_mapping:
                orig_col = col_mapping[cand_norm]
                val = df[orig_col]
                # Scale duration from microseconds to seconds if from a microsecond-based column name
                if key == "duration" and (orig_col.strip().lower() in ["flow duration", "flow_duration", "flow.duration", "flowduration"]):
                    val = val / 1e6
                df_canonical[key] = val
                found = True
                break
        if not found:
            df_canonical[key] = defaults.get(key, 0.0)
            missing_features.append(key)
            
    if missing_features:
        print(f"[Warning] Mapped missing features to defaults: {missing_features}", file=sys.stderr)
        try:
            import database
            database.add_log("WARNING", f"Missing canonical features mapped to defaults: {missing_features}")
        except Exception:
            pass
            
    return df_canonical, missing_features

def validate_schema(df_canonical: pd.DataFrame, missing_features: list = None):
    """
    Validates that core traffic flow metrics were successfully resolved.
    If ALL required canonical features cannot be constructed (i.e. all of them are missing from the uploaded CSV columns),
    or if all critical columns are completely zeroed (all defaults), we raise a ValueError.
    """
    required = ["duration", "packets", "bytes"]
    
    if missing_features is None:
        missing_features = []
        # Fallback: check if the column only contains 0, NaN, or defaults for all rows
        for col in required:
            if (df_canonical[col].fillna(0) == 0).all():
                missing_features.append(col)
                
    missing_required = [col for col in required if col in missing_features]
    
    # Check if all required metrics are completely zeroed/all defaults
    all_zero = True
    for col in required:
        if col not in missing_features:
            if not (df_canonical[col].fillna(0) == 0).all():
                all_zero = False
                break
                
    # We raise an error only if ALL required features are missing
    if len(missing_required) == len(required) or all_zero:
        cols_to_report = missing_required if missing_required else required
        raise ValueError(
            f"Unable to construct canonical schema. Missing required features: {cols_to_report}. "
            "The dataset must contain valid flow metrics (Duration, Packets, Bytes)."
        )

def run_feature_engineering(df_canonical: pd.DataFrame) -> pd.DataFrame:
    """
    Applies logical transformations to derive missing rates or averages.
    e.g. byte_rate = bytes / duration.
    """
    df = df_canonical.copy()
    
    # Safeguards for divisions
    duration_eps = df["duration"].fillna(0.0).apply(lambda d: max(float(d), 0.000001))
    packets_eps = df["packets"].fillna(0).apply(lambda p: max(int(p), 1))
    
    # Recalculate zeroed/missing rate statistics from base fields
    if "byte_rate" in df.columns:
        zeros_mask = (df["byte_rate"].fillna(0.0) == 0.0)
        df.loc[zeros_mask, "byte_rate"] = df.loc[zeros_mask, "bytes"] / duration_eps[zeros_mask]
        
    if "packet_rate" in df.columns:
        zeros_mask = (df["packet_rate"].fillna(0.0) == 0.0)
        df.loc[zeros_mask, "packet_rate"] = df.loc[zeros_mask, "packets"] / duration_eps[zeros_mask]
        
    if "avg_packet_size" in df.columns:
        zeros_mask = (df["avg_packet_size"].fillna(0.0) == 0.0)
        df.loc[zeros_mask, "avg_packet_size"] = df.loc[zeros_mask, "bytes"] / packets_eps[zeros_mask]
        
    return df

def extract_features(df_canonical: pd.DataFrame) -> pd.DataFrame:
    """Extracts the 10 core numerical features expected by the trained ML models."""
    df_feats = pd.DataFrame(index=df_canonical.index)
    
    df_feats["flow_byts_s"] = pd.to_numeric(df_canonical["byte_rate"], errors="coerce").fillna(0.0).clip(lower=0)
    df_feats["flow_pkts_s"] = pd.to_numeric(df_canonical["packet_rate"], errors="coerce").fillna(0.0).clip(lower=0)
    
    # Resolve forward/backward bytes fallbacks
    if "fwd_bytes" in df_canonical.columns and (df_canonical["fwd_bytes"] > 0).any():
        df_feats["fwd_bytes"] = pd.to_numeric(df_canonical["fwd_bytes"], errors="coerce").fillna(0.0)
    else:
        df_feats["fwd_bytes"] = pd.to_numeric(df_canonical["bytes"], errors="coerce").fillna(0.0) / 2.0
        
    if "bwd_bytes" in df_canonical.columns and (df_canonical["bwd_bytes"] > 0).any():
        df_feats["bwd_bytes"] = pd.to_numeric(df_canonical["bwd_bytes"], errors="coerce").fillna(0.0)
    else:
        df_feats["bwd_bytes"] = pd.to_numeric(df_canonical["bytes"], errors="coerce").fillna(0.0) / 2.0
        
    # Resolve total_pkts by summing forward and backward packets if available
    has_fwd_pkts = "fwd_packets" in df_canonical.columns and (df_canonical["fwd_packets"] > 0).any()
    has_bwd_pkts = "bwd_packets" in df_canonical.columns and (df_canonical["bwd_packets"] > 0).any()
    if has_fwd_pkts or has_bwd_pkts:
        fwd_p = pd.to_numeric(df_canonical.get("fwd_packets", 0.0), errors="coerce").fillna(0.0)
        bwd_p = pd.to_numeric(df_canonical.get("bwd_packets", 0.0), errors="coerce").fillna(0.0)
        df_feats["total_pkts"] = fwd_p + bwd_p
    else:
        df_feats["total_pkts"] = pd.to_numeric(df_canonical["packets"], errors="coerce").fillna(0.0)
    df_feats["syn_flag"] = pd.to_numeric(df_canonical["syn_count"], errors="coerce").fillna(0.0)
    df_feats["rst_flag"] = pd.to_numeric(df_canonical["rst_count"], errors="coerce").fillna(0.0)
    df_feats["fin_flag"] = pd.to_numeric(df_canonical["fin_count"], errors="coerce").fillna(0.0)
    df_feats["flow_duration_s"] = pd.to_numeric(df_canonical["duration"], errors="coerce").fillna(0.0).clip(lower=0)
    df_feats["pkt_len_mean"] = pd.to_numeric(df_canonical["avg_packet_size"], errors="coerce").fillna(0.0).clip(lower=0)
    
    return df_feats

def preprocess_dataset(df_raw: pd.DataFrame) -> tuple[np.ndarray, list[str], pd.DataFrame]:
    """
    Full pipeline to clean, map, validate, engineer, scale, and return features.
    
    StandardScaler Safeguards:
    By ensuring df_canonical matches df_raw's index, filling missing keys with defaults,
    and imputing NaNs/Infinities with training medians, we ensure that:
    1. The rows dimension of scaled features always matches the input dataset exactly.
    2. StandardScaler.transform() receives a robust dataset and never crashes on empty datasets or NaN inputs.
    """
    scaler, meta, _ = load_preprocessor_assets()
    medians = meta["medians"]
    skewed_cols = meta["skewed_cols"]
    feature_names = meta["features"]
    
    # 1. Normalize Column Names & Map to Canonical Feature Schema
    alias_dict = build_alias_dictionary()
    df_canonical, missing_features = map_to_canonical_schema(df_raw, alias_dict)
    
    # 2. Validate Canonical Schema
    validate_schema(df_canonical, missing_features)
    
    # 3. Feature Engineering
    df_canonical = run_feature_engineering(df_canonical)
    
    # 4. Extract ML Features
    df_model_feats = extract_features(df_canonical)
    
    # 5. Clean, Impute Infinities & NaNs (avoiding inplace DataFrame warnings)
    df_model_feats = df_model_feats.replace([np.inf, -np.inf], np.nan)
    for col in feature_names:
        if col not in df_model_feats.columns:
            df_model_feats[col] = medians.get(col, 0.0)
        df_model_feats[col] = df_model_feats[col].fillna(medians.get(col, 0.0))
        
    # Log transform skewed columns
    for col in skewed_cols:
        if col in df_model_feats.columns:
            df_model_feats[col] = np.log1p(df_model_feats[col].clip(lower=0))
            
    # Extract raw numpy array ordered correctly to match StandardScaler
    X_raw_ordered = df_model_feats[feature_names].values
    
    # 6. Scaling
    X_scaled = scaler.transform(X_raw_ordered)
    
    return X_scaled, feature_names, df_canonical

def preprocess_features(df_raw: pd.DataFrame) -> tuple[np.ndarray, list[str]]:
    """
    Compatibility wrapper matching the original API signature.
    Preprocesses the raw flow DataFrame and returns the scaled 10-feature array.
    """
    X_scaled, feature_names, _ = preprocess_dataset(df_raw)
    return X_scaled, feature_names

def compute_autoencoder_scores(X_scaled: np.ndarray) -> np.ndarray:
    """Computes the reconstruction error for scaled features using the saved Autoencoder."""
    _, _, autoencoder = load_preprocessor_assets()
    if autoencoder is None:
        return np.zeros(len(X_scaled))
    return autoencoder.reconstruction_error(X_scaled)
