"""
Retrain the unsupervised Stage-1 ensemble (IsolationForest + Autoencoder) on
the LOCAL benign baseline captured from this network
(docs/LOCAL_BASELINE_DATASET_PLAN.md, Phase 4).

Differences from train_cicddos.py / train_models.py:
  - Scaler, Autoencoder AND IsolationForest are fit on local benign flows only
    (pcap_to_flows.py output). IF uses a small contamination (default 0.01)
    since the capture is assumed clean - there is no attack mix in training.
  - Calibration anchors: lo = median benign score, mid = 99th-percentile
    benign score (-> 0.5, i.e. ~1% benign FPR at the default threshold).
    hi (-> 1.0) is the median score of an attack REFERENCE set (CICDDoS2019
    training-split attack flows) run through the same feature path. Attack
    data is used ONLY to pick this anchor - inference stays unsupervised.

Back up project/models before running (plan Phase 4), e.g.:
    Copy-Item project\\models project\\models_backup_cicddos -Recurse

Usage:
    python train_local_baseline.py ^
        --benign "..\\..\\data\\local_baseline\\csv\\benign_train.csv" ^
        --val    "..\\..\\data\\local_baseline\\csv\\benign_val.csv"
"""
import os
import sys
import glob
import json
import pickle
import argparse

import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from preprocessing import (
    AutoencoderAnomalyDetector,
    build_alias_dictionary,
    map_to_canonical_schema,
    run_feature_engineering,
    extract_features,
)

MODELS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "models"))
DEFAULT_ATTACK_REF = os.path.abspath(os.path.join(
    os.path.dirname(__file__), "..", "..", "data", "CICDDos2019"))

FEATURE_NAMES = [
    "flow_byts_s", "flow_pkts_s", "fwd_bytes", "bwd_bytes", "total_pkts",
    "syn_flag", "rst_flag", "fin_flag", "flow_duration_s", "pkt_len_mean"
]

ALERT_THRESHOLD = 0.5


def build_features(df_raw: pd.DataFrame, medians=None, skewed_cols=None):
    """Same canonical-schema -> 10-feature path the backend runs at inference."""
    alias_dict = build_alias_dictionary()
    df_canonical, _ = map_to_canonical_schema(
        df_raw.drop(columns=["Label", "__source", "window_start", "source_pcap"],
                    errors="ignore"),
        alias_dict)
    df_canonical = run_feature_engineering(df_canonical)
    feats = extract_features(df_canonical)
    feats = feats.replace([np.inf, -np.inf], np.nan)

    if medians is None:
        medians = feats.median()
        skew = feats.skew()
        skewed_cols = skew[skew > 2].index.tolist()

    feats = feats.fillna(medians)
    for col in skewed_cols:
        feats[col] = np.log1p(feats[col].clip(lower=0))

    return feats[FEATURE_NAMES], medians, skewed_cols


def load_attack_reference(path: str, max_rows: int = 100000) -> pd.DataFrame:
    """Loads attack flows only, from a CICDDoS2019 parquet dir or a labeled CSV."""
    if os.path.isdir(path):
        files = sorted(glob.glob(os.path.join(path, "*-training.parquet")))
        if not files:
            raise FileNotFoundError(f"No *-training.parquet files in {path}")
        frames = []
        for f in files:
            df = pd.read_parquet(f)
            frames.append(df[df["Label"] != "Benign"])
        atk = pd.concat(frames, ignore_index=True)
    else:
        atk = pd.read_csv(path, engine="python")
        if "Label" in atk.columns:
            atk = atk[atk["Label"].astype(str).str.lower() != "benign"]
    if len(atk) > max_rows:
        atk = atk.sample(n=max_rows, random_state=42)
    print(f"[+] Attack reference: {len(atk)} flows from {path}")
    return atk


def calibrate(raw_scores, anchors):
    return np.interp(raw_scores, [anchors["lo"], anchors["mid"], anchors["hi"]],
                     [0.0, 0.5, 1.0])


def score_ensemble(if_model, ae_model, calibration, X_scaled):
    if_raw = -if_model.score_samples(X_scaled)
    ae_raw = ae_model.reconstruction_error(X_scaled)
    if_probs = np.nan_to_num(calibrate(if_raw, calibration["if"]), nan=0.0, posinf=1.0, neginf=0.0)
    ae_probs = np.nan_to_num(calibrate(ae_raw, calibration["ae"]), nan=0.0, posinf=1.0, neginf=0.0)
    return np.maximum(if_probs, ae_probs)


def main():
    ap = argparse.ArgumentParser(description="Train Stage-1 ensemble on the local benign baseline")
    ap.add_argument("--benign", required=True, help="benign_train.csv from pcap_to_flows.py")
    ap.add_argument("--val", default=None, help="benign_val.csv holdout for FP-rate check")
    ap.add_argument("--attack-ref", default=DEFAULT_ATTACK_REF,
                    help="Attack reference: CICDDoS2019 parquet dir or labeled CSV "
                         "(anchor calibration only)")
    ap.add_argument("--contamination", type=float, default=0.01)
    args = ap.parse_args()

    os.makedirs(MODELS_DIR, exist_ok=True)

    # ---------------- Fit on local benign baseline ----------------
    df_benign = pd.read_csv(args.benign)
    print(f"[+] Local benign training flows: {len(df_benign)}")

    X_benign_df, medians, skewed_cols = build_features(df_benign)
    print(f"[+] Feature matrix: {X_benign_df.shape}, log1p skewed cols: {skewed_cols}")

    scaler = StandardScaler()
    X_benign = scaler.fit_transform(X_benign_df)

    print(f"[+] Training IsolationForest on benign only (contamination={args.contamination})...")
    if_model = IsolationForest(n_estimators=100, contamination=args.contamination,
                               random_state=42, n_jobs=-1)
    if_model.fit(X_benign)

    print("[+] Training Autoencoder on benign only...")
    ae_model = AutoencoderAnomalyDetector(input_dim=len(FEATURE_NAMES), latent_dim=4,
                                          random_state=42)
    ae_model.fit(X_benign)

    # ---------------- Calibration anchors ----------------
    df_attack = load_attack_reference(args.attack_ref)
    X_attack_df, _, _ = build_features(df_attack, medians=medians, skewed_cols=skewed_cols)
    X_attack = scaler.transform(X_attack_df)

    calibration = {}
    raw = {
        "if": (-if_model.score_samples(X_benign), -if_model.score_samples(X_attack)),
        "ae": (ae_model.reconstruction_error(X_benign), ae_model.reconstruction_error(X_attack)),
    }
    for name, (benign_scores, attack_scores) in raw.items():
        lo = float(np.quantile(benign_scores, 0.50))
        mid = float(np.quantile(benign_scores, 0.99))
        hi = float(np.median(attack_scores))
        if mid <= lo:
            mid = lo + 1e-6
        if hi <= mid:
            # Cross-domain attack reference scores inside the local benign
            # tail (its flows are not shaped by our 30s-window pcap pipeline).
            # Fall back to benign-only extrapolation: hi = one more lo->mid
            # step past mid, i.e. a flow twice as far out as the benign 99th
            # percentile maps to score 1.0.
            print(f"[!] '{name}': attack-ref median ({hi:.4f}) <= benign q99 ({mid:.4f}) - "
                  f"using benign-extrapolated hi anchor instead")
            hi = mid + (mid - lo) + 1e-6
        calibration[name] = {"lo": lo, "mid": mid, "hi": hi}
        print(f"[+] Calibrated '{name}' anchors: lo={lo:.4f} mid={mid:.4f} hi={hi:.4f}")

    # ---------------- Persist in the exact backend layout ----------------
    assets = {
        "scaler.pkl": scaler,
        "isolation_forest.pkl": if_model,
        "autoencoder.pkl": ae_model,
        "meta.pkl": {
            "medians": medians.to_dict(),
            "skewed_cols": skewed_cols,
            "features": FEATURE_NAMES,
            "calibration": calibration,
        },
    }
    for name, obj in assets.items():
        path = os.path.join(MODELS_DIR, name)
        with open(path, "wb") as f:
            pickle.dump(obj, f)
        print(f"[+] Saved {path}")

    # ---------------- Validation ----------------
    report = {
        "baseline": "local",
        "threshold": ALERT_THRESHOLD,
        "train_flows": int(len(df_benign)),
        "contamination": args.contamination,
        "attack_ref": args.attack_ref,
        "calibration": calibration,
    }

    train_probs = score_ensemble(if_model, ae_model, calibration, X_benign)
    train_fp = float((train_probs >= ALERT_THRESHOLD).mean())
    report["train_fp_rate"] = train_fp
    print(f"[+] Benign TRAIN flagged at {ALERT_THRESHOLD}: {train_fp:.4f}")

    if args.val and os.path.exists(args.val):
        df_val = pd.read_csv(args.val)
        X_val_df, _, _ = build_features(df_val, medians=medians, skewed_cols=skewed_cols)
        X_val = scaler.transform(X_val_df)
        val_probs = score_ensemble(if_model, ae_model, calibration, X_val)
        val_fp = float((val_probs >= ALERT_THRESHOLD).mean())
        report["val_flows"] = int(len(df_val))
        report["val_fp_rate"] = val_fp
        print(f"[+] Benign VAL   flagged at {ALERT_THRESHOLD}: {val_fp:.4f} "
              f"({int((val_probs >= ALERT_THRESHOLD).sum())}/{len(df_val)} flows)  "
              f"[pass: < 0.02-0.05]")

    attack_probs = score_ensemble(if_model, ae_model, calibration, X_attack)
    attack_recall = float((attack_probs >= ALERT_THRESHOLD).mean())
    report["attack_ref_flows"] = int(len(df_attack))
    report["attack_ref_recall"] = attack_recall
    print(f"[+] Attack-ref recall at {ALERT_THRESHOLD}: {attack_recall:.4f}")

    report_path = os.path.join(MODELS_DIR, "local_baseline_metrics.json")
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"[+] Wrote metrics report to {report_path}")


if __name__ == "__main__":
    main()
