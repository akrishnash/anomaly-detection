"""
Train the unsupervised two-stage Stage-1 ensemble (IsolationForest + Autoencoder)
on the CICDDoS2019 parquet dataset and evaluate on its held-out testing split.

Training split : data/CICDDos2019/*-training.parquet  (benign + attack flows)
Testing split  : data/CICDDos2019/*-testing.parquet   (includes attack types
                 never seen in training: DrDoS_DNS, DrDoS_NTP, DrDoS_SNMP,
                 TFTP, WebDDoS -> zero-day style evaluation)

The Autoencoder is fit on BENIGN (normal) flows only; the IsolationForest is
fit on the full training split. Labels are used only to pick calibration
anchors (same protocol as train_models.py) - inference stays unsupervised.

Saves scaler.pkl / isolation_forest.pkl / autoencoder.pkl / meta.pkl into
project/models in the exact format the backend expects, and writes the
evaluation metrics to project/models/cicddos_metrics.json.
"""
import os
import sys
import glob
import json
import pickle
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from preprocessing import (
    AutoencoderAnomalyDetector,
    build_alias_dictionary,
    map_to_canonical_schema,
    run_feature_engineering,
    extract_features,
)

DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "data", "CICDDos2019"))
MODELS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "models"))

FEATURE_NAMES = [
    "flow_byts_s", "flow_pkts_s", "fwd_bytes", "bwd_bytes", "total_pkts",
    "syn_flag", "rst_flag", "fin_flag", "flow_duration_s", "pkt_len_mean"
]

ALERT_THRESHOLD = 0.5


def load_split(split: str) -> pd.DataFrame:
    """Loads and concatenates all parquet files for a split ('training' or 'testing')."""
    files = sorted(glob.glob(os.path.join(DATA_DIR, f"*-{split}.parquet")))
    if not files:
        raise FileNotFoundError(f"No *-{split}.parquet files found in {DATA_DIR}")
    frames = []
    for f in files:
        df = pd.read_parquet(f)
        df["__source"] = os.path.basename(f).replace(f"-{split}.parquet", "")
        frames.append(df)
    out = pd.concat(frames, ignore_index=True)
    print(f"[+] Loaded {split} split: {len(out)} flows from {len(files)} files "
          f"({int((out['Label'] == 'Benign').sum())} benign / {int((out['Label'] != 'Benign').sum())} attack)")
    return out


def build_features(df_raw: pd.DataFrame, medians=None, skewed_cols=None):
    """
    Runs the same canonical-schema -> 10-feature path the backend uses at inference.
    On the training split (medians=None) it also derives the imputation medians and
    the list of skewed columns to log-transform; the testing split reuses them.
    """
    alias_dict = build_alias_dictionary()
    df_canonical, _ = map_to_canonical_schema(
        df_raw.drop(columns=["Label", "__source"], errors="ignore"), alias_dict
    )
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


def fit_calibration(if_scores, ae_scores, y):
    """Piecewise-linear anchors: median(normal)->0.0, q99(normal)->0.5, median(attack)->1.0."""
    calibration = {}
    for name, scores in {"if": if_scores, "ae": ae_scores}.items():
        normal_scores = scores[y == 0]
        attack_scores = scores[y == 1]
        lo = float(np.quantile(normal_scores, 0.50))
        mid = float(np.quantile(normal_scores, 0.99))
        hi = float(np.median(attack_scores))
        if mid <= lo:
            mid = lo + 1e-6
        if hi <= mid:
            hi = mid + (mid - lo) + 1e-6
        calibration[name] = {"lo": lo, "mid": mid, "hi": hi}
        print(f"[+] Calibrated '{name}' anchors: lo={lo:.4f} mid={mid:.4f} hi={hi:.4f}")
    return calibration


def calibrate(raw_scores, anchors):
    return np.interp(raw_scores, [anchors["lo"], anchors["mid"], anchors["hi"]], [0.0, 0.5, 1.0])


def score_ensemble(if_model, ae_model, calibration, X_scaled):
    if_raw = -if_model.score_samples(X_scaled)
    ae_raw = ae_model.reconstruction_error(X_scaled)
    if_probs = np.nan_to_num(calibrate(if_raw, calibration["if"]), nan=0.0, posinf=1.0, neginf=0.0)
    ae_probs = np.nan_to_num(calibrate(ae_raw, calibration["ae"]), nan=0.0, posinf=1.0, neginf=0.0)
    return np.maximum(if_probs, ae_probs)


def metrics_dict(y_true, y_pred):
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "n_flows": int(len(y_true)),
        "n_attack": int(y_true.sum()),
    }


def main():
    os.makedirs(MODELS_DIR, exist_ok=True)

    # ---------------- Training ----------------
    df_train = load_split("training")
    y_train = (df_train["Label"] != "Benign").astype(int).values

    X_train_df, medians, skewed_cols = build_features(df_train)
    print(f"[+] Feature matrix: {X_train_df.shape}, log1p-transformed skewed cols: {skewed_cols}")

    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train_df)

    contam = float(np.clip(np.mean(y_train), 0.01, 0.5))
    print(f"[+] Training IsolationForest on full training split (contamination={contam:.4f})...")
    if_model = IsolationForest(n_estimators=100, contamination=contam, random_state=42, n_jobs=-1)
    if_model.fit(X_train)

    print(f"[+] Training Autoencoder on benign (normal) flows only ({int((y_train == 0).sum())} flows)...")
    ae_model = AutoencoderAnomalyDetector(input_dim=len(FEATURE_NAMES), latent_dim=4, random_state=42)
    ae_model.fit(X_train[y_train == 0])

    print("[+] Calibrating ensemble score anchors on the training split...")
    if_train_raw = -if_model.score_samples(X_train)
    ae_train_raw = ae_model.reconstruction_error(X_train)
    calibration = fit_calibration(if_train_raw, ae_train_raw, y_train)

    # Persist in the exact layout the backend loads
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

    # ---------------- Evaluation on the testing split ----------------
    df_test = load_split("testing")
    y_test = (df_test["Label"] != "Benign").astype(int).values

    X_test_df, _, _ = build_features(df_test, medians=medians, skewed_cols=skewed_cols)
    X_test = scaler.transform(X_test_df)

    probs = score_ensemble(if_model, ae_model, calibration, X_test)
    y_pred = (probs >= ALERT_THRESHOLD).astype(int)

    overall = metrics_dict(y_test, y_pred)
    print()
    print("=" * 62)
    print("  CICDDoS2019 testing-split results (threshold = %.2f)" % ALERT_THRESHOLD)
    print("=" * 62)
    print(f"  Accuracy : {overall['accuracy']:.4f}")
    print(f"  Precision: {overall['precision']:.4f}")
    print(f"  Recall   : {overall['recall']:.4f}")
    print(f"  F1-score : {overall['f1']:.4f}")
    print(f"  Flows    : {overall['n_flows']} ({overall['n_attack']} attack)")

    # Per-file breakdown
    per_file = {}
    print("-" * 62)
    print(f"  {'file':<10} {'flows':>7} {'acc':>7} {'prec':>7} {'rec':>7} {'f1':>7}")
    for src in sorted(df_test["__source"].unique()):
        mask = (df_test["__source"] == src).values
        m = metrics_dict(y_test[mask], y_pred[mask])
        per_file[src] = m
        print(f"  {src:<10} {m['n_flows']:>7} {m['accuracy']:>7.4f} {m['precision']:>7.4f} {m['recall']:>7.4f} {m['f1']:>7.4f}")

    # Per-attack-type detection rate (recall); benign row shows false-positive rate
    per_label = {}
    print("-" * 62)
    print(f"  {'label':<14} {'flows':>8} {'detected':>9} {'rate':>8}")
    for label in sorted(df_test["Label"].unique()):
        mask = (df_test["Label"] == label).values
        detected = int(y_pred[mask].sum())
        rate = detected / mask.sum()
        tag = "FP-rate" if label == "Benign" else "recall"
        per_label[label] = {"flows": int(mask.sum()), "detected": detected, "rate": float(rate), "kind": tag}
        print(f"  {label:<14} {int(mask.sum()):>8} {detected:>9} {rate:>8.4f}  ({tag})")
    print("=" * 62)

    report = {
        "dataset": "CICDDoS2019",
        "threshold": ALERT_THRESHOLD,
        "train_flows": int(len(y_train)),
        "train_benign": int((y_train == 0).sum()),
        "overall": overall,
        "per_file": per_file,
        "per_label": per_label,
    }
    report_path = os.path.join(MODELS_DIR, "cicddos_metrics.json")
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"[+] Wrote metrics report to {report_path}")


if __name__ == "__main__":
    main()
