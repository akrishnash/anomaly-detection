#!/usr/bin/env python3
"""
NSL-KDD Dataset Ingestion, Preprocessing, and Model Comparison
==============================================================
This script:
  1. Downloads KDDTrain+.txt and KDDTest+.txt from a public repository if not local.
  2. Loads and preprocesses the dataset (maps attack classes to binary,
     performs aligned One-Hot encoding of categorical columns, scales features).
  3. Trains and evaluates five models:
     - Isolation Forest (Unsupervised baseline)
     - Random Forest Classifier (Supervised bagging)
     - AdaBoost Classifier (Supervised boosting)
     - XGBoost Classifier (Supervised gradient boosting)
     - IF + XGBoost (Hybrid model with Isolation Forest score appended as feature)
  4. Saves the results to 'nsl_kdd_evaluation_metrics.csv'.
  5. Generates a comparative performance bar chart at 'graphs/nsl_kdd_comparison.png'.
"""

import os
import sys
import urllib.request
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec

from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest, RandomForestClassifier, AdaBoostClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_curve, auc, precision_recall_curve, average_precision_score
)
from xgboost import XGBClassifier

# ── Config ───────────────────────────────────────────────────────────────────
BASE_DIR    = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DATA_DIR    = os.path.join(BASE_DIR, "data", "nsl_kdd")
TRAIN_PATH  = os.path.join(DATA_DIR, "KDDTrain+.txt")
TEST_PATH   = os.path.join(DATA_DIR, "KDDTest+.txt")
OUT_CSV     = os.path.join(BASE_DIR, "research", "results", "nsl_kdd_evaluation_metrics.csv")
os.makedirs(os.path.dirname(OUT_CSV), exist_ok=True)
OUT_PNG     = os.path.join(BASE_DIR, "docs", "graphs", "nsl_kdd_comparison.png")

TRAIN_URL   = "https://raw.githubusercontent.com/jmnwong/NSL-KDD-Dataset/master/KDDTrain%2B.txt"
TEST_URL    = "https://raw.githubusercontent.com/jmnwong/NSL-KDD-Dataset/master/KDDTest%2B.txt"

# NSL-KDD standard column names (43 columns)
COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", 
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", 
    "logged_in", "num_compromised", "root_shell", "su_attempted", 
    "num_root", "num_file_creations", "num_shells", "num_access_files", 
    "num_outbound_cmds", "is_host_login", "is_guest_login", "count", 
    "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate", 
    "srv_rerror_rate", "same_srv_rate", "diff_srv_rate", 
    "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count", 
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate", 
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate", 
    "dst_host_serror_rate", "dst_host_srv_serror_rate", 
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "label", "difficulty"
]

# ── Step 1: Download Datasets ─────────────────────────────────────────────────
def download_datasets():
    os.makedirs(DATA_DIR, exist_ok=True)
    
    if not os.path.exists(TRAIN_PATH):
        print(f"[*] Downloading KDDTrain+.txt from {TRAIN_URL}...")
        try:
            urllib.request.urlretrieve(TRAIN_URL, TRAIN_PATH)
            print("[+] Train dataset downloaded successfully.")
        except Exception as e:
            sys.exit(f"[-] Failed to download train dataset: {e}")
    else:
        print("[*] KDDTrain+.txt already exists locally.")

    if not os.path.exists(TEST_PATH):
        print(f"[*] Downloading KDDTest+.txt from {TEST_URL}...")
        try:
            urllib.request.urlretrieve(TEST_URL, TEST_PATH)
            print("[+] Test dataset downloaded successfully.")
        except Exception as e:
            sys.exit(f"[-] Failed to download test dataset: {e}")
    else:
        print("[*] KDDTest+.txt already exists locally.")

# ── Step 2: Load and Preprocess ───────────────────────────────────────────────
def load_and_preprocess():
    print("[*] Loading datasets...")
    train_df = pd.read_csv(TRAIN_PATH, header=None, names=COLUMNS)
    test_df = pd.read_csv(TEST_PATH, header=None, names=COLUMNS)
    
    print(f"    Raw Train shape: {train_df.shape}")
    print(f"    Raw Test shape : {test_df.shape}")
    
    # 1. Map target label (normal -> 0, any attack type -> 1)
    train_df["true_label"] = train_df["label"].apply(lambda x: 0 if str(x).strip().lower() == "normal" else 1)
    test_df["true_label"] = test_df["label"].apply(lambda x: 0 if str(x).strip().lower() == "normal" else 1)
    
    # 2. Drop the original label and the difficulty columns
    train_df.drop(columns=["label", "difficulty"], errors="ignore", inplace=True)
    test_df.drop(columns=["label", "difficulty"], errors="ignore", inplace=True)
    
    # 3. Identify categorical and numerical columns
    categorical_cols = ["protocol_type", "service", "flag"]
    numerical_cols = [c for c in train_df.columns if c not in categorical_cols and c != "true_label"]
    
    # 4. Handle missing/infinite values using Train medians
    medians = train_df[numerical_cols].median()
    for df in (train_df, test_df):
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        df.fillna(medians, inplace=True)
        
    # 5. Log1p transform highly skewed columns in training set (skew > 2)
    skew = train_df[numerical_cols].skew()
    skewed_cols = skew[skew > 2].index.tolist()
    print(f"    Applying log1p transform on {len(skewed_cols)} skewed columns...")
    for df in (train_df, test_df):
        df[skewed_cols] = np.log1p(df[skewed_cols].clip(lower=0))
    
    # 6. One-Hot encoding of categorical columns
    # We concatenate temporary to align the dummy columns perfectly across train and test
    n_train = len(train_df)
    combined = pd.concat([train_df, test_df], ignore_index=True)
    combined_encoded = pd.get_dummies(combined, columns=categorical_cols, dtype=float)
    
    train_encoded = combined_encoded.iloc[:n_train].copy().reset_index(drop=True)
    test_encoded = combined_encoded.iloc[n_train:].copy().reset_index(drop=True)
    
    X_train = train_encoded.drop(columns=["true_label"])
    y_train = train_encoded["true_label"].values
    
    X_test = test_encoded.drop(columns=["true_label"])
    y_test = test_encoded["true_label"].values
    
    print(f"    Encoded features count: {X_train.shape[1]}")
    
    # 7. Scale features using Train statistics
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    X_train_scaled_df = pd.DataFrame(X_train_scaled, columns=X_train.columns)
    X_test_scaled_df = pd.DataFrame(X_test_scaled, columns=X_test.columns)
    
    return X_train_scaled_df, y_train, X_test_scaled_df, y_test

# ── Step 3: Evaluation Metrics Helper ─────────────────────────────────────────
def calculate_metrics(y_true, y_pred, y_prob=None):
    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    
    if y_prob is not None:
        fpr, tpr, _ = roc_curve(y_true, y_prob)
        roc_auc = auc(fpr, tpr)
        precision, recall_val, _ = precision_recall_curve(y_true, y_prob)
        pr_auc = auc(recall_val, precision)
    else:
        roc_auc = 0.5
        pr_auc = 0.5
        
    return acc, prec, rec, f1, roc_auc, pr_auc

# ── Step 4: Main Ingestion & Training Pipeline ────────────────────────────────
def main():
    print("=" * 80)
    print("                 NSL-KDD MODEL COMPARISON & TRAINING PIPELINE")
    print("=" * 80)
    
    # Download and load
    download_datasets()
    X_train, y_train, X_test, y_test = load_and_preprocess()
    
    results = []
    
    # 1. Isolation Forest (Unsupervised Baseline)
    print("\n[*] Training Isolation Forest (Unsupervised)...")
    contam = np.mean(y_train)  # match actual training label ratio
    if_model = IsolationForest(n_estimators=100, contamination=contam, random_state=42, n_jobs=-1)
    if_model.fit(X_train)
    
    # Predict (-1 is anomaly, 1 is normal)
    train_raw_preds = if_model.predict(X_train)
    test_raw_preds = if_model.predict(X_test)
    
    # Map back to 0 (normal) and 1 (anomaly)
    y_pred_if = np.where(test_raw_preds == -1, 1, 0)
    
    # Get scores for AUCs (score_samples returns negative anomaly score, negate it so higher is more anomalous)
    y_prob_if = -if_model.score_samples(X_test)
    
    acc, prec, rec, f1, roc_auc, pr_auc = calculate_metrics(y_test, y_pred_if, y_prob_if)
    results.append({
        "Model": "Isolation Forest",
        "Accuracy": acc, "Precision": prec, "Recall": rec, "F1-Score": f1, "ROC-AUC": roc_auc, "PR-AUC": pr_auc
    })
    print(f"    IF F1-Score: {f1:.4f} | Recall: {rec:.4f} | Precision: {prec:.4f}")
    
    # 2. Random Forest (Supervised)
    print("\n[*] Training Random Forest (Supervised)...")
    rf_model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    rf_model.fit(X_train, y_train)
    y_pred_rf = rf_model.predict(X_test)
    y_prob_rf = rf_model.predict_proba(X_test)[:, 1]
    
    acc, prec, rec, f1, roc_auc, pr_auc = calculate_metrics(y_test, y_pred_rf, y_prob_rf)
    results.append({
        "Model": "Random Forest",
        "Accuracy": acc, "Precision": prec, "Recall": rec, "F1-Score": f1, "ROC-AUC": roc_auc, "PR-AUC": pr_auc
    })
    print(f"    RF F1-Score: {f1:.4f} | Recall: {rec:.4f} | Precision: {prec:.4f}")
    
    # 3. AdaBoost (Supervised)
    print("\n[*] Training AdaBoost (Supervised)...")
    ada_model = AdaBoostClassifier(n_estimators=100, random_state=42)
    ada_model.fit(X_train, y_train)
    y_pred_ada = ada_model.predict(X_test)
    y_prob_ada = ada_model.predict_proba(X_test)[:, 1]
    
    acc, prec, rec, f1, roc_auc, pr_auc = calculate_metrics(y_test, y_pred_ada, y_prob_ada)
    results.append({
        "Model": "AdaBoost",
        "Accuracy": acc, "Precision": prec, "Recall": rec, "F1-Score": f1, "ROC-AUC": roc_auc, "PR-AUC": pr_auc
    })
    print(f"    AdaBoost F1-Score: {f1:.4f} | Recall: {rec:.4f} | Precision: {prec:.4f}")
    
    # 4. XGBoost (Supervised)
    print("\n[*] Training XGBoost (Supervised)...")
    xgb_model = XGBClassifier(n_estimators=100, max_depth=6, learning_rate=0.1, random_state=42, n_jobs=-1, eval_metric="logloss")
    xgb_model.fit(X_train, y_train)
    y_pred_xgb = xgb_model.predict(X_test)
    y_prob_xgb = xgb_model.predict_proba(X_test)[:, 1]
    
    acc, prec, rec, f1, roc_auc, pr_auc = calculate_metrics(y_test, y_pred_xgb, y_prob_xgb)
    results.append({
        "Model": "XGBoost",
        "Accuracy": acc, "Precision": prec, "Recall": rec, "F1-Score": f1, "ROC-AUC": roc_auc, "PR-AUC": pr_auc
    })
    print(f"    XGBoost F1-Score: {f1:.4f} | Recall: {rec:.4f} | Precision: {prec:.4f}")
    
    # 5. IF + XGBoost (Hybrid)
    print("\n[*] Training IF + XGBoost (Hybrid)...")
    
    # Generate continuous anomaly scores for both splits
    tr_if_scores = -if_model.score_samples(X_train)
    te_if_scores = -if_model.score_samples(X_test)
    
    # Append to features
    X_train_aug = X_train.copy()
    X_train_aug["if_anomaly_score"] = tr_if_scores
    X_test_aug = X_test.copy()
    X_test_aug["if_anomaly_score"] = te_if_scores
    
    # Re-scale augmented features
    aug_scaler = StandardScaler()
    X_train_aug_scaled = aug_scaler.fit_transform(X_train_aug)
    X_test_aug_scaled = aug_scaler.transform(X_test_aug)
    
    # Train hybrid classifier
    xgb_hybrid = XGBClassifier(n_estimators=100, max_depth=6, learning_rate=0.1, random_state=42, n_jobs=-1, eval_metric="logloss")
    xgb_hybrid.fit(X_train_aug_scaled, y_train)
    
    y_pred_hyb = xgb_hybrid.predict(X_test_aug_scaled)
    y_prob_hyb = xgb_hybrid.predict_proba(X_test_aug_scaled)[:, 1]
    
    acc, prec, rec, f1, roc_auc, pr_auc = calculate_metrics(y_test, y_pred_hyb, y_prob_hyb)
    results.append({
        "Model": "IF + XGBoost (Hybrid)",
        "Accuracy": acc, "Precision": prec, "Recall": rec, "F1-Score": f1, "ROC-AUC": roc_auc, "PR-AUC": pr_auc
    })
    print(f"    Hybrid F1-Score: {f1:.4f} | Recall: {rec:.4f} | Precision: {prec:.4f}")
    
    # ── Step 5: Save Results ──────────────────────────────────────────────────
    df_res = pd.DataFrame(results)
    df_res.to_csv(OUT_CSV, index=False)
    print(f"\n[+] Saved metrics comparison to {OUT_CSV}")
    
    # ── Step 6: Visualization ─────────────────────────────────────────────────
    print("[*] Generating metrics visualization...")
    os.makedirs(os.path.dirname(OUT_PNG), exist_ok=True)
    
    metrics_to_plot = ["Accuracy", "Precision", "Recall", "F1-Score", "ROC-AUC"]
    models = [r["Model"] for r in results]
    
    x = np.arange(len(models))
    width = 0.15
    
    fig, ax = plt.subplots(figsize=(10, 6), facecolor="#f8f9fa")
    
    # Warm, premium color palette matching our design guidelines
    colors = ["#4A90E2", "#50E3C2", "#F5A623", "#E35B5B", "#9013FE"]
    
    for i, metric in enumerate(metrics_to_plot):
        values = [r[metric] for r in results]
        ax.bar(x + i * width, values, width, label=metric, color=colors[i], edgecolor="black", linewidth=0.7)
        
    ax.set_title("NSL-KDD Model Comparison (Test Set)", fontsize=14, fontweight="bold", pad=15)
    ax.set_xticks(x + width * 2)
    ax.set_xticklabels(models, fontweight="semibold")
    ax.set_ylabel("Score", fontsize=12, fontweight="semibold")
    ax.set_ylim(0, 1.15)
    ax.grid(axis='y', linestyle='--', alpha=0.5)
    ax.legend(loc='upper right', frameon=True, facecolor="white", edgecolor="#ddd")
    
    # Add values on top of bars
    for idx, rects in enumerate(ax.containers):
        for rect in rects:
            height = rect.get_height()
            ax.annotate(f"{height:.2f}",
                        xy=(rect.get_x() + rect.get_width() / 2, height),
                        xytext=(0, 3),  # 3 points vertical offset
                        textcoords="offset points",
                        ha='center', va='bottom', fontsize=7, alpha=0.8)
            
    plt.tight_layout()
    plt.savefig(OUT_PNG, dpi=300)
    plt.close()
    print(f"[+] Saved comparison plot to {OUT_PNG}")
    print("=" * 80)
    print("                             PIPELINE RUN SUCCESSFULLY!")
    print("=" * 80)

if __name__ == "__main__":
    main()
