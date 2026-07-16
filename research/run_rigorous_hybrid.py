#!/usr/bin/env python3
"""
Rigorous Leakage-Free Hybrid Anomaly Detection & Comparison
============================================================
This script:
  1. Splits the CTU-13 dataset FIRST (60% Train, 20% Test, 20% Unseen holdout).
  2. Runs 5-Fold Cross Validation on the training set, fitting scaling and Isolation Forest ONLY on each training fold.
  3. Evaluates 5 models on the Test and Unseen splits:
     - Isolation Forest (Unsupervised)
     - Random Forest (Supervised)
     - AdaBoost (Supervised)
     - XGBoost (Supervised)
     - IF + XGBoost (Hybrid)
  4. Generates a confusion matrix for the Hybrid system.
  5. Computes TreeSHAP values and identifies/plots the top 10 features.
  6. Outputs evaluation metrics to 'evaluation_metrics_v2.csv'.
  7. Generates comparative visualizations.
"""

import os
import sys
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec

from sklearn.model_selection import train_test_split, StratifiedKFold
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest, RandomForestClassifier, AdaBoostClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_curve, auc, precision_recall_curve, average_precision_score,
    confusion_matrix
)
from xgboost import XGBClassifier
import shap

# ── Config ───────────────────────────────────────────────────────────────────
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
ATTACK_CSV = os.path.join(BASE_DIR, "data", "ctu13", "CTU13_Attack_Traffic.csv")
NORMAL_CSV = os.path.join(BASE_DIR, "data", "ctu13", "CTU13_Normal_Traffic.csv")
N_SAMPLE    = 10000         # Sample size per class (20,000 total flows)
OUT_CSV     = os.path.join(BASE_DIR, "research", "results", "evaluation_metrics_v2.csv")
os.makedirs(os.path.dirname(OUT_CSV), exist_ok=True)
OUT_CM      = os.path.join(BASE_DIR, "docs", "graphs", "hybrid_confusion_matrix.png")
OUT_SHAP    = os.path.join(BASE_DIR, "docs", "graphs", "hybrid_shap_top10.png")
OUT_COMP    = os.path.join(BASE_DIR, "docs", "graphs", "model_comparison_v2.png")

DROP_COLS   = {"Unnamed: 0", "Label"}

# ── Load and Preprocess ───────────────────────────────────────────────────────
def load_data() -> pd.DataFrame:
    for path in (ATTACK_CSV, NORMAL_CSV):
        if not os.path.exists(path):
            sys.exit(f"[-] Dataset file not found: {path}")

    print("[*] Loading datasets...")
    attack = pd.read_csv(ATTACK_CSV)
    normal = pd.read_csv(NORMAL_CSV)

    atk_s = attack.sample(n=min(N_SAMPLE, len(attack)), random_state=42).copy()
    nrm_s = normal.sample(n=min(N_SAMPLE, len(normal)), random_state=42).copy()
    
    atk_s["true_label"] = 1
    nrm_s["true_label"] = 0

    df = pd.concat([atk_s, nrm_s], ignore_index=True)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    return df

def preprocess_splits(X_tr: pd.DataFrame, X_te: pd.DataFrame, X_un: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Clean and preprocess train, test, and unseen splits using train-set-only statistics."""
    X_tr = X_tr.copy()
    X_te = X_te.copy()
    X_un = X_un.copy()
    
    # 1. Impute missing / infinite values using training medians
    medians = X_tr.median()
    for df in (X_tr, X_te, X_un):
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        df.fillna(medians, inplace=True)
        
    # 2. Log1p transform skewed features based on training skewness
    skew = X_tr.skew()
    skewed_cols = skew[skew > 2].index.tolist()
    for df in (X_tr, X_te, X_un):
        df[skewed_cols] = np.log1p(df[skewed_cols].clip(lower=0))
        
    return X_tr, X_te, X_un

def preprocess_fold(X_tr: pd.DataFrame, X_val: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Clean and preprocess fold train and validation splits using fold-train-only statistics."""
    X_tr = X_tr.copy()
    X_val = X_val.copy()
    
    # 1. Impute using fold train medians
    medians = X_tr.median()
    for df in (X_tr, X_val):
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        df.fillna(medians, inplace=True)
        
    # 2. Log1p based on fold train skewness
    skew = X_tr.skew()
    skewed_cols = skew[skew > 2].index.tolist()
    for df in (X_tr, X_val):
        df[skewed_cols] = np.log1p(df[skewed_cols].clip(lower=0))
        
    return X_tr, X_val

# ── Custom Plotting ──────────────────────────────────────────────────────────
def plot_confusion_matrix(cm, labels, filename):
    fig, ax = plt.subplots(figsize=(6, 5), facecolor="#f8f9fa")
    im = ax.imshow(cm, cmap=plt.cm.Blues, interpolation='nearest')
    ax.figure.colorbar(im, ax=ax)
    ax.set(xticks=np.arange(cm.shape[1]),
           yticks=np.arange(cm.shape[0]),
           xticklabels=labels, yticklabels=labels,
           title="Confusion Matrix: Hybrid System (Test Set)",
           ylabel="True Label",
           xlabel="Predicted Label")
    
    thresh = cm.max() / 2.
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            ax.text(j, i, format(cm[i, j], 'd'),
                    ha="center", va="center",
                    color="white" if cm[i, j] > thresh else "black",
                    fontweight="bold")
    fig.tight_layout()
    plt.savefig(filename, dpi=300, bbox_inches="tight")
    plt.close()

# ── Main Pipeline ─────────────────────────────────────────────────────────────
def main():
    print("=" * 80)
    print("        RIGOROUS LEAKAGE-FREE HYBRID ANOMALY DETECTION & COMPARISON")
    print("=" * 80)
    
    os.makedirs(os.path.join(BASE_DIR, "docs", "graphs"), exist_ok=True)
    
    # 1. Load and split raw data first (before any preprocessing)
    df = load_data()
    y = df["true_label"].values
    feat_cols = [c for c in df.columns if c not in DROP_COLS and c != "true_label"]
    X_raw = df[feat_cols].copy()
    
    # Three-way split: 60% Train, 20% Test, 20% Unseen holdout
    # We split FIRST to prevent any data leakage
    X_train_raw, X_temp_raw, y_train, y_temp = train_test_split(
        X_raw, y, test_size=0.40, random_state=42, stratify=y
    )
    X_test_raw, X_unseen_raw, y_test, y_unseen = train_test_split(
        X_temp_raw, y_temp, test_size=0.50, random_state=42, stratify=y_temp
    )
    
    print(f"[*] Splitting completed:")
    print(f"    Train size   : {len(X_train_raw):,} (60%)")
    print(f"    Test size    : {len(X_test_raw):,} (20%)")
    print(f"    Unseen size  : {len(X_unseen_raw):,} (20% holdout)")
    
    # 2. 5-Fold Cross Validation on Train Set (Pipeline Leakage-Free)
    print("\n[*] Performing 5-Fold Cross Validation (Leakage-Free Validation)...")
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_scores = []
    
    for fold, (train_idx, val_idx) in enumerate(skf.split(X_train_raw, y_train), 1):
        # Extract fold train and val raw splits
        X_fold_tr_raw = X_train_raw.iloc[train_idx].copy()
        X_fold_val_raw = X_train_raw.iloc[val_idx].copy()
        y_fold_tr, y_fold_val = y_train[train_idx], y_train[val_idx]
        
        # Preprocess fold splits cleanly
        X_fold_tr, X_fold_val = preprocess_fold(X_fold_tr_raw, X_fold_val_raw)
        
        # Scale fold features
        scaler = StandardScaler()
        X_fold_tr_sc = scaler.fit_transform(X_fold_tr)
        X_fold_val_sc = scaler.transform(X_fold_val)
        
        # Fit Isolation Forest ONLY on fold train features (Unsupervised representation)
        contam = np.mean(y_fold_tr)
        if_fold = IsolationForest(n_estimators=100, contamination=contam, random_state=42, n_jobs=-1)
        if_fold.fit(X_fold_tr_sc)
        
        # Generate fold scores (negate score_samples so higher is more anomalous)
        tr_scores = -if_fold.score_samples(X_fold_tr_sc)
        val_scores = -if_fold.score_samples(X_fold_val_sc)
        
        # Build augmented features
        X_fold_tr = X_fold_tr.copy()
        X_fold_val = X_fold_val.copy()
        X_fold_tr["if_anomaly_score"] = tr_scores
        X_fold_val["if_anomaly_score"] = val_scores
        
        # Scale augmented features
        aug_scaler = StandardScaler()
        X_fold_tr_aug = aug_scaler.fit_transform(X_fold_tr)
        X_fold_val_aug = aug_scaler.transform(X_fold_val)
        
        # Train XGBoost Classifier
        xgb_fold = XGBClassifier(n_estimators=100, max_depth=6, learning_rate=0.1,
                                 random_state=42, n_jobs=-1, eval_metric="logloss")
        xgb_fold.fit(X_fold_tr_aug, y_fold_tr)
        
        # Evaluate
        fold_preds = xgb_fold.predict(X_fold_val_aug)
        fold_f1 = f1_score(y_fold_val, fold_preds)
        cv_scores.append(fold_f1)
        print(f"    Fold {fold} F1-Score: {fold_f1:.4f}")
        
    print(f"[+] 5-Fold Cross Validation Mean F1-Score: {np.mean(cv_scores):.4f} (std: {np.std(cv_scores):.4f})")
    
    # 3. Train final models on Train split
    print("\n[*] Training final models on the entire Training split...")
    
    # Preprocess final splits based on Training Split statistics
    X_train_raw, X_test_raw, X_unseen_raw = preprocess_splits(X_train_raw, X_test_raw, X_unseen_raw)
    
    # Base Scaling
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train_raw)
    X_test_scaled = scaler.transform(X_test_raw)
    X_unseen_scaled = scaler.transform(X_unseen_raw)
    
    train_contamination = np.mean(y_train)
    
    # Fit Isolation Forest ONLY on Train split
    if_model = IsolationForest(n_estimators=150, contamination=train_contamination, random_state=42, n_jobs=-1)
    if_model.fit(X_train_scaled)
    
    # Generate scores (higher = more anomalous)
    tr_if_scores = -if_model.score_samples(X_train_scaled)
    te_if_scores = -if_model.score_samples(X_test_scaled)
    un_if_scores = -if_model.score_samples(X_unseen_scaled)
    
    # Build Augmented Datasets (Hybrid)
    X_train_aug_df = X_train_raw.copy()
    X_train_aug_df["if_anomaly_score"] = tr_if_scores
    
    X_test_aug_df = X_test_raw.copy()
    X_test_aug_df["if_anomaly_score"] = te_if_scores
    
    X_unseen_aug_df = X_unseen_raw.copy()
    X_unseen_aug_df["if_anomaly_score"] = un_if_scores
    
    # Scale Augmented
    aug_scaler = StandardScaler()
    X_train_aug = aug_scaler.fit_transform(X_train_aug_df)
    X_test_aug = aug_scaler.transform(X_test_aug_df)
    X_unseen_aug = aug_scaler.transform(X_unseen_aug_df)
    
    # Define comparison models
    models = {
        "Isolation Forest": None, # Handled separately since it is unsupervised
        "Random Forest":    RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1),
        "AdaBoost":         AdaBoostClassifier(random_state=42),
        "XGBoost":          XGBClassifier(n_estimators=100, random_state=42, n_jobs=-1, eval_metric="logloss"),
        "IF + XGBoost (Hybrid)": XGBClassifier(n_estimators=100, max_depth=6, learning_rate=0.1,
                                               random_state=42, n_jobs=-1, eval_metric="logloss")
    }
    
    # Train supervised base models
    models["Random Forest"].fit(X_train_scaled, y_train)
    models["AdaBoost"].fit(X_train_scaled, y_train)
    models["XGBoost"].fit(X_train_scaled, y_train)
    models["IF + XGBoost (Hybrid)"].fit(X_train_aug, y_train)
    
    # 4. Evaluation Loop on both Test set and Unseen Holdout Set
    print("\n[*] Evaluating all models...")
    eval_metrics = []
    
    for name, model in models.items():
        if name == "Isolation Forest":
            # Predict using optimal threshold from train
            train_threshold = np.percentile(tr_if_scores, train_contamination * 100)
            
            # Predict on Test
            test_preds = (te_if_scores >= train_threshold).astype(int)
            test_probs = te_if_scores
            
            # Predict on Unseen
            unseen_preds = (un_if_scores >= train_threshold).astype(int)
            unseen_probs = un_if_scores
        elif name == "IF + XGBoost (Hybrid)":
            test_preds = model.predict(X_test_aug)
            test_probs = model.predict_proba(X_test_aug)[:, 1]
            
            unseen_preds = model.predict(X_unseen_aug)
            unseen_probs = model.predict_proba(X_unseen_aug)[:, 1]
        else:
            test_preds = model.predict(X_test_scaled)
            test_probs = model.predict_proba(X_test_scaled)[:, 1]
            
            unseen_preds = model.predict(X_unseen_scaled)
            unseen_probs = model.predict_proba(X_unseen_scaled)[:, 1]
            
        # Compute metrics on Test Set
        acc_te = accuracy_score(y_test, test_preds)
        prec_te = precision_score(y_test, test_preds, zero_division=0)
        rec_te = recall_score(y_test, test_preds)
        f1_te = f1_score(y_test, test_preds)
        roc_auc_te = auc(roc_curve(y_test, test_probs)[0], roc_curve(y_test, test_probs)[1])
        pr_auc_te = average_precision_score(y_test, test_probs)
        
        # Compute metrics on Unseen Holdout Scenario
        acc_un = accuracy_score(y_unseen, unseen_preds)
        prec_un = precision_score(y_unseen, unseen_preds, zero_division=0)
        rec_un = recall_score(y_unseen, unseen_preds)
        f1_un = f1_score(y_unseen, unseen_preds)
        roc_auc_un = auc(roc_curve(y_unseen, unseen_probs)[0], roc_curve(y_unseen, unseen_probs)[1])
        pr_auc_un = average_precision_score(y_unseen, unseen_probs)
        
        eval_metrics.append({
            "Model": name,
            "Accuracy (Test)": acc_te,
            "Precision (Test)": prec_te,
            "Recall (Test)": rec_te,
            "F1-Score (Test)": f1_te,
            "ROC-AUC (Test)": roc_auc_te,
            "PR-AUC (Test)": pr_auc_te,
            "Accuracy (Unseen)": acc_un,
            "Precision (Unseen)": prec_un,
            "Recall (Unseen)": rec_un,
            "F1-Score (Unseen)": f1_un,
            "ROC-AUC (Unseen)": roc_auc_un,
            "PR-AUC (Unseen)": pr_auc_un
        })
        
        # Generate Confusion Matrix for the Hybrid system
        if name == "IF + XGBoost (Hybrid)":
            cm_test = confusion_matrix(y_test, test_preds)
            plot_confusion_matrix(cm_test, ["Normal (0)", "Attack (1)"], OUT_CM)
            print(f"[*] Generated Confusion Matrix plot: {OUT_CM}")
            
    # Format and save metrics to CSV
    metrics_df = pd.DataFrame(eval_metrics).round(4)
    metrics_df.to_csv(OUT_CSV, index=False, float_format="%.4f")
    print(f"[*] Saved comparative evaluation metrics to: {OUT_CSV}")
    
    # Print clean results table
    print("\n" + "=" * 80)
    print("                             FINAL EVALUATION RESULTS")
    print("=" * 80)
    print(metrics_df[["Model", "F1-Score (Test)", "ROC-AUC (Test)", "F1-Score (Unseen)", "ROC-AUC (Unseen)"]].to_string(index=False))
    print("=" * 80)

    # 5. SHAP Analysis: Identify top 10 features of Hybrid model
    print("\n[*] Applying SHAP on Hybrid Model to identify top 10 features...")
    # Wrap test augmented features in a DataFrame with names
    X_test_aug_df = pd.DataFrame(X_test_aug, columns=feat_cols + ["if_anomaly_score"])
    
    explainer = shap.TreeExplainer(models["IF + XGBoost (Hybrid)"])
    shap_vals = explainer(X_test_aug_df)
    
    # Calculate mean absolute SHAP value per feature
    mean_shap = np.abs(shap_vals.values).mean(axis=0)
    shap_df = pd.DataFrame({
        "Feature": feat_cols + ["if_anomaly_score"],
        "Mean_SHAP": mean_shap
    }).sort_values(by="Mean_SHAP", ascending=False).reset_index(drop=True)
    
    print("\n  Top 10 Features based on Mean Absolute SHAP Value:")
    print("  " + "-" * 55)
    for idx, row in shap_df.head(10).iterrows():
        print(f"   #{idx+1:02d}  {row['Feature']:<32} : {row['Mean_SHAP']:.4f}")
    print("  " + "-" * 55)
    
    # Plot top 10 SHAP features
    plt.figure(figsize=(9, 5), facecolor="#f8f9fa")
    top_10 = shap_df.head(10).iloc[::-1] # reverse for plotting bottom-up
    bars = plt.barh(top_10["Feature"], top_10["Mean_SHAP"], color="#2c3e50", edgecolor="none", height=0.6)
    
    # Add grid lines
    plt.grid(True, axis="x", linestyle="--", alpha=0.5, color="#bdc3c7")
    plt.xlabel("Mean Absolute SHAP Value (Impact on Model Output)", fontweight="semibold")
    plt.title("Top 10 Most Influential Features: Hybrid Anomaly Detection", fontsize=12, fontweight="bold", pad=15)
    
    # Annotate bar values
    for bar in bars:
        width = bar.get_width()
        plt.text(width + 0.005, bar.get_y() + bar.get_height()/2, f"{width:.4f}",
                 va="center", ha="left", fontsize=9, fontweight="semibold", color="#2c3e50")
                 
    plt.tight_layout()
    plt.savefig(OUT_SHAP, dpi=300, bbox_inches="tight")
    plt.close()
    print(f"[*] Saved SHAP Top 10 Features plot to: {OUT_SHAP}")
    
    # 6. Generate Comparative Bar Chart for all 5 models (on F1-Score)
    print("\n[*] Generating comparative performance visualization...")
    plt.rcParams.update({
        "font.family": "sans-serif",
        "font.size": 10,
        "axes.edgecolor": "#bdc3c7",
        "axes.linewidth": 0.8,
        "grid.color": "#ecf0f1",
        "grid.linewidth": 0.6
    })

    fig, ax = plt.subplots(figsize=(10, 6), facecolor="#f8f9fa")
    ax.set_facecolor("#ffffff")
    
    bar_width = 0.35
    model_names = metrics_df["Model"].values
    index = np.arange(len(model_names))
    
    # F1 Test and F1 Unseen
    rects1 = ax.bar(index - bar_width/2, metrics_df["F1-Score (Test)"].values, bar_width,
                    label="Test Split (F1-Score)", color="#3498db", edgecolor="#ffffff", linewidth=0.8)
    rects2 = ax.bar(index + bar_width/2, metrics_df["F1-Score (Unseen)"].values, bar_width,
                    label="Unseen Holdout (F1-Score)", color="#2ecc71", edgecolor="#ffffff", linewidth=0.8)
                    
    ax.set_xticks(index)
    ax.set_xticklabels(model_names, rotation=15, fontweight="semibold")
    ax.set_ylabel("F1-Score", fontweight="semibold")
    ax.set_title("F1-Score Comparison: Test Split vs. Unseen Holdout Scenario", fontsize=12, fontweight="bold", pad=15)
    ax.set_ylim([0, 1.18])
    ax.legend(loc="upper right", framealpha=0.9, edgecolor="#bdc3c7")
    ax.grid(True, axis="y")
    
    # Add values on top of bars
    for rect in rects1:
        h = rect.get_height()
        ax.annotate(f"{h:.3f}", xy=(rect.get_x() + rect.get_width()/2, h),
                    xytext=(0, 3), textcoords="offset points", ha="center", va="bottom", fontsize=8, fontweight="bold")
    for rect in rects2:
        h = rect.get_height()
        ax.annotate(f"{h:.3f}", xy=(rect.get_x() + rect.get_width()/2, h),
                    xytext=(0, 3), textcoords="offset points", ha="center", va="bottom", fontsize=8, fontweight="bold")
                    
    plt.tight_layout()
    plt.savefig(OUT_COMP, dpi=300, bbox_inches="tight")
    plt.close()
    print(f"[*] Saved model comparison visualization to: {OUT_COMP}")
    print("=" * 80)

if __name__ == "__main__":
    main()
