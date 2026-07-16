#!/usr/bin/env python3
"""
Model Comparison: Isolation Forest vs. AdaBoost, XGBoost, and Random Forest
===========================================================================
This script:
  1. Loads CTU-13 Attack and Normal flows.
  2. Samples a configurable number of records from each class.
  3. Prepares and scales the 10 core features used in the baseline anomaly detector.
  4. Splits the dataset into 80% train and 20% test splits.
  5. Trains:
     - Isolation Forest (Unsupervised)
     - AdaBoost Classifier (Supervised)
     - XGBoost Classifier (Supervised)
     - Random Forest Classifier (Supervised)
  6. Evaluates all models on the unseen test set across key metrics.
  7. Outputs the results to 'evaluation_metrics.csv'.
  8. Generates a premium performance visualization at 'graphs/model_comparison.png'.
"""

import os
import sys
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest, AdaBoostClassifier, RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_curve, auc, precision_recall_curve, average_precision_score
)
from xgboost import XGBClassifier

# ── Config ───────────────────────────────────────────────────────────────────
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
ATTACK_CSV = os.path.join(BASE_DIR, "data", "ctu13", "CTU13_Attack_Traffic.csv")
NORMAL_CSV = os.path.join(BASE_DIR, "data", "ctu13", "CTU13_Normal_Traffic.csv")
N_SAMPLE    = 10000         # Sample size per class (20,000 flows total)
TEST_SIZE   = 0.20          # 80/20 train/test split
OUT_CSV     = os.path.join(BASE_DIR, "research", "results", "evaluation_metrics.csv")
os.makedirs(os.path.dirname(OUT_CSV), exist_ok=True)
OUT_PNG     = os.path.join(BASE_DIR, "docs", "graphs", "model_comparison.png")

FEATURE_COLS = [
    "flow_byts_s", "flow_pkts_s",
    "fwd_bytes", "bwd_bytes", "total_pkts",
    "syn_flag", "rst_flag", "fin_flag",
    "flow_duration_s", "pkt_len_mean",
]

# ── Colors for plotting ──────────────────────────────────────────────────────
COLORS = {
    "Isolation Forest": "#7f8c8d",  # Cool grey (unsupervised baseline)
    "AdaBoost":         "#e67e22",  # Rich orange
    "XGBoost":          "#1abc9c",  # Clean teal
    "Random Forest":    "#2980b9",  # Slate blue
}

# ── 1. Load and Preprocess ────────────────────────────────────────────────────
def load_data() -> pd.DataFrame:
    for path in (ATTACK_CSV, NORMAL_CSV):
        if not os.path.exists(path):
            sys.exit(f"[-] Dataset file not found: {path}\n"
                     f"    Please ensure that the sample_logs/ directory is prepared.")

    print(f"[*] Loading dataset files...")
    attack = pd.read_csv(ATTACK_CSV)
    normal = pd.read_csv(NORMAL_CSV)
    print(f"    Attack flows available : {len(attack):,}")
    print(f"    Normal flows available : {len(normal):,}")

    # Sample equally to prevent class imbalance skewing accuracy/F1 comparisons
    attack_sampled = attack.sample(n=min(N_SAMPLE, len(attack)), random_state=42).copy()
    normal_sampled = normal.sample(n=min(N_SAMPLE, len(normal)), random_state=42).copy()
    
    attack_sampled["true_label"] = 1
    normal_sampled["true_label"] = 0

    df = pd.concat([attack_sampled, normal_sampled], ignore_index=True)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    print(f"    Sampled dataset: {len(df):,} flows ({len(attack_sampled):,} Attack, {len(normal_sampled):,} Normal)")
    return df

def featurise(df: pd.DataFrame) -> pd.DataFrame:
    """Map raw CICFlowMeter columns to cleaned model features."""
    out = pd.DataFrame()

    # Feature mapping and validation (clip negative values, fill NaNs/Infs with 0)
    out["flow_byts_s"]     = pd.to_numeric(df["Flow Byts/s"],  errors="coerce").fillna(0).clip(lower=0)
    out["flow_pkts_s"]     = pd.to_numeric(df["Flow Pkts/s"],  errors="coerce").fillna(0).clip(lower=0)
    out["fwd_bytes"]       = pd.to_numeric(df["TotLen Fwd Pkts"], errors="coerce").fillna(0).clip(lower=0)
    out["bwd_bytes"]       = pd.to_numeric(df["TotLen Bwd Pkts"], errors="coerce").fillna(0).clip(lower=0)
    out["total_pkts"]      = (pd.to_numeric(df["Tot Fwd Pkts"], errors="coerce").fillna(0) +
                              pd.to_numeric(df["Tot Bwd Pkts"], errors="coerce").fillna(0)).clip(lower=0)
    out["syn_flag"]        = pd.to_numeric(df["SYN Flag Cnt"],  errors="coerce").fillna(0).clip(lower=0)
    out["rst_flag"]        = pd.to_numeric(df["RST Flag Cnt"],  errors="coerce").fillna(0).clip(lower=0)
    out["fin_flag"]        = pd.to_numeric(df["FIN Flag Cnt"],  errors="coerce").fillna(0).clip(lower=0)
    out["flow_duration_s"] = (pd.to_numeric(df["Flow Duration"], errors="coerce").fillna(0) / 1e6).clip(lower=0)
    out["pkt_len_mean"]    = pd.to_numeric(df["Pkt Len Mean"],  errors="coerce").fillna(0).clip(lower=0)

    # Target label
    out["true_label"] = df["true_label"].values
    return out

# ── 2. Run Comparison ─────────────────────────────────────────────────────────
def main():
    print("=" * 80)
    print("           CTU-13 BOTNET DETECTION — ALGORITHM COMPARISON PIPELINE")
    print("=" * 80)

    # Create graphs dir if it does not exist
    os.makedirs(os.path.dirname(OUT_PNG), exist_ok=True)

    # Load and clean data
    raw_df = load_data()
    processed_df = featurise(raw_df)

    X = processed_df[FEATURE_COLS].values
    y = processed_df["true_label"].values

    # Train / Test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, random_state=42, stratify=y
    )
    print(f"[*] Train set size: {len(X_train):,}")
    print(f"[*] Test set size : {len(X_test):,}")

    # Scale features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Compute training anomaly/contamination ratio for Isolation Forest
    contamination_ratio = np.mean(y_train)  # Proportion of class 1 in training split
    print(f"[*] Training set contamination ratio (Attack percentage): {contamination_ratio:.4%}")

    # Models dictionary
    models = {
        "Isolation Forest": IsolationForest(n_estimators=200, contamination=contamination_ratio, random_state=42, n_jobs=-1),
        "AdaBoost":         AdaBoostClassifier(random_state=42),
        "XGBoost":          XGBClassifier(random_state=42, n_jobs=-1, eval_metric="logloss"),
        "Random Forest":    RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    }

    # Dictionary to hold predictions, probabilities/scores, and metrics
    test_predictions = {}
    anomaly_scores = {}  # higher = more likely to be attack
    metrics_list = []

    print("\n[*] Training and evaluating models...")

    for name, model in models.items():
        print(f"    Training {name}...")
        if name == "Isolation Forest":
            # Unsupervised model training (no labels)
            model.fit(X_train_scaled)
            
            # For ROC/PR curves, we need a score where higher values mean "more anomalous"
            # score_samples returns negative anomaly scores (lower = more anomalous).
            # So negating it gives a score where higher = more anomalous.
            scores = -model.score_samples(X_test_scaled)
            anomaly_scores[name] = scores
            
            # Predict using training set threshold
            train_scores = model.score_samples(X_train_scaled)
            threshold = np.percentile(train_scores, contamination_ratio * 100)
            preds = (scores >= -threshold).astype(int)
            test_predictions[name] = preds
        else:
            # Supervised model training
            model.fit(X_train_scaled, y_train)
            preds = model.predict(X_test_scaled)
            probs = model.predict_proba(X_test_scaled)[:, 1]
            test_predictions[name] = preds
            anomaly_scores[name] = probs

        # Calculate evaluation metrics
        acc = accuracy_score(y_test, test_predictions[name])
        prec = precision_score(y_test, test_predictions[name], zero_division=0)
        rec = recall_score(y_test, test_predictions[name])
        f1 = f1_score(y_test, test_predictions[name], zero_division=0)
        
        # Area under curves
        fpr, tpr, _ = roc_curve(y_test, anomaly_scores[name])
        roc_auc = auc(fpr, tpr)
        
        pr_precision, pr_recall, _ = precision_recall_curve(y_test, anomaly_scores[name])
        pr_auc = average_precision_score(y_test, anomaly_scores[name])

        metrics_list.append({
            "Model": name,
            "Accuracy": acc,
            "Precision": prec,
            "Recall": rec,
            "F1-Score": f1,
            "ROC-AUC": roc_auc,
            "PR-AUC (AP)": pr_auc
        })

    # Convert to DataFrame and round values for clean formatting
    metrics_df = pd.DataFrame(metrics_list).round(4)
    print("\n" + "=" * 80)
    print("                              EVALUATION RESULTS")
    print("=" * 80)
    print(metrics_df.to_string(index=False, formatters={
        "Accuracy": "{:.4f}".format,
        "Precision": "{:.4f}".format,
        "Recall": "{:.4f}".format,
        "F1-Score": "{:.4f}".format,
        "ROC-AUC": "{:.4f}".format,
        "PR-AUC (AP)": "{:.4f}".format,
    }))
    print("=" * 80)

    # Save to CSV
    metrics_df.to_csv(OUT_CSV, index=False)
    print(f"[*] Saved evaluation metrics table to: {OUT_CSV}")

    # ── 3. High-Quality Matplotlib Comparison Plot ─────────────────────────────────
    print(f"[*] Generating evaluation plot...")
    plt.rcParams.update({
        "font.family": "sans-serif",
        "font.size": 10,
        "axes.edgecolor": "#bdc3c7",
        "axes.linewidth": 0.8,
        "grid.color": "#ecf0f1",
        "grid.linewidth": 0.6
    })

    fig = plt.figure(figsize=(14, 10), facecolor="#f8f9fa")
    gs = gridspec.GridSpec(2, 2, height_ratios=[1.2, 1.0])
    
    ax_roc = fig.add_subplot(gs[0, 0])
    ax_pr  = fig.add_subplot(gs[0, 1])
    ax_bar = fig.add_subplot(gs[1, :])

    # Plot ROC & PR curves
    for name in models.keys():
        color = COLORS[name]
        
        # ROC Curve
        fpr, tpr, _ = roc_curve(y_test, anomaly_scores[name])
        roc_auc = auc(fpr, tpr)
        ax_roc.plot(fpr, tpr, color=color, lw=2.0, label=f"{name} (AUC = {roc_auc:.4f})")
        
        # PR Curve
        prec_vals, rec_vals, _ = precision_recall_curve(y_test, anomaly_scores[name])
        ap = average_precision_score(y_test, anomaly_scores[name])
        ax_pr.plot(rec_vals, prec_vals, color=color, lw=2.0, label=f"{name} (AP = {ap:.4f})")

    # ROC Plot Styling
    ax_roc.plot([0, 1], [0, 1], color="#95a5a6", linestyle="--", lw=1.0)
    ax_roc.set_facecolor("#ffffff")
    ax_roc.set_xlim([-0.02, 1.02])
    ax_roc.set_ylim([-0.02, 1.02])
    ax_roc.set_xlabel("False Positive Rate", fontweight="semibold")
    ax_roc.set_ylabel("True Positive Rate", fontweight="semibold")
    ax_roc.set_title("Receiver Operating Characteristic (ROC) Curve", fontsize=12, fontweight="bold", pad=12)
    ax_roc.legend(loc="lower right", framealpha=0.9, edgecolor="#bdc3c7")
    ax_roc.grid(True)

    # PR Plot Styling
    ax_pr.set_facecolor("#ffffff")
    ax_pr.set_xlim([-0.02, 1.02])
    ax_pr.set_ylim([-0.02, 1.02])
    ax_pr.set_xlabel("Recall", fontweight="semibold")
    ax_pr.set_ylabel("Precision", fontweight="semibold")
    ax_pr.set_title("Precision-Recall (PR) Curve", fontsize=12, fontweight="bold", pad=12)
    ax_pr.legend(loc="lower left", framealpha=0.9, edgecolor="#bdc3c7")
    ax_pr.grid(True)

    # Metrics bar chart styling
    ax_bar.set_facecolor("#ffffff")
    bar_width = 0.18
    metrics_names = ["Accuracy", "Precision", "Recall", "F1-Score"]
    
    # Generate X coordinates
    index = np.arange(len(metrics_names))
    
    for i, name in enumerate(models.keys()):
        row = metrics_df[metrics_df["Model"] == name].iloc[0]
        values = [row["Accuracy"], row["Precision"], row["Recall"], row["F1-Score"]]
        
        rects = ax_bar.bar(
            index + (i - 1.5) * bar_width, 
            values, 
            bar_width, 
            color=COLORS[name], 
            label=name,
            edgecolor="#ffffff",
            linewidth=1.0
        )
        
        # Add values on top of bars
        for rect in rects:
            height = rect.get_height()
            ax_bar.annotate(
                f"{height:.3f}",
                xy=(rect.get_x() + rect.get_width() / 2, height),
                xytext=(0, 3),  # 3 points vertical offset
                textcoords="offset points",
                ha="center", 
                va="bottom",
                fontsize=8,
                fontweight="semibold"
            )

    ax_bar.set_xticks(index)
    ax_bar.set_xticklabels(metrics_names, fontweight="semibold")
    ax_bar.set_ylabel("Metric Value", fontweight="semibold")
    ax_bar.set_title("Overall Model Evaluation Metric Comparison", fontsize=12, fontweight="bold", pad=12)
    ax_bar.set_ylim([0, 1.15])
    ax_bar.legend(loc="upper right", framealpha=0.9, edgecolor="#bdc3c7", ncol=4)
    ax_bar.grid(True, axis="y")

    # Add a main title to the figure
    plt.suptitle("CTU-13 Network Anomaly Detection: Model Performance Comparison\n(Unsupervised Isolation Forest vs. Supervised Classifiers)",
                 fontsize=15, fontweight="bold", y=0.98)
    
    plt.tight_layout()
    plt.savefig(OUT_PNG, dpi=300, bbox_inches="tight")
    print(f"[*] Saved performance comparison visualization to: {OUT_PNG}")
    print("=" * 80)

if __name__ == "__main__":
    main()
