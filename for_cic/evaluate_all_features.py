#!/usr/bin/env python3
"""
Evaluate Isolation Forest on CIC-IDS2017: All 77 Features vs Top 13 Features
==========================================================================
This script:
1. Loads the CIC-IDS2017 sample CSV dataset from the local 'for_cic' folder.
2. Formats labels to binary classification: 0 (BENIGN/Normal) vs 1 (Attack).
3. Lists and counts all 77 features.
4. Identifies the top 13 features most correlated with the binary label.
5. Trains and predicts Isolation Forest using:
   a) All 77 features.
   b) Only the top 13 features.
6. Saves detailed classification reports and confusion matrices to evaluation_metrics.md.
7. Generates a comparison dashboard (all_features_analysis.png).
"""

import os
import sys
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix

# Configuration
DATASET_CSV = "for_cic/cic_sample.csv"
OUTPUT_PNG = "for_cic/all_features_analysis.png"
REPORT_MD = "for_cic/evaluation_metrics.md"

def load_data():
    """Loads and returns the CIC-IDS2017 sample dataset."""
    if not os.path.exists(DATASET_CSV):
        sys.exit(f"[-] File not found: {DATASET_CSV}\n"
                 f"    Please ensure 'cic_sample.csv' is present in the 'for_cic' directory.")

    print(f"[*] Loading CIC-IDS2017 dataset from {DATASET_CSV}...")
    df = pd.read_csv(DATASET_CSV)
    print(f"    Loaded dataset shape: {df.shape[0]:,} flows, {df.shape[1]} columns")
    
    # Map label column: BENIGN -> 0, everything else -> 1
    print("[*] Mapping labels to binary target (0 = Normal, 1 = Attack)...")
    df["true_label"] = np.where(df["Label"] == "BENIGN", 0, 1)
    
    n_normal = (df["true_label"] == 0).sum()
    n_attack = (df["true_label"] == 1).sum()
    print(f"    Normal flows (0): {n_normal:,}")
    print(f"    Attack flows (1): {n_attack:,}")
    return df

def plot_confusion_matrix(ax, cm, title, labels=["Normal", "Attack"]):
    """Plots a beautiful heatmap of a confusion matrix."""
    ax.imshow(cm, interpolation='nearest', cmap=plt.cm.Blues, alpha=0.3)
    ax.set_xticks(np.arange(len(labels)))
    ax.set_yticks(np.arange(len(labels)))
    ax.set_xticklabels(labels, fontsize=9)
    ax.set_yticklabels(labels, fontsize=9)
    
    ax.set_xlabel('Predicted Label', fontsize=9, labelpad=4)
    ax.set_ylabel('True Label', fontsize=9, labelpad=4)
    ax.set_title(title, fontsize=11, fontweight="bold", pad=8)
    
    thresh = cm.max() / 2.
    total = np.sum(cm)
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            count = cm[i, j]
            pct = (count / total) * 100
            label_text = f"{count:,}\n({pct:.1f}%)"
            color = "white" if cm[i, j] > thresh else "black"
            
            if i == j:
                cell_bg = "#E8F5E9" if i == 0 else "#E3F2FD"
            else:
                cell_bg = "#FFEBEE"
                
            rect = mpatches.Rectangle((j-0.5, i-0.5), 1, 1, fill=True, color=cell_bg, zorder=-1)
            ax.add_patch(rect)
            
            ax.text(j, i, label_text, ha="center", va="center",
                    color=color if i == j and cm[i, j] > thresh else "black",
                    fontsize=10, fontweight="bold")
            
            shorthand = ""
            if i == 0 and j == 0: shorthand = "TN"
            elif i == 0 and j == 1: shorthand = "FP"
            elif i == 1 and j == 0: shorthand = "FN"
            elif i == 1 and j == 1: shorthand = "TP"
            ax.text(j, i+0.28, shorthand, ha="center", va="center", color="#757575", fontsize=8)

def main():
    # 1. Load data
    df = load_data()

    # 2. Extract and print features
    raw_feature_cols = [c for c in df.columns if c not in ["Label", "true_label"]]
    n_all_features = len(raw_feature_cols)

    # Print features in a neat grid of 3 columns
    print("\n" + "=" * 80)
    print(f"  FEATURE DISCOVERY (Total CIC-IDS2017 Features: {n_all_features})")
    print("=" * 80)
    col_width = 26
    for i in range(0, n_all_features, 3):
        row_cols = raw_feature_cols[i:i+3]
        row_str = "  " + "".join([f"{col:<{col_width}}" for col in row_cols])
        print(row_str)
    print("=" * 80 + "\n")

    # 3. Find top 13 most correlated features
    print("[*] Finding top 13 features most correlated with label...")
    corr_df = df[raw_feature_cols].copy()
    corr_df["true_label"] = df["true_label"]
    
    # Preprocess temporary frame to compute correlation correctly (replace infs/NaNs)
    corr_df = corr_df.replace([np.inf, -np.inf], np.nan).fillna(0)
    
    correlations = corr_df.corr()["true_label"].abs().sort_values(ascending=False)
    # Exclude true_label itself at index 0
    top_13_features = correlations.index[1:14].tolist()
    
    print("\n" + "=" * 80)
    print("  TOP 13 FEATURES IDENTIFIED BY TARGET CORRELATION")
    print("=" * 80)
    for idx, col in enumerate(top_13_features, 1):
        print(f"   #{idx:02d}  {col:<26}  (Correlation: {correlations[col]:.4f})")
    print("=" * 80 + "\n")

    # 4. Clean and scale features
    print("[*] Cleaning and scaling features...")
    X_all = df[raw_feature_cols].replace([np.inf, -np.inf], np.nan).fillna(0).values
    X_13 = df[top_13_features].replace([np.inf, -np.inf], np.nan).fillna(0).values
    y = df["true_label"].values

    scaler = StandardScaler()
    X_all_scaled = scaler.fit_transform(X_all)
    X_13_scaled = scaler.fit_transform(X_13)

    contamination_rate = min(np.mean(y), 0.49) # proportion of attacks capped at 0.49 for sklearn constraints

    # 5. Run Isolation Forest using ALL 77 Features
    print(f"[*] Fitting Isolation Forest on ALL {n_all_features} Features...")
    if_all = IsolationForest(n_estimators=150, contamination=contamination_rate, random_state=42, n_jobs=-1)
    preds_all = if_all.fit_predict(X_all_scaled)
    y_pred_all = np.where(preds_all == -1, 1, 0)
    
    cm_all = confusion_matrix(y, y_pred_all)
    tn_all, fp_all, fn_all, tp_all = cm_all.ravel()
    
    print("\n  All Features Classification Report:")
    print(classification_report(y, y_pred_all, target_names=["Normal (0)", "Attack (1)"], digits=4))

    # 6. Run Isolation Forest using TOP 13 Features
    print(f"[*] Fitting Isolation Forest on TOP 13 Features...")
    if_13 = IsolationForest(n_estimators=150, contamination=contamination_rate, random_state=42, n_jobs=-1)
    preds_13 = if_13.fit_predict(X_13_scaled)
    y_pred_13 = np.where(preds_13 == -1, 1, 0)
    
    cm_13 = confusion_matrix(y, y_pred_13)
    tn_13, fp_13, fn_13, tp_13 = cm_13.ravel()
    
    print("\n  Top 13 Features Classification Report:")
    print(classification_report(y, y_pred_13, target_names=["Normal (0)", "Attack (1)"], digits=4))

    # 7. Write results to evaluation_metrics.md
    with open(REPORT_MD, "w") as f:
        f.write(f"""# CIC-IDS2017 Network Anomaly Detection — Isolation Forest Metrics Report

This document reports the performance metrics of the **Isolation Forest** model on the **CIC-IDS2017** dataset, comparing the use of **all 77 features** vs. a subset of the **top 13 features**.

---

## Dataset Characteristics
*   **Total Dataset Size**: {len(df):,} network flows
*   **Normal Flows (BENIGN)**: {len(df[df["true_label"] == 0]):,}
*   **Attack/Anomaly Flows (DoS, PortScan, etc.)**: {len(df[df["true_label"] == 1]):,}
*   **Contamination Rate**: {contamination_rate:.4%}

---

## Feature Comparison
*   **All Features Config**: Using all **77 numerical features** present in the dataset.
*   **13 Features Config**: Using only the top 13 features most correlated with the attack labels:
{chr(10).join([f"    {idx}. `{col}` (correlation: {correlations[col]:.4f})" for idx, col in enumerate(top_13_features, 1)])}

---

## Model Performance Summary

| Configuration | Recall (Attack) | Precision (Attack) | F1-Score (Attack) | Overall Accuracy |
| :--- | :---: | :---: | :---: | :---: |
| **All 77 Features** | **{tp_all / (tp_all + fn_all):.2%}** | **{tp_all / (tp_all + fp_all):.2%}** | **{2 * (tp_all / (tp_all + fn_all)) * (tp_all / (tp_all + fp_all)) / ((tp_all / (tp_all + fn_all)) + (tp_all / (tp_all + fp_all))):.2%}** | **{(tn_all + tp_all) / len(df):.2%}** |
| **Top 13 Features** | **{tp_13 / (tp_13 + fn_13):.2%}** | **{tp_13 / (tp_13 + fp_13):.2%}** | **{2 * (tp_13 / (tp_13 + fn_13)) * (tp_13 / (tp_13 + fp_13)) / ((tp_13 / (tp_13 + fn_13)) + (tp_13 / (tp_13 + fp_13))):.2%}** | **{(tn_13 + tp_13) / len(df):.2%}** |

---

## Detailed Isolation Forest Reports

### 1. Configuration: All 77 Features

#### Classification Report:
```text
{classification_report(y, y_pred_all, target_names=["Normal (0)", "Attack (1)"], digits=4)}
```

#### Confusion Matrix:
*   **True Negatives (TN)**: {tn_all:,}
*   **False Positives (FP)**: {fp_all:,}
*   **False Negatives (FN)**: {fn_all:,}
*   **True Positives (TP)**: {tp_all:,}

---

### 2. Configuration: Top 13 Features

#### Classification Report:
```text
{classification_report(y, y_pred_13, target_names=["Normal (0)", "Attack (1)"], digits=4)}
```

#### Confusion Matrix:
*   **True Negatives (TN)**: {tn_13:,}
*   **False Positives (FP)**: {fp_13:,}
*   **False Negatives (FN)**: {fn_13:,}
*   **True Positives (TP)**: {tp_13:,}
""")
    print(f"[+] Written detailed metrics comparison to: {REPORT_MD}")

    # 8. Create Visualization Comparison Dashboard
    print(f"[*] Generating visual dashboard -> {OUTPUT_PNG}...")
    fig, axes = plt.subplots(2, 2, figsize=(16, 14))
    fig.patch.set_facecolor("#F8F9FA")
    fig.suptitle("CIC-IDS2017 Anomaly Detection — Isolation Forest Feature Configuration Comparison", 
                 fontsize=15, fontweight="bold", y=0.98, color="#1A252C")

    # 8.1. Plot Subplot 1: Heatmap of the Top 13 Features Correlation Matrix
    ax_corr = axes[0, 0]
    top_13_with_target = top_13_features + ["true_label"]
    corr_matrix = corr_df[top_13_with_target].corr()
    im = ax_corr.imshow(corr_matrix.values, cmap="coolwarm", vmin=-1, vmax=1)
    
    ax_corr.set_xticks(np.arange(len(top_13_with_target)))
    ax_corr.set_yticks(np.arange(len(top_13_with_target)))
    ax_corr.set_xticklabels(top_13_with_target, rotation=45, ha="right", fontsize=8)
    ax_corr.set_yticklabels(top_13_with_target, fontsize=8)
    ax_corr.set_title("Correlation Heatmap of Top 13 Features + Target", fontsize=11, fontweight="bold", pad=8)
    cbar = fig.colorbar(im, ax=ax_corr, fraction=0.046, pad=0.04)
    cbar.ax.tick_params(labelsize=8)
    
    # Annotate matrix
    for i in range(len(top_13_with_target)):
        for j in range(len(top_13_with_target)):
            val = corr_matrix.values[i, j]
            ax_corr.text(j, i, f"{val:.2f}", ha="center", va="center", 
                         color="white" if abs(val) > 0.6 else "black", fontsize=8)

    # 8.2. Plot Subplot 2: Grouped Bar Chart of Performance Metrics
    ax_bar = axes[0, 1]
    metrics = ["Precision", "Recall", "F1-Score", "Accuracy"]
    
    # Calculate percentages for All 77 Features
    p_all = (tp_all / (tp_all + fp_all)) * 100
    r_all = (tp_all / (tp_all + fn_all)) * 100
    f1_all = (2 * p_all * r_all / (p_all + r_all))
    acc_all = ((tn_all + tp_all) / len(df)) * 100
    
    # Calculate percentages for Top 13 Features
    p_13 = (tp_13 / (tp_13 + fp_13)) * 100
    r_13 = (tp_13 / (tp_13 + fn_13)) * 100
    f1_13 = (2 * p_13 * r_13 / (p_13 + r_13))
    acc_13 = ((tn_13 + tp_13) / len(df)) * 100
    
    all_vals = [p_all, r_all, f1_all, acc_all]
    vals_13 = [p_13, r_13, f1_13, acc_13]
    
    x = np.arange(len(metrics))
    width = 0.35
    
    rects1 = ax_bar.bar(x - width/2, all_vals, width, label='All 77 Features', color='#B0BEC5', edgecolor='black', linewidth=0.5)
    rects2 = ax_bar.bar(x + width/2, vals_13, width, label='Top 13 Features', color='#4CAF50', edgecolor='black', linewidth=0.5)
    
    ax_bar.set_ylabel('Percentage (%)', fontsize=9)
    ax_bar.set_title('Performance Comparison: All 77 Features vs Top 13 Features', fontsize=11, fontweight="bold", pad=8)
    ax_bar.set_xticks(x)
    ax_bar.set_xticklabels(metrics, fontsize=9)
    ax_bar.set_ylim(0, 110)
    ax_bar.grid(True, linestyle="--", alpha=0.3, axis='y')
    ax_bar.legend(fontsize=9, loc="lower right")
    
    # Annotate bar heights
    def autolabel(rects):
        for rect in rects:
            height = rect.get_height()
            ax_bar.annotate(f'{height:.2f}%',
                        xy=(rect.get_x() + rect.get_width() / 2, height),
                        xytext=(0, 3),  # 3 points vertical offset
                        textcoords="offset points",
                        ha='center', va='bottom', fontsize=8, fontweight='bold')
                        
    autolabel(rects1)
    autolabel(rects2)

    # 8.3. Plot Subplot 3: Confusion Matrix for All 77 Features
    plot_confusion_matrix(axes[1, 0], cm_all, "Isolation Forest (All 77 Features) Confusion Matrix")

    # 8.4. Plot Subplot 4: Confusion Matrix for Top 13 Features
    plot_confusion_matrix(axes[1, 1], cm_13, "Isolation Forest (Top 13 Features) Confusion Matrix")

    # Layout adjustment and save
    plt.tight_layout(rect=[0, 0.02, 1, 0.95])
    plt.savefig(OUTPUT_PNG, dpi=180, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close()
    
    print(f"[+] Visualization updated: {OUTPUT_PNG}")
    print("\n" + "=" * 80)
    print("  SUMMARY OF ISOLATION FOREST RESULTS (CIC-IDS2017)")
    print("=" * 80)
    print(f"  All 77 Features (Recall)    : {tp_all / (tp_all + fn_all):.2%}")
    print(f"  All 77 Features (Precision) : {tp_all / (tp_all + fp_all):.2%}")
    print(f"  Top 13 Features (Recall)    : {tp_13 / (tp_13 + fn_13):.2%}")
    print(f"  Top 13 Features (Precision) : {tp_13 / (tp_13 + fp_13):.2%}")
    print("=" * 80 + "\n")

if __name__ == "__main__":
    main()
