#!/usr/bin/env python3
"""
Ensemble Anomaly Detector — IF + LOF + Autoencoder
====================================================
Research question: does diversity of anomaly notions help?

Each detector captures a different geometric idea of "rare":
  IF  — globally rare: short average path length in random trees
  LOF — locally rare:  lower density than its k neighbours
  AE  — representationally rare: high reconstruction error vs
         the normal-traffic manifold (trained on benign only)

We measure KS distance (the structural ceiling) for each detector
individually, then for their ensemble. If ensemble KS > any single
KS, diversity demonstrably helps.

Output:
  graphs/ensemble_comparison.png  — 4-panel research figure
  Console: KS and AUC per detector + ensemble
"""

import os
import warnings
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
from scipy.stats import ks_2samp, gaussian_kde
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.neural_network import MLPRegressor
from sklearn.preprocessing import StandardScaler, MinMaxScaler
from sklearn.metrics import roc_auc_score, roc_curve, auc as sk_auc

warnings.filterwarnings("ignore")

ATTACK_CSV    = "sample_logs/CTU13_Attack_Traffic.csv"
NORMAL_CSV    = "sample_logs/CTU13_Normal_Traffic.csv"
N_SAMPLE      = 6_000
CONTAMINATION = 0.40
OUT_PNG       = "graphs/ensemble_comparison.png"
DROP_COLS     = {"Unnamed: 0", "Label", "true_label"}

COLORS = {
    "IF":       "#E53935",
    "LOF":      "#FB8C00",
    "AE":       "#8E24AA",
    "Ensemble": "#1565C0",
}


# ── 1. Load & featurise ───────────────────────────────────────────────────────

def load() -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Returns X (all flows), y (true labels), X_normal (benign only for AE training)."""
    print("[*] Loading CTU-13 ...")
    atk = pd.read_csv(ATTACK_CSV).sample(N_SAMPLE, random_state=42)
    nrm = pd.read_csv(NORMAL_CSV).sample(N_SAMPLE, random_state=42)
    atk["true_label"] = 1
    nrm["true_label"] = 0

    df = pd.concat([atk, nrm], ignore_index=True).sample(
        frac=1, random_state=42).reset_index(drop=True)

    feat_cols = [c for c in df.columns if c not in DROP_COLS]
    X_raw = df[feat_cols].replace([np.inf, -np.inf], np.nan)
    X_raw = X_raw.fillna(X_raw.median())
    X_raw = X_raw.loc[:, X_raw.var() > 0]
    skewed = X_raw.skew()[lambda s: s.abs() > 2].index
    X_raw[skewed] = np.log1p(X_raw[skewed].clip(lower=0))

    sc = StandardScaler()
    X  = sc.fit_transform(X_raw.values)
    y  = df["true_label"].values

    X_normal = X[y == 0]
    print(f"    {N_SAMPLE:,} attack + {N_SAMPLE:,} normal = {len(X):,} flows | {X.shape[1]} features")
    return X, y, X_normal


# ── 2. Three detectors ────────────────────────────────────────────────────────

def run_if(X: np.ndarray) -> np.ndarray:
    print("[*] Training Isolation Forest ...")
    m = IsolationForest(n_estimators=200, contamination=CONTAMINATION,
                        random_state=42, n_jobs=-1)
    m.fit(X)
    # score_samples: lower = more anomalous; flip so higher = more anomalous
    return -m.score_samples(X)


def run_lof(X: np.ndarray) -> np.ndarray:
    print("[*] Training LOF ...")
    m = LocalOutlierFactor(n_neighbors=20, contamination=CONTAMINATION,
                           novelty=False, n_jobs=-1)
    raw = m.fit_predict(X)          # -1 = outlier
    # negative_outlier_factor_: more negative = more anomalous; flip
    return -m.negative_outlier_factor_


def run_autoencoder(X: np.ndarray, X_normal: np.ndarray) -> np.ndarray:
    """Train MLP autoencoder on normal flows only; score all flows by
    mean-squared reconstruction error (higher = more anomalous)."""
    print("[*] Training Autoencoder (MLP, normal traffic only) ...")
    dim = X.shape[1]
    ae  = MLPRegressor(
        hidden_layer_sizes=(dim // 2, dim // 4, dim // 2),
        activation="relu",
        max_iter=300,
        random_state=42,
        early_stopping=True,
        validation_fraction=0.1,
        n_iter_no_change=15,
    )
    ae.fit(X_normal, X_normal)
    recon = ae.predict(X)
    mse   = np.mean((X - recon) ** 2, axis=1)
    return mse


def normalise(score: np.ndarray) -> np.ndarray:
    mn, mx = score.min(), score.max()
    return (score - mn) / (mx - mn + 1e-9)


# ── 3. Measure KS + AUC ───────────────────────────────────────────────────────

def measure(score: np.ndarray, y: np.ndarray, name: str) -> dict:
    norm_score = normalise(score)
    auc_val    = roc_auc_score(y, norm_score)
    ks_stat, _ = ks_2samp(norm_score[y == 1], norm_score[y == 0])
    fpr, tpr, _ = roc_curve(y, norm_score)
    print(f"    {name:<10}  KS={ks_stat:.3f}   AUC={auc_val:.3f}")
    return {"name": name, "score": norm_score, "auc": auc_val,
            "ks": ks_stat, "fpr": fpr, "tpr": tpr}


# ── 4. Plot ───────────────────────────────────────────────────────────────────

def plot(results: list[dict], y: np.ndarray) -> None:
    os.makedirs("graphs", exist_ok=True)
    fig = plt.figure(figsize=(20, 16), facecolor="#F4F6FA")
    fig.suptitle(
        "Ensemble Anomaly Detection: IF + LOF + Autoencoder\n"
        "Does diversity of anomaly notions push past the KS ceiling?",
        fontsize=13, fontweight="bold", y=0.995,
    )
    gs = gridspec.GridSpec(2, 2, figure=fig, hspace=0.40, wspace=0.35,
                           top=0.955, bottom=0.07, left=0.07, right=0.97)

    BG = "#EAEFF7"

    # ── Panel A: KS bars ──────────────────────────────────────────────────────
    ax_ks = fig.add_subplot(gs[0, 0])
    ax_ks.set_facecolor(BG)
    names  = [r["name"] for r in results]
    ks_vals = [r["ks"]  for r in results]
    colors  = [COLORS[n] for n in names]
    bars = ax_ks.bar(names, ks_vals, color=colors, alpha=0.85,
                     edgecolor="white", linewidth=0.8, width=0.55)
    ax_ks.axhline(results[0]["ks"], color=COLORS["IF"], linestyle=":",
                  linewidth=1.4, alpha=0.6, label=f"IF baseline ({results[0]['ks']:.3f})")
    for bar, v in zip(bars, ks_vals):
        ax_ks.text(bar.get_x() + bar.get_width()/2, v + 0.005,
                   f"{v:.3f}", ha="center", va="bottom",
                   fontsize=11, fontweight="bold")
    ax_ks.set_ylabel("KS Distance  (= max achievable TPR-FPR)", fontsize=9)
    ax_ks.set_title(
        "KS Ceiling per Detector\nHigher = better separation of attack vs normal",
        fontweight="bold", fontsize=10, loc="left",
    )
    ax_ks.set_ylim(0, max(ks_vals) * 1.20)
    ax_ks.legend(fontsize=8)
    ax_ks.grid(True, alpha=0.25, linestyle="--", axis="y")

    # ── Panel B: ROC curves ───────────────────────────────────────────────────
    ax_roc = fig.add_subplot(gs[0, 1])
    ax_roc.set_facecolor(BG)
    for r in results:
        ax_roc.plot(r["fpr"], r["tpr"], color=COLORS[r["name"]], linewidth=2.2,
                    label=f"{r['name']}  (AUC={r['auc']:.3f})")
    ax_roc.plot([0,1],[0,1], "k--", linewidth=1, alpha=0.35, label="Random (0.500)")
    ax_roc.set_xlabel("False Positive Rate", fontsize=9)
    ax_roc.set_ylabel("True Positive Rate", fontsize=9)
    ax_roc.set_title("ROC Curves — All Detectors", fontweight="bold", fontsize=10, loc="left")
    ax_roc.legend(fontsize=8.5, loc="lower right")
    ax_roc.grid(True, alpha=0.25, linestyle="--")

    # ── Panel C: Score KDE per detector ──────────────────────────────────────
    ax_kde = fig.add_subplot(gs[1, 0])
    ax_kde.set_facecolor(BG)
    ls_map = {"IF": "-", "LOF": "--", "AE": "-.", "Ensemble": ":"}
    lw_map = {"IF": 1.8, "LOF": 1.8, "AE": 1.8, "Ensemble": 2.8}
    for r in results:
        for cls, label_suffix, alpha in [(0, "Normal", 0.25), (1, "Attack", 0.70)]:
            sc   = r["score"][y == cls]
            xs   = np.linspace(sc.min(), sc.max(), 300)
            kde  = gaussian_kde(sc, bw_method=0.15)
            c    = COLORS[r["name"]]
            lbl  = f"{r['name']} – {label_suffix}" if cls == 1 else None
            ax_kde.plot(xs, kde(xs), color=c,
                        linestyle=ls_map[r["name"]],
                        linewidth=lw_map[r["name"]],
                        alpha=alpha, label=lbl)
    ax_kde.set_xlabel("Normalised anomaly score (higher = more anomalous)", fontsize=9)
    ax_kde.set_ylabel("Density", fontsize=9)
    ax_kde.set_title(
        "Score Distributions (solid=Attack, faded=Normal)\n"
        "Wider gap = better detector",
        fontweight="bold", fontsize=10, loc="left",
    )
    ax_kde.legend(fontsize=7.5, loc="upper right", ncol=2)
    ax_kde.grid(True, alpha=0.25, linestyle="--")

    # ── Panel D: Unique TPs per detector (what each catches the others miss) ──
    ax_venn = fig.add_subplot(gs[1, 1])
    ax_venn.set_facecolor(BG)

    # Use top-40% flagged as "detected" per individual detector
    thresh = int(len(y) * CONTAMINATION)
    attack_idx = set(np.where(y == 1)[0])
    tp_sets = {}
    for r in results[:-1]:   # exclude ensemble here
        top_idx  = set(np.argsort(r["score"])[-thresh:])
        tp_sets[r["name"]] = top_idx & attack_idx

    # Which attacks are caught ONLY by one detector
    labels_d   = list(tp_sets.keys())
    all_caught  = set.union(*tp_sets.values())
    only_counts = {}
    for name, tps in tp_sets.items():
        others = set.union(*(v for k, v in tp_sets.items() if k != name))
        only_counts[name] = len(tps - others)
    shared_all  = len(set.intersection(*tp_sets.values()))
    shared_pairs = {}
    for i, n1 in enumerate(labels_d):
        for n2 in labels_d[i+1:]:
            shared_pairs[f"{n1}+{n2}"] = len(
                (tp_sets[n1] & tp_sets[n2]) - tp_sets[
                    next(n for n in labels_d if n not in (n1,n2))]
            )

    cats   = (["Only IF", "Only LOF", "Only AE"] +
              [f"{a}+{b}" for a,b in [("IF","LOF"),("IF","AE"),("LOF","AE")]] +
              ["All three"])
    counts = ([only_counts["IF"], only_counts["LOF"], only_counts["AE"]] +
              [shared_pairs["IF+LOF"], shared_pairs["IF+AE"], shared_pairs["LOF+AE"]] +
              [shared_all])
    bar_colors = ([COLORS["IF"], COLORS["LOF"], COLORS["AE"]] +
                  ["#795548","#607D8B","#9C27B0"] + [COLORS["Ensemble"]])

    bars2 = ax_venn.bar(cats, counts, color=bar_colors, alpha=0.85,
                        edgecolor="white", linewidth=0.8)
    for bar, v in zip(bars2, counts):
        ax_venn.text(bar.get_x() + bar.get_width()/2, v + 5,
                     str(v), ha="center", va="bottom", fontsize=9, fontweight="bold")
    ax_venn.set_ylabel("True Positives (attack flows correctly flagged)", fontsize=9)
    ax_venn.set_title(
        "Unique Contributions of Each Detector\nAttacks caught by one detector but missed by others",
        fontweight="bold", fontsize=10, loc="left",
    )
    plt.setp(ax_venn.get_xticklabels(), rotation=30, ha="right", fontsize=8)
    ax_venn.grid(True, alpha=0.25, linestyle="--", axis="y")
    ax_venn.text(0.98, 0.97,
        f"Total unique attacks in data : {len(attack_idx):,}\n"
        f"Caught by at least one       : {len(all_caught & attack_idx):,}\n"
        f"IF alone catch               : {only_counts['IF']:,}\n"
        f"LOF alone catch              : {only_counts['LOF']:,}\n"
        f"AE alone catch               : {only_counts['AE']:,}",
        transform=ax_venn.transAxes, fontsize=8, va="top", ha="right",
        bbox=dict(boxstyle="round,pad=0.4", fc="white", ec="#90A4AE", alpha=0.92))

    plt.savefig(OUT_PNG, dpi=150, bbox_inches="tight", facecolor=fig.get_facecolor())
    print(f"\n[+] Figure saved -> {OUT_PNG}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    X, y, X_normal = load()

    scores_if  = run_if(X)
    scores_lof = run_lof(X)
    scores_ae  = run_autoencoder(X, X_normal)

    # Ensemble: average of three normalised scores
    ens = (normalise(scores_if) + normalise(scores_lof) + normalise(scores_ae)) / 3

    print("\n" + "=" * 55)
    print("  DETECTOR COMPARISON  (KS = structural ceiling)")
    print("=" * 55)
    results = [
        measure(scores_if,  y, "IF"),
        measure(scores_lof, y, "LOF"),
        measure(scores_ae,  y, "AE"),
        measure(ens,        y, "Ensemble"),
    ]
    best = max(results, key=lambda r: r["ks"])
    print(f"\n  Best KS  : {best['name']}  ({best['ks']:.3f})")
    lift = results[-1]["ks"] - results[0]["ks"]
    print(f"  KS lift  : Ensemble vs IF  = {lift:+.3f}")
    print("=" * 55)

    plot(results, y)


if __name__ == "__main__":
    main()
