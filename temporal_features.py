#!/usr/bin/env python3
"""
Temporal Features Experiment — The Go/No-Go for the Paper
==========================================================
Question: Do behavioral/temporal features fix Stage 1 recall on
low-volume stealthy attacks (Backdoor, Shellcode, Analysis, Worms)?

The previous zero-day simulation showed Stage 1 (AE) only catches
2-13% of these hidden attack types. Both AE and IF fail because
per-flow statistics overlap with normal idle traffic.

Hypothesis: Temporal/behavioral context breaks this overlap.
  - Backdoor repeatedly beacons to the same C&C IP
    → ct_dst_ltm (same destination in last 100 connections) will be high
  - Shellcode exploits a specific service
    → ct_srv_src (same service from same source) will be elevated
  - These patterns are invisible per-flow but obvious across flows

Experiment 1 — UNSW-NB15 (has ct_* behavioral features):
  AE trained on:
    (a) Flow features only              [baseline — what we already have]
    (b) Flow + behavioral (ct_*, jitter, inter-packet times)
    (c) Behavioral features only
  Compare per-attack-type recall, especially hidden types.

Experiment 2 — CTU-13 (within-flow IAT as temporal proxy):
  Compute periodicity index from IAT stats (low CV = regular beaconing)
  Compare AE with and without IAT temporal features.

Output: graphs/temporal_features.png
"""

import os
import warnings
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
warnings.filterwarnings("ignore")

from sklearn.neural_network import MLPRegressor
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import recall_score, roc_auc_score
from scipy.stats import ks_2samp

UNSW_TRAIN = "sample_logs/unsw_nb15/UNSW_NB15_training-set.csv"
UNSW_TEST  = "sample_logs/unsw_nb15/UNSW_NB15_testing-set.csv"
ATTACK_CSV = "sample_logs/CTU13_Attack_Traffic.csv"
NORMAL_CSV = "sample_logs/CTU13_Normal_Traffic.csv"
OUT_PNG    = "graphs/temporal_features.png"
AE_PCT     = 95

# UNSW-NB15 column groups
META_COLS  = {"id", "proto", "service", "state", "attack_cat", "label"}

CT_COLS    = [   # behavioral: count of similar connections in last 100
    "ct_srv_src", "ct_state_ttl", "ct_dst_ltm", "ct_src_dport_ltm",
    "ct_dst_sport_ltm", "ct_dst_src_ltm", "ct_src_ltm", "ct_srv_dst",
]
JITTER_COLS = ["sinpkt", "dinpkt", "sjit", "djit"]   # inter-packet timing
TTL_COLS    = ["sttl", "dttl"]
TEMPORAL_COLS = CT_COLS + JITTER_COLS + TTL_COLS      # all temporal/behavioral

# CTU-13 temporal columns (within-flow IAT)
IAT_COLS_CTU = [
    "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
    "Fwd IAT Mean", "Fwd IAT Std", "Bwd IAT Mean", "Bwd IAT Std",
    "Active Mean", "Active Std", "Idle Mean", "Idle Std",
]
CORE_COLS_CTU = [
    "Flow Byts/s", "Flow Pkts/s", "TotLen Fwd Pkts", "TotLen Bwd Pkts",
    "Tot Fwd Pkts", "Tot Bwd Pkts", "SYN Flag Cnt", "RST Flag Cnt",
    "FIN Flag Cnt", "Pkt Len Mean",
]

HIDDEN_TYPES = {"Backdoor", "Shellcode", "Analysis", "Worms"}


# ── helpers ───────────────────────────────────────────────────────────────────

def prep(df, cols, fit_sc=None):
    X = df[cols].replace([np.inf, -np.inf], np.nan).fillna(df[cols].median())
    X = X.loc[:, X.var() > 0] if fit_sc is None else X[fit_sc.feature_names_in_]
    if fit_sc is None:
        skewed = X.skew()[lambda s: s.abs() > 2].index
        X[skewed] = np.log1p(X[skewed].clip(lower=0))
        sc = StandardScaler().fit(X.values)
        return sc.transform(X.values), X.columns.tolist(), sc
    return fit_sc.transform(X.values), None, None


def train_ae(X_normal):
    dim = X_normal.shape[1]
    ae = MLPRegressor(
        hidden_layer_sizes=(max(dim // 2, 8), max(dim // 4, 4), max(dim // 2, 8)),
        activation="relu", max_iter=300, random_state=42,
        early_stopping=True, validation_fraction=0.1, n_iter_no_change=15,
    )
    ae.fit(X_normal, X_normal)
    return ae


def mse(ae, X):
    return np.mean((X - ae.predict(X)) ** 2, axis=1)


def evaluate(ae, X_te, y_te, cats_te, thr):
    scores = mse(ae, X_te)
    pred   = (scores > thr).astype(int)
    ks, _  = ks_2samp(scores[y_te == 1], scores[y_te == 0])
    auc    = roc_auc_score(y_te, scores)
    overall_rec = recall_score(y_te, pred, zero_division=0)
    per_type = {}
    for cat in sorted(set(cats_te) - {"Normal"}):
        idx = cats_te == cat
        per_type[cat] = recall_score(y_te[idx], pred[idx], zero_division=0)
    return {"ks": ks, "auc": auc, "recall": overall_rec, "per_type": per_type}


# ── Experiment 1: UNSW-NB15 ───────────────────────────────────────────────────

def run_unsw():
    print("=" * 62)
    print("  EXPERIMENT 1: UNSW-NB15")
    print("  Flow features only  vs  Flow + Behavioral  vs  Behavioral only")
    print("=" * 62)

    tr = pd.read_csv(UNSW_TRAIN)
    te = pd.read_csv(UNSW_TEST)
    y_tr   = tr["label"].values
    y_te   = te["label"].values
    cats_te = te["attack_cat"].str.strip().values

    # available columns (excluding meta and label)
    all_feat = [c for c in tr.columns if c not in META_COLS]
    flow_cols = [c for c in all_feat if c not in TEMPORAL_COLS]
    temp_cols = [c for c in TEMPORAL_COLS if c in tr.columns]

    print(f"  Flow features     : {len(flow_cols)}")
    print(f"  Temporal/behav.   : {len(temp_cols)}")
    print(f"    ct_* cols       : {[c for c in CT_COLS if c in tr.columns]}")
    print()

    configs = [
        ("Flow only",          flow_cols),
        ("Temporal only",      temp_cols),
        ("Flow + Temporal",    flow_cols + temp_cols),
    ]

    results = {}
    for name, cols in configs:
        print(f"  [{name}]  {len(cols)} features")
        X_tr, feat, sc = prep(tr, cols)
        X_tr_nrm = X_tr[y_tr == 0]

        # apply same transform to test
        te_raw = te[feat].replace([np.inf,-np.inf], np.nan).fillna(te[feat].median())
        skewed_tr = tr[feat].replace([np.inf,-np.inf],np.nan).skew()
        skewed_tr = skewed_tr[skewed_tr.abs()>2].index.tolist()
        for c in skewed_tr:
            if c in te_raw.columns:
                te_raw[c] = np.log1p(te_raw[c].clip(lower=0))
        X_te = sc.transform(te_raw.values)

        ae  = train_ae(X_tr_nrm)
        thr = np.percentile(mse(ae, X_tr_nrm), AE_PCT)
        res = evaluate(ae, X_te, y_te, cats_te, thr)
        results[name] = res

        print(f"    Overall recall: {res['recall']:.3f}  KS: {res['ks']:.3f}  AUC: {res['auc']:.3f}")
        print(f"    Per-type recall (key hidden types):")
        for cat in ["Backdoor", "Analysis", "Shellcode", "Worms"]:
            r = res["per_type"].get(cat, 0)
            marker = " <-- HIDDEN" if cat in HIDDEN_TYPES else ""
            print(f"      {cat:<14} {r:.3f}{marker}")
        print()

    # Cohen's d for temporal features on hidden types
    print("  COHEN'S d — temporal features vs hidden attacks (UNSW-NB15 train)")
    print(f"  {'Feature':<24} {'Backdoor d':>12} {'Analysis d':>12} {'Shellcode d':>12}")
    print("  " + "-" * 62)
    for c in temp_cols:
        try:
            atk_b = tr[tr["attack_cat"] == "Backdoor"][c].replace([np.inf,-np.inf], np.nan).dropna()
            atk_a = tr[tr["attack_cat"] == "Analysis"][c].replace([np.inf,-np.inf], np.nan).dropna()
            atk_s = tr[tr["attack_cat"] == "Shellcode"][c].replace([np.inf,-np.inf], np.nan).dropna()
            nrm   = tr[tr["label"] == 0][c].replace([np.inf,-np.inf], np.nan).dropna()
            def cohend(a, b):
                pool_std = np.sqrt((a.var() + b.var()) / 2 + 1e-9)
                return (a.mean() - b.mean()) / pool_std
            db = cohend(atk_b, nrm)
            da = cohend(atk_a, nrm)
            ds = cohend(atk_s, nrm)
            if max(abs(db), abs(da), abs(ds)) > 0.2:  # only show discriminative ones
                print(f"  {c:<24} {db:>+12.3f} {da:>+12.3f} {ds:>+12.3f}")
        except Exception:
            pass
    print()

    return results, temp_cols, cats_te


# ── Experiment 2: CTU-13 IAT temporal proxy ───────────────────────────────────

def run_ctu13():
    print("=" * 62)
    print("  EXPERIMENT 2: CTU-13")
    print("  Core 10 features  vs  Core + IAT temporal features")
    print("=" * 62)

    from sklearn.model_selection import train_test_split

    atk = pd.read_csv(ATTACK_CSV).sample(6000, random_state=42); atk["label"] = 1
    nrm = pd.read_csv(NORMAL_CSV).sample(6000, random_state=42); nrm["label"] = 0
    df  = pd.concat([atk, nrm]).sample(frac=1, random_state=42).reset_index(drop=True)
    df_tr, df_te = train_test_split(df, test_size=0.30, stratify=df["label"], random_state=42)

    # available cols
    core_avail = [c for c in CORE_COLS_CTU if c in df.columns]
    iat_avail  = [c for c in IAT_COLS_CTU  if c in df.columns]

    # compute periodicity proxy: CV of IAT (low = regular beaconing)
    for split in [df_tr, df_te]:
        mean_col = "Flow IAT Mean"
        std_col  = "Flow IAT Std"
        if mean_col in split.columns and std_col in split.columns:
            split["iat_cv"]     = split[std_col] / (split[mean_col].abs() + 1e-9)
            split["idle_ratio"] = split.get("Idle Mean", 0) / (split.get("Active Mean", 0).abs() + 1e-9)

    extra_derived = ["iat_cv", "idle_ratio"]
    iat_full = iat_avail + [c for c in extra_derived if c in df_tr.columns]

    configs = [
        ("Core 10 features",       core_avail),
        ("Core + IAT temporal",    core_avail + iat_full),
        ("IAT temporal only",      iat_full),
    ]

    results_ctu = {}
    for name, cols in configs:
        cols = [c for c in cols if c in df_tr.columns]
        print(f"  [{name}]  {len(cols)} features")

        tr_raw = df_tr[cols].replace([np.inf,-np.inf], np.nan).fillna(df_tr[cols].median())
        tr_raw = tr_raw.loc[:, tr_raw.var()>0]
        skewed = tr_raw.skew()[lambda s: s.abs()>2].index
        tr_raw[skewed] = np.log1p(tr_raw[skewed].clip(lower=0))
        sc  = StandardScaler().fit(tr_raw.values)
        X_tr = sc.transform(tr_raw.values)
        y_tr = df_tr["label"].values

        te_raw = df_te[tr_raw.columns].replace([np.inf,-np.inf], np.nan).fillna(df_te[tr_raw.columns].median())
        for c in skewed:
            if c in te_raw.columns:
                te_raw[c] = np.log1p(te_raw[c].clip(lower=0))
        X_te  = sc.transform(te_raw.values)
        y_te  = df_te["label"].values

        X_tr_nrm = X_tr[y_tr == 0]
        ae  = train_ae(X_tr_nrm)
        thr = np.percentile(mse(ae, X_tr_nrm), AE_PCT)

        scores = mse(ae, X_te)
        pred   = (scores > thr).astype(int)
        ks, _  = ks_2samp(scores[y_te == 1], scores[y_te == 0])
        auc    = roc_auc_score(y_te, scores)
        rec    = recall_score(y_te, pred, zero_division=0)
        from sklearn.metrics import precision_score, f1_score
        prec   = precision_score(y_te, pred, zero_division=0)
        f1     = f1_score(y_te, pred, zero_division=0)

        print(f"    Precision={prec:.3f}  Recall={rec:.3f}  F1={f1:.3f}  KS={ks:.3f}  AUC={auc:.3f}")
        results_ctu[name] = {"ks": ks, "auc": auc, "recall": rec, "prec": prec, "f1": f1}
    print()

    return results_ctu


# ── Plot ──────────────────────────────────────────────────────────────────────

def plot(unsw_results, ctu_results, temp_cols, cats_te):
    os.makedirs("graphs", exist_ok=True)
    fig = plt.figure(figsize=(20, 11), facecolor="#F4F6FA")
    fig.suptitle(
        "Temporal & Behavioral Features: Do They Fix Stage 1 Recall on Hidden Attack Types?",
        fontsize=13, fontweight="bold", y=0.98,
    )
    gs = gridspec.GridSpec(2, 3, figure=fig, hspace=0.45, wspace=0.38,
                           left=0.06, right=0.97, top=0.91, bottom=0.10)
    BG = "#EAEFF7"
    CMAP = {"Flow only": "#E53935", "Temporal only": "#FB8C00", "Flow + Temporal": "#1565C0"}
    CMAP2 = {"Core 10 features": "#E53935", "Core + IAT temporal": "#1565C0",
              "IAT temporal only": "#FB8C00"}

    all_cats_unsw = sorted(set(cats_te) - {"Normal"})

    # Panel A: UNSW per-type recall heatmap
    ax_heat = fig.add_subplot(gs[0, :2])
    ax_heat.set_facecolor(BG)
    configs = list(unsw_results.keys())
    matrix  = np.array([[unsw_results[c]["per_type"].get(cat, 0) for cat in all_cats_unsw]
                         for c in configs])
    im = ax_heat.imshow(matrix, cmap="RdYlGn", aspect="auto", vmin=0, vmax=1)
    ax_heat.set_xticks(range(len(all_cats_unsw)))
    ax_heat.set_xticklabels(
        [("* " + c if c in HIDDEN_TYPES else c) for c in all_cats_unsw],
        fontsize=8.5, rotation=25, ha="right"
    )
    ax_heat.set_yticks(range(len(configs)))
    ax_heat.set_yticklabels(configs, fontsize=9)
    for i in range(len(configs)):
        for j in range(len(all_cats_unsw)):
            v = matrix[i, j]
            ax_heat.text(j, i, f"{v:.2f}", ha="center", va="center",
                         fontsize=8, color="black" if 0.2 < v < 0.8 else "white",
                         fontweight="bold")
    plt.colorbar(im, ax=ax_heat, fraction=0.02, pad=0.01)
    ax_heat.set_title("UNSW-NB15: Per-Attack-Type Recall by Feature Set\n"
                       "* = hidden from Stage 2 in zero-day simulation",
                       fontweight="bold", fontsize=10, loc="left")

    # Panel B: UNSW overall KS comparison
    ax_ks = fig.add_subplot(gs[0, 2])
    ax_ks.set_facecolor(BG)
    names_u = list(unsw_results.keys())
    ks_u    = [unsw_results[n]["ks"] for n in names_u]
    bars = ax_ks.bar(range(len(names_u)), ks_u,
                     color=[CMAP.get(n, "#607D8B") for n in names_u],
                     alpha=0.85, edgecolor="white")
    for bar, v in zip(bars, ks_u):
        ax_ks.text(bar.get_x()+bar.get_width()/2, v+0.005, f"{v:.3f}",
                   ha="center", fontsize=10, fontweight="bold")
    ax_ks.set_xticks(range(len(names_u)))
    ax_ks.set_xticklabels([n.replace(" ", "\n") for n in names_u], fontsize=8)
    ax_ks.set_ylabel("KS Distance (structural ceiling)")
    ax_ks.set_ylim(0, max(ks_u) * 1.25)
    ax_ks.set_title("UNSW-NB15\nKS Ceiling by Feature Set",
                     fontweight="bold", fontsize=10, loc="left")
    ax_ks.grid(True, alpha=0.25, linestyle="--", axis="y")

    # Panel C: Hidden types recall lift (key chart)
    ax_lift = fig.add_subplot(gs[1, :2])
    ax_lift.set_facecolor(BG)
    hidden_sorted = sorted(HIDDEN_TYPES)
    x     = np.arange(len(hidden_sorted))
    w     = 0.25
    for i, (name, color) in enumerate(CMAP.items()):
        vals = [unsw_results[name]["per_type"].get(c, 0) for c in hidden_sorted]
        bars = ax_lift.bar(x + (i - 1) * w, vals, w, label=name,
                           color=color, alpha=0.82, edgecolor="white")
        for bar, v in zip(bars, vals):
            ax_lift.text(bar.get_x()+bar.get_width()/2,
                         v + 0.005, f"{v:.2f}",
                         ha="center", va="bottom", fontsize=8, fontweight="bold")
    ax_lift.set_xticks(x)
    ax_lift.set_xticklabels([f"{c}\n(zero-day type)" for c in hidden_sorted], fontsize=9)
    ax_lift.set_ylabel("Stage 1 Recall")
    ax_lift.set_ylim(0, 1.0)
    ax_lift.set_title("Hidden Attack Type Recall — Flow Only vs Temporal vs Combined\n"
                       "This is the go/no-go: does adding temporal context fix Stage 1?",
                       fontweight="bold", fontsize=10, loc="left")
    ax_lift.legend(fontsize=9)
    ax_lift.grid(True, alpha=0.25, linestyle="--", axis="y")

    # Panel D: CTU-13 comparison
    ax_ctu = fig.add_subplot(gs[1, 2])
    ax_ctu.set_facecolor(BG)
    metrics = ["F1", "Recall", "KS"]
    names_c = list(ctu_results.keys())
    x_c = np.arange(len(metrics))
    w_c = 0.25
    for i, (name, color) in enumerate(CMAP2.items()):
        vals = [ctu_results[name].get(m.lower(), ctu_results[name].get("ks" if m=="KS" else m.lower(), 0))
                for m in metrics]
        # fix KS key
        vals = [ctu_results[name]["f1"],
                ctu_results[name]["recall"],
                ctu_results[name]["ks"]]
        bars_c = ax_ctu.bar(x_c + (i - 1) * w_c, vals, w_c * 0.9,
                             label=name, color=color, alpha=0.82, edgecolor="white")
        for bar, v in zip(bars_c, vals):
            ax_ctu.text(bar.get_x()+bar.get_width()/2, v+0.005, f"{v:.2f}",
                        ha="center", va="bottom", fontsize=7.5, fontweight="bold")
    ax_ctu.set_xticks(x_c)
    ax_ctu.set_xticklabels(metrics, fontsize=10)
    ax_ctu.set_ylim(0, 1.15)
    ax_ctu.set_title("CTU-13: Core vs Core+IAT\nDoes IAT periodicity help?",
                      fontweight="bold", fontsize=10, loc="left")
    ax_ctu.legend(fontsize=7.5)
    ax_ctu.grid(True, alpha=0.25, linestyle="--", axis="y")

    plt.savefig(OUT_PNG, dpi=150, bbox_inches="tight", facecolor=fig.get_facecolor())
    print(f"[+] Figure saved -> {OUT_PNG}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    print("TEMPORAL FEATURES EXPERIMENT")
    print("Go/no-go: does temporal context lift Stage 1 recall on hidden attack types?")
    print()

    unsw_results, temp_cols, cats_te = run_unsw()
    ctu_results = run_ctu13()

    print("=" * 62)
    print("  VERDICT")
    print("=" * 62)
    flow_hidden = {c: unsw_results["Flow only"]["per_type"].get(c, 0) for c in HIDDEN_TYPES}
    comb_hidden = {c: unsw_results["Flow + Temporal"]["per_type"].get(c, 0) for c in HIDDEN_TYPES}
    for cat in sorted(HIDDEN_TYPES):
        f = flow_hidden[cat]
        t = comb_hidden[cat]
        lift = t - f
        verdict = "LIFT" if lift > 0.05 else ("marginal" if lift > 0.01 else "NO LIFT")
        print(f"  {cat:<14}  flow={f:.3f}  +temporal={t:.3f}  delta={lift:+.3f}  [{verdict}]")
    avg_lift = np.mean([comb_hidden[c] - flow_hidden[c] for c in HIDDEN_TYPES])
    print(f"\n  Average recall lift on hidden types: {avg_lift:+.3f}")
    if avg_lift > 0.10:
        print("  >> TEMPORAL FEATURES HELP. Paper claim is supported.")
        print("     Recommendation: use Flow + Temporal as Stage 1 AE input.")
    elif avg_lift > 0.03:
        print("  >> MARGINAL. Some lift but not enough to make a strong claim.")
        print("     Recommendation: investigate which ct_* features drive the lift.")
    else:
        print("  >> NO SIGNIFICANT LIFT. Bottleneck is deeper than behavioral features.")
        print("     Recommendation: graph features (IP fan-out, topology) or payload needed.")

    print()
    plot(unsw_results, ctu_results, temp_cols, cats_te)


if __name__ == "__main__":
    main()
