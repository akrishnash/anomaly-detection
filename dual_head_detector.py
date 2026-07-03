#!/usr/bin/env python3
"""
Dual-Head Two-Stage Detector — Final System Experiment
=======================================================
Wires the theory into one system:

  Stage 1 = flow-AE  UNION  temporal-AE     (OR-fusion, justified by Thm 2:
                                             heads measured conditionally
                                             independent, rho_miss = 0.994)
  Stage 2 = GBM over the flagged pool       (trained on KNOWN attack types only)
  Output  = known-attack alerts + ZERO-DAY CANDIDATE QUEUE

Zero-day protocol (same as zero_day_sim.py, for apples-to-apples):
  Stage 2 trained on 5 known types: Generic, Exploits, DoS, Fuzzers, Reconnaissance
  4 types completely hidden:        Backdoor, Analysis, Shellcode, Worms

Ablations (Stage 1 configs):
  A1  flow-AE only          (= previous baseline, Exp 7b)
  A2  temporal-AE only
  A3  UNION  (proposed)
  A4  INTERSECTION          (control — should collapse recall)

Also reports GPD-calibrated head thresholds (Thm 3) alongside the 95th-pct ones.

Output: graphs/dual_head_results.png
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

from scipy.stats import genpareto
from sklearn.neural_network import MLPRegressor
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.metrics import precision_score, recall_score, f1_score

UNSW_TRAIN = "sample_logs/unsw_nb15/UNSW_NB15_training-set.csv"
UNSW_TEST  = "sample_logs/unsw_nb15/UNSW_NB15_testing-set.csv"
OUT_PNG    = "graphs/dual_head_results.png"

META_COLS  = {"id", "proto", "service", "state", "attack_cat", "label"}
TEMPORAL_COLS = [
    "ct_srv_src", "ct_state_ttl", "ct_dst_ltm", "ct_src_dport_ltm",
    "ct_dst_sport_ltm", "ct_dst_src_ltm", "ct_src_ltm", "ct_srv_dst",
    "sinpkt", "dinpkt", "sjit", "djit", "sttl", "dttl",
]
KNOWN_TYPES  = {"Generic", "Exploits", "DoS", "Fuzzers", "Reconnaissance"}
HIDDEN_TYPES = ["Backdoor", "Analysis", "Shellcode", "Worms"]
AE_PCT  = 95
S2_CONF = 0.55


# ── helpers ───────────────────────────────────────────────────────────────────

def build_matrices(tr, te, cols):
    tr_raw = tr[cols].replace([np.inf, -np.inf], np.nan)
    tr_raw = tr_raw.fillna(tr_raw.median())
    tr_raw = tr_raw.loc[:, tr_raw.var() > 0]
    skewed = tr_raw.skew()[lambda s: s.abs() > 2].index.tolist()
    tr_raw[skewed] = np.log1p(tr_raw[skewed].clip(lower=0))
    sc = StandardScaler().fit(tr_raw.values)

    te_raw = te[tr_raw.columns].replace([np.inf, -np.inf], np.nan)
    te_raw = te_raw.fillna(te_raw.median())
    for c in skewed:
        te_raw[c] = np.log1p(te_raw[c].clip(lower=0))
    return sc.transform(tr_raw.values), sc.transform(te_raw.values)


def train_head(X_tr, y_tr):
    """Train AE on train-normals; return (mse_train_all, mse_train_normal, ae)."""
    X_nrm = X_tr[y_tr == 0]
    dim = X_tr.shape[1]
    ae = MLPRegressor(
        hidden_layer_sizes=(max(dim // 2, 8), max(dim // 4, 4), max(dim // 2, 8)),
        activation="relu", max_iter=300, random_state=42,
        early_stopping=True, validation_fraction=0.1, n_iter_no_change=15,
    )
    ae.fit(X_nrm, X_nrm)
    mse_nrm = np.mean((X_nrm - ae.predict(X_nrm)) ** 2, axis=1)
    mse_tr  = np.mean((X_tr - ae.predict(X_tr)) ** 2, axis=1)
    return ae, mse_tr, mse_nrm


def mse_of(ae, X):
    return np.mean((X - ae.predict(X)) ** 2, axis=1)


def gpd_threshold(nrm_scores, q, p_u=0.10):
    u = np.quantile(nrm_scores, 1 - p_u)
    exc = nrm_scores[nrm_scores > u] - u
    xi, _, sigma = genpareto.fit(exc, floc=0)
    if abs(xi) < 1e-9:
        return u + sigma * np.log(p_u / q), xi
    return u + (sigma / xi) * ((p_u / q) ** xi - 1), xi


def run_pipeline(name, flags_tr, flags_te, X_all_tr, X_all_te,
                 cats_tr, cats_te, y_te):
    """Stage 2 (GBM, known types only) over a given Stage 1 flag set."""
    known_mask = np.array([(c == "Normal" or c in KNOWN_TYPES) for c in cats_tr])
    idx = flags_tr & known_mask
    le  = LabelEncoder().fit(cats_tr[idx])
    clf = GradientBoostingClassifier(n_estimators=200, max_depth=4,
                                     learning_rate=0.1, random_state=42)
    print(f"\n  [{name}] Stage 2 training on {idx.sum():,} flagged known-type flows ...")
    clf.fit(X_all_tr[idx], le.transform(cats_tr[idx]))

    Xf        = X_all_te[flags_te]
    cats_f    = cats_te[flags_te]
    y_f       = y_te[flags_te]
    proba     = clf.predict_proba(Xf)
    conf      = proba.max(axis=1)
    pred_cat  = le.inverse_transform(clf.predict(Xf))

    high = conf >= S2_CONF
    low  = ~high

    # zero-day queue
    zd_cats = cats_f[low]
    zd_y    = y_f[low]
    zd_prec = (zd_y == 1).mean() if len(zd_y) else 0.0

    # hidden-type accounting
    hidden_stats = {}
    misclassified_hidden = 0
    for cat in HIDDEN_TYPES:
        total   = (cats_te == cat).sum()
        s1      = (cats_f == cat).sum()
        queue   = (zd_cats == cat).sum()
        wrong   = ((cats_f == cat) & high & (pred_cat != "Normal")).sum()
        misclassified_hidden += wrong
        hidden_stats[cat] = {"total": int(total), "s1": int(s1),
                             "queue": int(queue), "wrong": int(wrong)}

    # binary pipeline prediction: attack if (high-conf non-Normal) or in queue
    final = np.zeros(len(y_te), dtype=int)
    fidx  = np.where(flags_te)[0]
    final[fidx[high]] = (pred_cat[high] != "Normal").astype(int)
    final[fidx[low]]  = 1

    prec = precision_score(y_te, final, zero_division=0)
    rec  = recall_score(y_te, final, zero_division=0)
    f1   = f1_score(y_te, final, zero_division=0)
    fp   = int(((final == 1) & (y_te == 0)).sum())

    print(f"    Pipeline: Precision={prec:.3f}  Recall={rec:.3f}  F1={f1:.3f}  FP={fp:,}")
    print(f"    Zero-day queue: {len(zd_y):,} flows | precision {zd_prec:.3f} "
          f"({(zd_y==1).sum():,} real attacks)")
    print(f"    Hidden-type flows misclassified as KNOWN attacks: {misclassified_hidden}")
    print(f"    {'Hidden type':<12} {'total':>6} {'S1 flagged':>11} {'ZD queue':>9} {'end-to-end':>11}")
    for cat in HIDDEN_TYPES:
        h = hidden_stats[cat]
        print(f"    {cat:<12} {h['total']:>6,} {h['s1']:>11,} {h['queue']:>9,} "
              f"{h['queue']/max(h['total'],1)*100:>10.1f}%")

    return {"name": name, "prec": prec, "rec": rec, "f1": f1, "fp": fp,
            "zd_n": len(zd_y), "zd_prec": zd_prec,
            "zd_real": int((zd_y == 1).sum()),
            "hidden": hidden_stats, "mis_hidden": misclassified_hidden}


# ── main ──────────────────────────────────────────────────────────────────────

def main():
    print("DUAL-HEAD TWO-STAGE DETECTOR — final system experiment")
    print(f"Known types : {sorted(KNOWN_TYPES)}")
    print(f"Hidden types: {HIDDEN_TYPES}\n")

    tr = pd.read_csv(UNSW_TRAIN)
    te = pd.read_csv(UNSW_TEST)
    y_tr, y_te = tr["label"].values, te["label"].values
    cats_tr = tr["attack_cat"].str.strip().values
    cats_te = te["attack_cat"].str.strip().values

    all_feat  = [c for c in tr.columns if c not in META_COLS]
    temp_cols = [c for c in TEMPORAL_COLS if c in tr.columns]
    flow_cols = [c for c in all_feat if c not in temp_cols]

    print("[*] Building matrices + training heads ...")
    Xf_tr, Xf_te = build_matrices(tr, te, flow_cols)
    Xt_tr, Xt_te = build_matrices(tr, te, temp_cols)
    Xa_tr, Xa_te = build_matrices(tr, te, all_feat)   # Stage 2 feature space

    ae_f, msef_tr, msef_nrm = train_head(Xf_tr, y_tr)
    ae_t, mset_tr, mset_nrm = train_head(Xt_tr, y_tr)
    msef_te = mse_of(ae_f, Xf_te)
    mset_te = mse_of(ae_t, Xt_te)

    thr_f = np.percentile(msef_nrm, AE_PCT)
    thr_t = np.percentile(mset_nrm, AE_PCT)

    b1_tr, b2_tr = msef_tr > thr_f, mset_tr > thr_t
    b1_te, b2_te = msef_te > thr_f, mset_te > thr_t

    # ── Stage 1 ablation ─────────────────────────────────────────────────────
    configs = {
        "A1 flow only":    (b1_tr,          b1_te),
        "A2 temporal only":(b2_tr,          b2_te),
        "A3 UNION":        (b1_tr | b2_tr,  b1_te | b2_te),
        "A4 INTERSECTION": (b1_tr & b2_tr,  b1_te & b2_te),
    }

    atk, nrm = y_te == 1, y_te == 0
    print("\n" + "=" * 70)
    print("  STAGE 1 ABLATION (UNSW-NB15 test)")
    print("=" * 70)
    print(f"  {'Config':<18} {'TPR':>6} {'FPR':>6} | " +
          " ".join(f"{c[:6]:>6}" for c in HIDDEN_TYPES))
    print("  " + "-" * 66)
    s1_abl = {}
    for name, (ftr, fte) in configs.items():
        tpr, fpr = fte[atk].mean(), fte[nrm].mean()
        per_hidden = [fte[cats_te == c].mean() for c in HIDDEN_TYPES]
        s1_abl[name] = {"tpr": tpr, "fpr": fpr, "hidden": per_hidden}
        print(f"  {name:<18} {tpr:>6.3f} {fpr:>6.3f} | " +
              " ".join(f"{v:>6.2f}" for v in per_hidden))

    # ── GPD thresholds (Thm 3 tie-in) ────────────────────────────────────────
    print("\n  GPD-calibrated head thresholds (target q=0.02 per head):")
    for lbl, nrm_scores, te_scores in [("flow", msef_nrm, msef_te),
                                        ("temporal", mset_nrm, mset_te)]:
        t_g, xi = gpd_threshold(nrm_scores, q=0.02)
        realized = (te_scores[nrm] > t_g).mean()
        print(f"    {lbl:<9} xi={xi:>6.3f}  t_q={t_g:.4f}  realized FPR={realized:.4f} (target 0.02)")

    # ── Full pipelines: baseline vs dual-head ────────────────────────────────
    print("\n" + "=" * 70)
    print("  FULL PIPELINE + ZERO-DAY SIMULATION")
    print("=" * 70)
    res_base = run_pipeline("BASELINE: flow-only Stage 1", b1_tr, b1_te,
                            Xa_tr, Xa_te, cats_tr, cats_te, y_te)
    res_dual = run_pipeline("DUAL-HEAD: union Stage 1", b1_tr | b2_tr, b1_te | b2_te,
                            Xa_tr, Xa_te, cats_tr, cats_te, y_te)

    # ── Summary ──────────────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("  SUMMARY — baseline vs dual-head")
    print("=" * 70)
    print(f"  {'Metric':<32} {'flow-only':>10} {'dual-head':>10}")
    print("  " + "-" * 54)
    print(f"  {'Pipeline recall':<32} {res_base['rec']:>10.3f} {res_dual['rec']:>10.3f}")
    print(f"  {'Pipeline precision':<32} {res_base['prec']:>10.3f} {res_dual['prec']:>10.3f}")
    print(f"  {'Pipeline F1':<32} {res_base['f1']:>10.3f} {res_dual['f1']:>10.3f}")
    print(f"  {'ZD queue size':<32} {res_base['zd_n']:>10,} {res_dual['zd_n']:>10,}")
    print(f"  {'ZD queue precision':<32} {res_base['zd_prec']:>10.3f} {res_dual['zd_prec']:>10.3f}")
    print(f"  {'Hidden misclassified as known':<32} {res_base['mis_hidden']:>10} {res_dual['mis_hidden']:>10}")
    for cat in HIDDEN_TYPES:
        b = res_base["hidden"][cat]; d = res_dual["hidden"][cat]
        print(f"  {'  ' + cat + ' end-to-end':<32} "
              f"{b['queue']/max(b['total'],1)*100:>9.1f}% {d['queue']/max(d['total'],1)*100:>9.1f}%")

    plot(s1_abl, res_base, res_dual)


def plot(s1_abl, res_base, res_dual):
    os.makedirs("graphs", exist_ok=True)
    fig = plt.figure(figsize=(19, 6.5), facecolor="#F4F6FA")
    fig.suptitle("Dual-Head Two-Stage Detector: Ablation + Zero-Day Simulation (UNSW-NB15)",
                 fontsize=13, fontweight="bold", y=0.99)
    gs = gridspec.GridSpec(1, 3, figure=fig, wspace=0.34,
                           left=0.055, right=0.98, top=0.85, bottom=0.16)
    BG = "#EAEFF7"
    CMAP = {"A1 flow only": "#E53935", "A2 temporal only": "#FB8C00",
            "A3 UNION": "#1565C0", "A4 INTERSECTION": "#78909C"}

    # Panel 1: Stage 1 ablation TPR/FPR
    ax1 = fig.add_subplot(gs[0]); ax1.set_facecolor(BG)
    names = list(s1_abl.keys())
    x = np.arange(len(names)); w = 0.36
    tprs = [s1_abl[n]["tpr"] for n in names]
    fprs = [s1_abl[n]["fpr"] for n in names]
    b1 = ax1.bar(x - w/2, tprs, w, color=[CMAP[n] for n in names], alpha=0.88, label="TPR (recall)")
    b2 = ax1.bar(x + w/2, fprs, w, color=[CMAP[n] for n in names], alpha=0.35, label="FPR")
    for bar, v in list(zip(b1, tprs)) + list(zip(b2, fprs)):
        ax1.text(bar.get_x()+bar.get_width()/2, v+0.006, f"{v:.2f}",
                 ha="center", fontsize=8.5, fontweight="bold")
    ax1.set_xticks(x); ax1.set_xticklabels([n.replace(" ", "\n", 1) for n in names], fontsize=8)
    ax1.set_ylabel("rate"); ax1.set_ylim(0, max(tprs)*1.3)
    ax1.set_title("Stage 1 ablation\nUnion wins; intersection collapses (control)",
                  fontweight="bold", fontsize=10, loc="left")
    ax1.legend(fontsize=8); ax1.grid(True, alpha=0.25, ls="--", axis="y")

    # Panel 2: hidden-type end-to-end, baseline vs dual
    ax2 = fig.add_subplot(gs[1]); ax2.set_facecolor(BG)
    x2 = np.arange(len(HIDDEN_TYPES)); w2 = 0.36
    base_v = [res_base["hidden"][c]["queue"]/max(res_base["hidden"][c]["total"],1)*100
              for c in HIDDEN_TYPES]
    dual_v = [res_dual["hidden"][c]["queue"]/max(res_dual["hidden"][c]["total"],1)*100
              for c in HIDDEN_TYPES]
    bb = ax2.bar(x2 - w2/2, base_v, w2, color="#E53935", alpha=0.85, label="flow-only pipeline")
    bd = ax2.bar(x2 + w2/2, dual_v, w2, color="#1565C0", alpha=0.85, label="dual-head pipeline")
    for bar, v in list(zip(bb, base_v)) + list(zip(bd, dual_v)):
        ax2.text(bar.get_x()+bar.get_width()/2, v+0.3, f"{v:.1f}%",
                 ha="center", fontsize=8.5, fontweight="bold")
    ax2.set_xticks(x2); ax2.set_xticklabels(HIDDEN_TYPES, fontsize=9)
    ax2.set_ylabel("% of hidden-type flows reaching zero-day queue")
    ax2.set_title("Zero-day end-to-end detection\n(hidden attack families, never seen by Stage 2)",
                  fontweight="bold", fontsize=10, loc="left")
    ax2.legend(fontsize=8.5); ax2.grid(True, alpha=0.25, ls="--", axis="y")

    # Panel 3: pipeline metrics + queue
    ax3 = fig.add_subplot(gs[2]); ax3.set_facecolor(BG)
    metrics = ["Recall", "Precision", "F1", "ZD queue\nprecision"]
    base_m = [res_base["rec"], res_base["prec"], res_base["f1"], res_base["zd_prec"]]
    dual_m = [res_dual["rec"], res_dual["prec"], res_dual["f1"], res_dual["zd_prec"]]
    x3 = np.arange(len(metrics)); w3 = 0.36
    b3 = ax3.bar(x3 - w3/2, base_m, w3, color="#E53935", alpha=0.85, label="flow-only")
    d3 = ax3.bar(x3 + w3/2, dual_m, w3, color="#1565C0", alpha=0.85, label="dual-head")
    for bar, v in list(zip(b3, base_m)) + list(zip(d3, dual_m)):
        ax3.text(bar.get_x()+bar.get_width()/2, v+0.01, f"{v:.2f}",
                 ha="center", fontsize=8.5, fontweight="bold")
    ax3.set_xticks(x3); ax3.set_xticklabels(metrics, fontsize=9)
    ax3.set_ylim(0, 1.12)
    ax3.set_title("Full pipeline: flow-only vs dual-head\n(Stage 2 identical; only Stage 1 changes)",
                  fontweight="bold", fontsize=10, loc="left")
    ax3.legend(fontsize=8.5); ax3.grid(True, alpha=0.25, ls="--", axis="y")

    plt.savefig(OUT_PNG, dpi=150, bbox_inches="tight", facecolor=fig.get_facecolor())
    print(f"\n[+] Figure saved -> {OUT_PNG}")


if __name__ == "__main__":
    main()
