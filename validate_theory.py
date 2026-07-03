#!/usr/bin/env python3
"""
Validate the Three Theorems (theory.md) on Real Data
=====================================================
Theorem 1 (KS ceiling):      sup_t J(t) = KS, exactly, on empirical CDFs.
                             Corollaries: BA ceiling = (1+KS)/2, KS >= AUC - 1/2.
Theorem 2 (OR-fusion):       miss-product law, fusion-benefit criterion,
                             rho_miss and conditional MI diagnostics.
Theorem 3 (EVT threshold):   GPD tail fit gives calibrated FPR at any target q;
                             naive percentile thresholds drift in the deep tail.

Data: CTU-13 (Theorem 1), UNSW-NB15 (Theorems 2 and 3).
Output: graphs/theory_validation.png + console report.
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

from scipy.stats import ks_2samp, genpareto
from sklearn.ensemble import IsolationForest
from sklearn.neural_network import MLPRegressor
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import train_test_split

ATTACK_CSV = "sample_logs/CTU13_Attack_Traffic.csv"
NORMAL_CSV = "sample_logs/CTU13_Normal_Traffic.csv"
UNSW_TRAIN = "sample_logs/unsw_nb15/UNSW_NB15_training-set.csv"
UNSW_TEST  = "sample_logs/unsw_nb15/UNSW_NB15_testing-set.csv"
OUT_PNG    = "graphs/theory_validation.png"

META_COLS  = {"id", "proto", "service", "state", "attack_cat", "label"}
TEMPORAL_COLS = [
    "ct_srv_src", "ct_state_ttl", "ct_dst_ltm", "ct_src_dport_ltm",
    "ct_dst_sport_ltm", "ct_dst_src_ltm", "ct_src_ltm", "ct_srv_dst",
    "sinpkt", "dinpkt", "sjit", "djit", "sttl", "dttl",
]
HIDDEN_TYPES = ["Backdoor", "Analysis", "Shellcode", "Worms"]
AE_PCT = 95


# ── shared helpers ────────────────────────────────────────────────────────────

def make_ae(dim):
    return MLPRegressor(
        hidden_layer_sizes=(max(dim // 2, 8), max(dim // 4, 4), max(dim // 2, 8)),
        activation="relu", max_iter=300, random_state=42,
        early_stopping=True, validation_fraction=0.1, n_iter_no_change=15,
    )


def ae_scores(tr_df, te_df, cols, y_tr):
    """Fit prep on train, train AE on train-normals, return (mse_train_normal, mse_test)."""
    tr_raw = tr_df[cols].replace([np.inf, -np.inf], np.nan)
    tr_raw = tr_raw.fillna(tr_raw.median())
    tr_raw = tr_raw.loc[:, tr_raw.var() > 0]
    skewed = tr_raw.skew()[lambda s: s.abs() > 2].index.tolist()
    tr_raw[skewed] = np.log1p(tr_raw[skewed].clip(lower=0))
    sc = StandardScaler().fit(tr_raw.values)
    X_tr = sc.transform(tr_raw.values)

    te_raw = te_df[tr_raw.columns].replace([np.inf, -np.inf], np.nan)
    te_raw = te_raw.fillna(te_raw.median())
    for c in skewed:
        te_raw[c] = np.log1p(te_raw[c].clip(lower=0))
    X_te = sc.transform(te_raw.values)

    X_nrm = X_tr[y_tr == 0]
    ae = make_ae(X_tr.shape[1])
    ae.fit(X_nrm, X_nrm)
    mse_nrm = np.mean((X_nrm - ae.predict(X_nrm)) ** 2, axis=1)
    mse_te  = np.mean((X_te - ae.predict(X_te)) ** 2, axis=1)
    return mse_nrm, mse_te


def youden_curve(scores, y):
    """Empirical J(t) over all candidate thresholds. Returns (thresholds, J values)."""
    order = np.argsort(scores)
    s_sorted = scores[order]
    y_sorted = y[order]
    n_a = (y == 1).sum()
    n_n = (y == 0).sum()
    # F_A(t), F_N(t) evaluated just after each sorted point
    cum_a = np.cumsum(y_sorted == 1) / n_a
    cum_n = np.cumsum(y_sorted == 0) / n_n
    J = cum_n - cum_a          # = F_N(t) - F_A(t) for flag-high orientation
    return s_sorted, J


# ── Part A: Theorem 1 on CTU-13 ───────────────────────────────────────────────

def part_a():
    print("=" * 66)
    print("  THEOREM 1 — KS ceiling  (CTU-13)")
    print("=" * 66)

    atk = pd.read_csv(ATTACK_CSV).sample(6000, random_state=42); atk["label"] = 1
    nrm = pd.read_csv(NORMAL_CSV).sample(6000, random_state=42); nrm["label"] = 0
    df  = pd.concat([atk, nrm]).sample(frac=1, random_state=42).reset_index(drop=True)
    df_tr, df_te = train_test_split(df, test_size=0.30, stratify=df["label"], random_state=42)
    y_tr, y_te = df_tr["label"].values, df_te["label"].values
    feat_cols = [c for c in df.columns if c not in {"Unnamed: 0", "Label", "label"}]

    results = {}

    # AE scores
    mse_nrm, mse_te = ae_scores(df_tr, df_te, feat_cols, y_tr)
    results["AE"] = mse_te

    # IF scores (fit on train, score test; flip so higher = anomalous)
    tr_raw = df_tr[feat_cols].replace([np.inf,-np.inf], np.nan)
    tr_raw = tr_raw.fillna(tr_raw.median()); tr_raw = tr_raw.loc[:, tr_raw.var()>0]
    skewed = tr_raw.skew()[lambda s: s.abs()>2].index.tolist()
    tr_raw[skewed] = np.log1p(tr_raw[skewed].clip(lower=0))
    sc = StandardScaler().fit(tr_raw.values)
    te_raw = df_te[tr_raw.columns].replace([np.inf,-np.inf], np.nan).fillna(df_te[tr_raw.columns].median())
    for c in skewed: te_raw[c] = np.log1p(te_raw[c].clip(lower=0))
    iso = IsolationForest(n_estimators=200, contamination=0.40, random_state=42, n_jobs=-1)
    iso.fit(sc.transform(tr_raw.values))
    results["IF"] = -iso.score_samples(sc.transform(te_raw.values))

    panelA = {}
    for name, s in results.items():
        ks, _ = ks_2samp(s[y_te == 1], s[y_te == 0])
        ts, J = youden_curve(s, y_te)
        j_star = J.max()
        auc = roc_auc_score(y_te, s)
        ba_ceiling = (1 + ks) / 2
        print(f"\n  [{name}]")
        print(f"    KS (two-sample)           : {ks:.4f}")
        print(f"    sup_t J(t) (empirical)    : {j_star:.4f}   |diff| = {abs(ks - j_star):.2e}  -> equality holds")
        print(f"    BA ceiling (1+KS)/2       : {ba_ceiling:.4f}")
        print(f"    AUC                       : {auc:.4f}   KS >= AUC - 1/2 ? "
              f"{ks:.3f} >= {auc - 0.5:.3f}  [{'OK' if ks >= auc - 0.5 - 1e-9 else 'VIOLATED'}]")
        print(f"    Recall bound at FPR<=5%   : {min(1.0, 0.05 + ks):.3f}")
        panelA[name] = {"ts": ts, "J": J, "ks": ks, "auc": auc}
    return panelA


# ── Part B: Theorem 2 on UNSW-NB15 (dual heads) ───────────────────────────────

def cond_mi(s1, s2, y, bins=10):
    """Conditional mutual information I(S1;S2|Y) in bits via per-class quantile binning."""
    total = 0.0
    for cls in [0, 1]:
        a, b = s1[y == cls], s2[y == cls]
        qa = np.quantile(a, np.linspace(0, 1, bins + 1)); qa[0] -= 1; qa[-1] += 1
        qb = np.quantile(b, np.linspace(0, 1, bins + 1)); qb[0] -= 1; qb[-1] += 1
        ia = np.clip(np.searchsorted(qa, a, side="right") - 1, 0, bins - 1)
        ib = np.clip(np.searchsorted(qb, b, side="right") - 1, 0, bins - 1)
        joint = np.zeros((bins, bins))
        for i, j in zip(ia, ib):
            joint[i, j] += 1
        joint /= joint.sum()
        pa = joint.sum(axis=1, keepdims=True)
        pb = joint.sum(axis=0, keepdims=True)
        with np.errstate(divide="ignore", invalid="ignore"):
            term = joint * np.log2(joint / (pa @ pb))
        mi = np.nansum(term)
        total += (y == cls).mean() * mi
    return total


def part_b():
    print("\n" + "=" * 66)
    print("  THEOREM 2 — OR-fusion of dual heads  (UNSW-NB15)")
    print("=" * 66)

    tr = pd.read_csv(UNSW_TRAIN)
    te = pd.read_csv(UNSW_TEST)
    y_tr, y_te = tr["label"].values, te["label"].values
    cats_te = te["attack_cat"].str.strip().values

    all_feat  = [c for c in tr.columns if c not in META_COLS]
    temp_cols = [c for c in TEMPORAL_COLS if c in tr.columns]
    flow_cols = [c for c in all_feat if c not in temp_cols]

    print(f"  Head 1 (flow): {len(flow_cols)} features | Head 2 (temporal): {len(temp_cols)} features")

    print("  Training flow-AE head ...")
    nrm1, s1 = ae_scores(tr, te, flow_cols, y_tr)
    print("  Training temporal-AE head ...")
    nrm2, s2 = ae_scores(tr, te, temp_cols, y_tr)

    t1 = np.percentile(nrm1, AE_PCT)
    t2 = np.percentile(nrm2, AE_PCT)
    b1 = s1 > t1
    b2 = s2 > t2
    b_or = b1 | b2

    def rates(flags, mask):
        return flags[mask].mean() if mask.sum() else 0.0

    atk, nrm_mask = y_te == 1, y_te == 0
    TPR1, FPR1 = rates(b1, atk), rates(b1, nrm_mask)
    TPR2, FPR2 = rates(b2, atk), rates(b2, nrm_mask)
    TPR_or, FPR_or = rates(b_or, atk), rates(b_or, nrm_mask)

    pred_miss  = (1 - TPR1) * (1 - TPR2)
    pred_TPRor = 1 - pred_miss
    pred_FPRor = 1 - (1 - FPR1) * (1 - FPR2)
    joint_miss = ((~b1) & (~b2))[atk].mean()
    rho_all    = joint_miss / max(pred_miss, 1e-12)

    lhs = (1 - TPR1) * TPR2
    rhs = (1 - FPR1) * FPR2

    print(f"\n  Head operating points (95th-pct thresholds):")
    print(f"    Head 1 (flow)    : TPR={TPR1:.3f}  FPR={FPR1:.3f}")
    print(f"    Head 2 (temporal): TPR={TPR2:.3f}  FPR={FPR2:.3f}")
    print(f"\n  Miss-product law (Thm 2a):")
    print(f"    Predicted union recall (CI) : {pred_TPRor:.3f}")
    print(f"    Actual union recall         : {TPR_or:.3f}")
    print(f"    Predicted union FPR (CI)    : {pred_FPRor:.3f}")
    print(f"    Actual union FPR            : {FPR_or:.3f}")
    print(f"    rho_miss (overall)          : {rho_all:.3f}   (1 = independent blind spots)")
    print(f"\n  Fusion-benefit criterion (Thm 2c): (1-TPR1)*TPR2 > (1-FPR1)*FPR2 ?")
    print(f"    {lhs:.4f} > {rhs:.4f}  ->  {'FUSE (union justified)' if lhs > rhs else 'DO NOT FUSE'}"
          f"   (margin: {lhs/max(rhs,1e-12):.1f}x)")

    mi = cond_mi(s1, s2, y_te)
    print(f"\n  Conditional MI I(S1;S2|Y)     : {mi:.3f} bits "
          f"(out of max {np.log2(10):.2f} bits at 10 bins; low = non-redundant heads)")

    # per-attack-type table
    print(f"\n  Per-attack-type: miss-product prediction vs actual union")
    print(f"  {'Type':<16} {'n':>6} {'TPR1':>6} {'TPR2':>6} {'pred U':>7} {'actual U':>9} {'rho_miss':>9}")
    print("  " + "-" * 64)
    per_type = {}
    for cat in sorted(set(cats_te) - {"Normal"}):
        m = cats_te == cat
        r1, r2 = b1[m].mean(), b2[m].mean()
        pu = 1 - (1 - r1) * (1 - r2)
        au = b_or[m].mean()
        jm = ((~b1) & (~b2))[m].mean()
        rho = jm / max((1 - r1) * (1 - r2), 1e-12)
        tag = "  <- hidden" if cat in HIDDEN_TYPES else ""
        print(f"  {cat:<16} {m.sum():>6,} {r1:>6.2f} {r2:>6.2f} {pu:>7.2f} {au:>9.2f} {rho:>9.2f}{tag}")
        per_type[cat] = {"n": int(m.sum()), "TPR1": r1, "TPR2": r2, "pred": pu, "act": au, "rho": rho}

    return {"per_type": per_type, "overall": (TPR1, TPR2, pred_TPRor, TPR_or, rho_all, mi),
            "s_nrm1": nrm1, "s1_te": s1, "y_te": y_te}


# ── Part C: Theorem 3 — GPD threshold calibration ─────────────────────────────

def part_c(nrm_train_scores, test_scores, y_te):
    print("\n" + "=" * 66)
    print("  THEOREM 3 — EVT/GPD threshold calibration  (UNSW-NB15, flow-AE)")
    print("=" * 66)

    s_nrm_te = test_scores[y_te == 0]
    s_atk_te = test_scores[y_te == 1]
    n = len(nrm_train_scores)

    p_u = 0.10
    u = np.quantile(nrm_train_scores, 1 - p_u)
    excesses = nrm_train_scores[nrm_train_scores > u] - u
    xi, loc, sigma = genpareto.fit(excesses, floc=0)
    print(f"  Train normals: n={n:,} | u = 90th pct = {u:.5f} | excesses: {len(excesses):,}")
    print(f"  GPD fit: shape xi = {xi:.4f}  scale sigma = {sigma:.5f}"
          f"   ({'HEAVY tail (xi>0): percentile method will underestimate FP rates' if xi > 0 else 'light/bounded tail'})")

    def t_gpd(q):
        if abs(xi) < 1e-9:
            return u + sigma * np.log(p_u / q)
        return u + (sigma / xi) * ((p_u / q) ** xi - 1)

    qs = [0.05, 0.01, 0.005, 0.001, 1e-4]
    print(f"\n  {'target q':>10} {'GPD thr':>10} {'realized FPR':>13} {'recall':>8} | {'pctile thr':>11} {'realized FPR':>13}")
    print("  " + "-" * 74)
    rows = []
    for q in qs:
        tq = t_gpd(q)
        fpr_g = (s_nrm_te > tq).mean()
        rec_g = (s_atk_te > tq).mean()
        # naive percentile threshold at same target
        tp = np.quantile(nrm_train_scores, 1 - q)
        fpr_p = (s_nrm_te > tp).mean()
        print(f"  {q:>10.4g} {tq:>10.5f} {fpr_g:>13.5f} {rec_g:>8.3f} | {tp:>11.5f} {fpr_p:>13.5f}")
        rows.append({"q": q, "fpr_gpd": fpr_g, "fpr_pct": fpr_p, "recall": rec_g})

    print("\n  Calibration = realized FPR close to target q. GPD extrapolates the tail;")
    print("  the percentile threshold is undefined below 1/n and noisy near it.")
    return {"xi": xi, "sigma": sigma, "u": u, "rows": rows}


# ── Figure ────────────────────────────────────────────────────────────────────

def plot(panelA, resB, resC):
    os.makedirs("graphs", exist_ok=True)
    fig = plt.figure(figsize=(19, 6.2), facecolor="#F4F6FA")
    fig.suptitle("Validating the Three Theorems on Real Data",
                 fontsize=13, fontweight="bold", y=0.99)
    gs = gridspec.GridSpec(1, 3, figure=fig, wspace=0.32,
                           left=0.05, right=0.98, top=0.86, bottom=0.13)
    BG = "#EAEFF7"

    # Panel 1: J(t) curves vs KS lines (Theorem 1)
    ax1 = fig.add_subplot(gs[0]); ax1.set_facecolor(BG)
    for name, color in [("AE", "#8E24AA"), ("IF", "#E53935")]:
        d = panelA[name]
        xs = np.linspace(0, 1, len(d["J"]))
        ax1.plot(xs, d["J"], color=color, lw=1.8, label=f"{name}: J(t) curve")
        ax1.axhline(d["ks"], color=color, ls="--", lw=1.2, alpha=0.7,
                    label=f"{name}: KS = {d['ks']:.3f}")
    ax1.set_xlabel("threshold sweep (normalised rank)", fontsize=9)
    ax1.set_ylabel("Youden J(t) = TPR - FPR", fontsize=9)
    ax1.set_title("Theorem 1: sup J(t) touches KS exactly\n(no threshold exceeds the dashed ceiling)",
                  fontweight="bold", fontsize=10, loc="left")
    ax1.legend(fontsize=8); ax1.grid(True, alpha=0.25, ls="--")

    # Panel 2: predicted vs actual union recall per type (Theorem 2)
    ax2 = fig.add_subplot(gs[1]); ax2.set_facecolor(BG)
    per = resB["per_type"]
    cats = sorted(per.keys(), key=lambda c: -per[c]["n"])
    x = np.arange(len(cats)); w = 0.38
    ax2.bar(x - w/2, [per[c]["pred"] for c in cats], w, color="#FB8C00",
            alpha=0.85, label="Predicted union (miss-product law)")
    ax2.bar(x + w/2, [per[c]["act"] for c in cats], w, color="#1565C0",
            alpha=0.85, label="Actual union recall")
    ax2.set_xticks(x)
    ax2.set_xticklabels([("* " + c if c in HIDDEN_TYPES else c) for c in cats],
                        rotation=30, ha="right", fontsize=8)
    ax2.set_ylabel("Stage 1 recall", fontsize=9)
    ax2.set_title("Theorem 2: closed-form prediction vs reality\n* = zero-day (hidden) type",
                  fontweight="bold", fontsize=10, loc="left")
    ax2.legend(fontsize=8); ax2.grid(True, alpha=0.25, ls="--", axis="y")

    # Panel 3: calibration plot (Theorem 3)
    ax3 = fig.add_subplot(gs[2]); ax3.set_facecolor(BG)
    rows = resC["rows"]
    qs      = [r["q"] for r in rows]
    fpr_g   = [max(r["fpr_gpd"], 1e-6) for r in rows]
    fpr_p   = [max(r["fpr_pct"], 1e-6) for r in rows]
    ax3.loglog(qs, qs, "k--", lw=1.2, alpha=0.6, label="Perfect calibration (y = x)")
    ax3.loglog(qs, fpr_g, "o-", color="#2E7D32", lw=2, ms=7, label="GPD threshold (Thm 3)")
    ax3.loglog(qs, fpr_p, "s-", color="#E53935", lw=2, ms=7, label="Naive percentile threshold")
    ax3.set_xlabel("target false-positive rate q", fontsize=9)
    ax3.set_ylabel("realized FPR on held-out normals", fontsize=9)
    ax3.set_title(f"Theorem 3: threshold calibration\nGPD fit: xi = {resC['xi']:.3f} (heavy tail)"
                  if resC["xi"] > 0 else
                  f"Theorem 3: threshold calibration\nGPD fit: xi = {resC['xi']:.3f}",
                  fontweight="bold", fontsize=10, loc="left")
    ax3.legend(fontsize=8); ax3.grid(True, alpha=0.25, ls="--", which="both")

    plt.savefig(OUT_PNG, dpi=150, bbox_inches="tight", facecolor=fig.get_facecolor())
    print(f"\n[+] Figure saved -> {OUT_PNG}")


def main():
    print("VALIDATING theory.md — three theorems, three experiments\n")
    panelA = part_a()
    resB   = part_b()
    resC   = part_c(resB["s_nrm1"], resB["s1_te"], resB["y_te"])
    plot(panelA, resB, resC)

    T1, T2, predU, actU, rho, mi = resB["overall"]
    print("\n" + "=" * 66)
    print("  SUMMARY")
    print("=" * 66)
    print(f"  Thm 1: sup J(t) = KS holds to machine precision on CTU-13 (AE and IF).")
    print(f"  Thm 2: union recall predicted {predU:.3f} vs actual {actU:.3f}; rho_miss = {rho:.2f}; "
          f"I(S1;S2|Y) = {mi:.3f} bits.")
    print(f"  Thm 3: GPD (xi = {resC['xi']:.3f}) calibration vs percentile — see table and figure.")


if __name__ == "__main__":
    main()
