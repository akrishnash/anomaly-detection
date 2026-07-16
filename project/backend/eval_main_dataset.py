"""
Joins every CICDDoS2019 *-testing.parquet into a single data/CICDDos2019/
main_dataset.csv, then runs the full production pipeline on that CSV
(canonical preprocessing -> Stage 1 IF+AE ensemble -> Stage 2 rule engine)
and reports how accurately the system segregates DDoS attacks:

  1. Stage 1 binary detection: accuracy / precision / recall / F1
  2. Stage 2 subtype segregation: cross-tab of ground-truth Label vs verdict,
     plus per-label detection rate and dominant verdict.

Writes the full report to project/models/main_dataset_eval.json.
"""
import os
import sys
import glob
import json
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import preprocessing
import anomaly_detector
import ddos_classifier

DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "data", "CICDDos2019"))
MODELS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "models"))
MAIN_CSV = os.path.join(DATA_DIR, "main_dataset.csv")
THRESHOLD = 0.5

# Verdict family each ground-truth label should ideally land in (given that
# this dataset export carries no ports, reflection labels can only reach the
# port-less "Amplification Attack (unknown service)" verdict).
EXPECTED_FAMILY = {
    "DrDoS_DNS": "Amplification", "DrDoS_LDAP": "Amplification",
    "DrDoS_MSSQL": "Amplification", "DrDoS_NTP": "Amplification",
    "DrDoS_NetBIOS": "Amplification", "DrDoS_SNMP": "Amplification",
    "DrDoS_UDP": "UDP Flood", "TFTP": "Amplification",
    "Syn": "SYN Flood", "UDP-lag": "UDP Flood", "WebDDoS": "HTTP Flood",
}


def build_main_dataset() -> pd.DataFrame:
    files = sorted(glob.glob(os.path.join(DATA_DIR, "*-testing.parquet")))
    if not files:
        raise FileNotFoundError(f"No *-testing.parquet files in {DATA_DIR}")
    frames = [pd.read_parquet(f) for f in files]
    df = pd.concat(frames, ignore_index=True)
    df.to_csv(MAIN_CSV, index=False)
    size_mb = os.path.getsize(MAIN_CSV) / 1e6
    print(f"[+] Joined {len(files)} testing parquet files -> {MAIN_CSV}")
    print(f"    {len(df)} rows, {len(df.columns)} columns, {size_mb:.1f} MB")
    return df


def main():
    build_main_dataset()

    # Read the CSV back so the evaluation exercises the exact CSV ingestion path
    print("[+] Reading main_dataset.csv back for evaluation...")
    df = pd.read_csv(MAIN_CSV)
    labels = df["Label"].astype(str).values
    y_true = (labels != "Benign").astype(int)

    print("[+] Preprocessing via production canonical-schema pipeline...")
    X_scaled, _, df_canonical = preprocessing.preprocess_dataset(df)
    probs, _, _ = anomaly_detector.score_flows(X_scaled)
    y_pred = (probs >= THRESHOLD).astype(int)

    # ---- Stage 1: binary detection quality ----
    stage1 = {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
    }
    print()
    print("=" * 66)
    print("  STAGE 1 - binary attack detection on main_dataset.csv")
    print("=" * 66)
    print(f"  Flows: {len(df)}  (attack {int(y_true.sum())} / benign {int((y_true == 0).sum())})")
    for k in ("accuracy", "precision", "recall", "f1"):
        print(f"  {k.capitalize():<10}: {stage1[k]:.4f}")

    # ---- Stage 2: subtype verdicts for flows Stage 1 flagged ----
    print()
    print("[+] Running Stage 2 rule engine on flagged flows...")
    df_feats = preprocessing.extract_features(df_canonical)
    flow_records = df_feats.to_dict("records")
    protocols = df_canonical["protocol"].values
    src_ports = df_canonical["src_port"].values
    dst_ports = df_canonical["dst_port"].values

    verdicts = np.empty(len(df), dtype=object)
    for i in range(len(df)):
        if y_pred[i] == 0:
            verdicts[i] = "Normal"
            continue
        rec = flow_records[i]
        rec["protocol"] = protocols[i]
        rec["src_port"] = src_ports[i]
        rec["dst_port"] = dst_ports[i]
        verdicts[i] = ddos_classifier.classify_flow(rec)["attack_type"]

    # Cross-tab: ground truth vs verdict
    ct = pd.crosstab(pd.Series(labels, name="true_label"),
                     pd.Series(verdicts, name="model_verdict"))
    print()
    print("=" * 66)
    print("  STAGE 2 - segregation: ground-truth label vs model verdict")
    print("=" * 66)
    print(ct.to_string())

    # Per-label summary: detection rate, dominant verdict, family match
    print()
    print(f"  {'label':<15} {'flows':>8} {'detected':>9} {'det.rate':>9}  {'dominant verdict':<38} {'family-ok':>9}")
    per_label = {}
    for label in sorted(set(labels)):
        mask = labels == label
        n = int(mask.sum())
        detected_mask = mask & (y_pred == 1)
        detected = int(detected_mask.sum())
        det_verdicts = pd.Series(verdicts[detected_mask])
        dominant = det_verdicts.value_counts().idxmax() if detected else "-"
        expected = EXPECTED_FAMILY.get(label)
        if label == "Benign":
            family_ok = None
            fam_str = "-"
        elif detected == 0:
            family_ok = 0.0
            fam_str = "0.0%"
        else:
            family_ok = float(det_verdicts.str.contains(expected, regex=False).mean()) if expected else None
            fam_str = f"{family_ok * 100:.1f}%" if family_ok is not None else "-"
        per_label[label] = {
            "flows": n, "detected": detected, "detection_rate": detected / n,
            "dominant_verdict": str(dominant), "expected_family": expected,
            "family_match_rate_among_detected": family_ok,
            "verdict_breakdown": det_verdicts.value_counts().to_dict(),
        }
        print(f"  {label:<15} {n:>8} {detected:>9} {detected / n:>9.4f}  {str(dominant):<38} {fam_str:>9}")

    # Aggregate segregation quality among detected attack flows
    attack_detected = (y_true == 1) & (y_pred == 1)
    fam_hits = 0
    for i in np.where(attack_detected)[0]:
        exp = EXPECTED_FAMILY.get(labels[i])
        if exp and exp in verdicts[i]:
            fam_hits += 1
    seg_acc = fam_hits / attack_detected.sum() if attack_detected.sum() else 0.0
    print()
    print(f"  Subtype segregation accuracy (detected attack flows whose verdict")
    print(f"  matches the expected family): {seg_acc:.4f} ({fam_hits}/{int(attack_detected.sum())})")
    print("=" * 66)

    report = {
        "dataset": "main_dataset.csv (all CICDDoS2019 testing parquets joined)",
        "rows": int(len(df)),
        "threshold": THRESHOLD,
        "stage1_binary": stage1,
        "stage2_segregation_accuracy_among_detected": seg_acc,
        "per_label": per_label,
        "crosstab": ct.to_dict(),
    }
    out = os.path.join(MODELS_DIR, "main_dataset_eval.json")
    with open(out, "w") as f:
        json.dump(report, f, indent=2)
    print(f"[+] Wrote full report to {out}")


if __name__ == "__main__":
    main()
