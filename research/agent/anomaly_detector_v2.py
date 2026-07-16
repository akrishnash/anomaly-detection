#!/usr/bin/env python3
"""
Network Anomaly Detection System v2 — Isolation Forest
=======================================================
Accepts:  .pcap / .pcapng / .cap   (parsed via scapy)
          .log  / .csv             (CSV with columns:
                                    timestamp, src_ip, dst_ip, dst_port,
                                    protocol, bytes, status)

For each 5-minute time window per source IP the detector builds a feature
vector and feeds all vectors into scikit-learn IsolationForest.
Flagged windows are then labelled by inspecting which features deviate most
from the normal baseline.

Usage:
  python anomaly_detector_v2.py [file]  [options]

  python anomaly_detector_v2.py sample_logs/network_traffic.log
  python anomaly_detector_v2.py sample_logs/network_traffic.pcap
  python anomaly_detector_v2.py myfile.pcap --contamination 0.03 --window 10min
"""

import sys
import os
import argparse
from pathlib import Path
from datetime import datetime
from collections import defaultdict

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import matplotlib.patches as mpatches
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# ── Defaults ──────────────────────────────────────────────────────────────────
DEFAULT_WINDOW        = "5min"
DEFAULT_CONTAMINATION = 0.02      # expect ~2% of windows to be anomalous
N_ESTIMATORS          = 200
DEDUP_GAP_MINUTES     = 15        # collapse same-type events within this gap

FEATURE_COLS = [
    "n_packets", "n_bytes", "avg_bytes", "std_bytes",
    "n_dst_ports", "n_dst_ips", "failed_ratio",
    "hour_sin", "hour_cos",
]

ANOMALY_COLORS = {
    "Port Scan":          "#FB8C00",
    "Brute Force":        "#8E24AA",
    "Traffic Spike":      "#E53935",
    "Data Exfiltration":  "#4E342E",
    "Night Activity":     "#1565C0",
    "Unknown":            "#757575",
}

SEV_ORDER  = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
SEV_PREFIX = {"CRITICAL": "[!!!]", "HIGH": "[!! ]", "MEDIUM": "[!  ]", "LOW": "[.  ]"}


# ══════════════════════════════════════════════════════════════════════════════
#  PARSERS
# ══════════════════════════════════════════════════════════════════════════════

def _parse_log(filepath: str) -> pd.DataFrame:
    df = pd.read_csv(filepath, parse_dates=["timestamp"])
    required = {"timestamp", "src_ip", "dst_ip", "dst_port", "bytes", "status"}
    missing = required - set(df.columns)
    if missing:
        sys.exit(f"[-] Log file missing columns: {missing}")
    if "protocol" not in df.columns:
        df["protocol"] = "TCP"
    df["flags"] = ""
    df["bytes"] = pd.to_numeric(df["bytes"], errors="coerce").fillna(0).astype(int)
    return df[["timestamp", "src_ip", "dst_ip", "dst_port",
               "protocol", "bytes", "status", "flags"]]


def _parse_pcap(filepath: str) -> pd.DataFrame:
    try:
        from scapy.all import rdpcap, IP, TCP, UDP, ICMP, conf as scapy_conf
        scapy_conf.verb = 0
    except ImportError:
        sys.exit("[-] scapy not installed.  Run:  pip install scapy")

    print("[*] Reading PCAP (may take a moment for large files) ...")
    raw = rdpcap(filepath)

    rows = []
    for pkt in raw:
        if IP not in pkt:
            continue
        ts     = datetime.fromtimestamp(float(pkt.time))
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        size   = len(pkt)

        if TCP in pkt:
            dst_port = pkt[TCP].dport
            protocol = "TCP"
            flags    = str(pkt[TCP].flags)
            # RST flag → failed/rejected connection
            status   = "FAILED" if "R" in flags else "SUCCESS"
        elif UDP in pkt:
            dst_port = pkt[UDP].dport
            protocol = "UDP"
            flags    = ""
            status   = "SUCCESS"
        elif ICMP in pkt:
            dst_port = 0
            protocol = "ICMP"
            flags    = str(pkt[ICMP].type)
            status   = "SUCCESS"
        else:
            continue

        rows.append([ts, src_ip, dst_ip, dst_port, protocol, size, status, flags])

    if not rows:
        sys.exit("[-] No valid IP packets found in PCAP.")

    df = pd.DataFrame(rows, columns=["timestamp", "src_ip", "dst_ip", "dst_port",
                                      "protocol", "bytes", "status", "flags"])
    return df.sort_values("timestamp").reset_index(drop=True)


def load_file(filepath: str) -> pd.DataFrame:
    if not os.path.exists(filepath):
        sys.exit(f"[-] File not found: {filepath}")
    ext = Path(filepath).suffix.lower()
    if ext in {".pcap", ".pcapng", ".cap"}:
        print("[+] Input type : PCAP")
        return _parse_pcap(filepath)
    print("[+] Input type : Log / CSV")
    return _parse_log(filepath)


# ══════════════════════════════════════════════════════════════════════════════
#  FEATURE ENGINEERING
# ══════════════════════════════════════════════════════════════════════════════

def build_features(df: pd.DataFrame, window: str) -> pd.DataFrame:
    """
    Aggregate per (time_window, src_ip) and extract 9 features.
    Cyclical hour encoding keeps 23:00 and 00:00 close in feature space.
    """
    tmp = df.copy()
    tmp["window"]    = tmp["timestamp"].dt.floor(window)
    tmp["hour"]      = tmp["timestamp"].dt.hour
    tmp["is_failed"] = (tmp["status"] == "FAILED").astype(int)

    agg = (
        tmp.groupby(["window", "src_ip"])
        .agg(
            n_packets   = ("bytes",     "count"),
            n_bytes     = ("bytes",     "sum"),
            avg_bytes   = ("bytes",     "mean"),
            std_bytes   = ("bytes",     "std"),
            n_dst_ports = ("dst_port",  "nunique"),
            n_dst_ips   = ("dst_ip",    "nunique"),
            n_failed    = ("is_failed", "sum"),
            hour        = ("hour",      "first"),
        )
        .reset_index()
    )

    agg["failed_ratio"] = agg["n_failed"] / agg["n_packets"]
    agg["std_bytes"]    = agg["std_bytes"].fillna(0)
    agg["hour_sin"]     = np.sin(2 * np.pi * agg["hour"] / 24)
    agg["hour_cos"]     = np.cos(2 * np.pi * agg["hour"] / 24)

    return agg


# ══════════════════════════════════════════════════════════════════════════════
#  ISOLATION FOREST
# ══════════════════════════════════════════════════════════════════════════════

def run_isolation_forest(
    features: pd.DataFrame, contamination: float
) -> tuple[pd.DataFrame, StandardScaler, IsolationForest]:

    X = features[FEATURE_COLS].fillna(0).values

    scaler   = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = IsolationForest(
        n_estimators=N_ESTIMATORS,
        contamination=contamination,
        random_state=42,
        n_jobs=-1,
    )
    features = features.copy()
    features["if_label"] = model.fit_predict(X_scaled)   # -1 = anomaly
    features["if_score"] = model.score_samples(X_scaled)  # lower = more anomalous

    return features, scaler, model


# ══════════════════════════════════════════════════════════════════════════════
#  ANOMALY TYPE CLASSIFICATION
# ══════════════════════════════════════════════════════════════════════════════

def _z(val, mean, std) -> float:
    return (val - mean) / max(std, 1e-9)


def classify_anomaly(row: pd.Series, thresholds: dict) -> tuple[str, str]:
    """
    Rule-based label derived from which features are most deviant.
    Applied only to windows already flagged as anomalous by IF.
    """
    z_ports  = _z(row["n_dst_ports"],  thresholds["ports_mean"],  thresholds["ports_std"])
    z_bytes  = _z(row["n_bytes"],      thresholds["bytes_mean"],  thresholds["bytes_std"])
    z_failed = _z(row["failed_ratio"], thresholds["failed_mean"], thresholds["failed_std"])
    z_avg    = _z(row["avg_bytes"],    thresholds["avg_mean"],    thresholds["avg_std"])

    night = int(row["hour"]) in range(0, 6)

    if z_ports > 3:
        return "Port Scan", "HIGH"
    if z_failed > 2.5 and z_ports <= 3:
        return "Brute Force", "HIGH"
    if z_bytes > 3:
        if z_avg > 2:
            return "Data Exfiltration", "CRITICAL"
        if night:
            return "Night Activity", "CRITICAL"
        return "Traffic Spike", "CRITICAL" if z_bytes > 5 else "HIGH"
    if night:
        return "Night Activity", "MEDIUM"
    return "Unknown", "LOW"


def label_anomalies(features: pd.DataFrame) -> list[dict]:
    flagged = features[features["if_label"] == -1]
    if flagged.empty:
        return []

    normal = features[features["if_label"] == 1]
    thresholds = {
        "ports_mean":  normal["n_dst_ports"].mean(),
        "ports_std":   normal["n_dst_ports"].std(),
        "bytes_mean":  normal["n_bytes"].mean(),
        "bytes_std":   normal["n_bytes"].std(),
        "failed_mean": normal["failed_ratio"].mean(),
        "failed_std":  normal["failed_ratio"].std(),
        "avg_mean":    normal["avg_bytes"].mean(),
        "avg_std":     normal["avg_bytes"].std(),
    }

    results = []
    for _, row in flagged.iterrows():
        atype, severity = classify_anomaly(row, thresholds)
        results.append({
            "timestamp":    row["window"],
            "src_ip":       row["src_ip"],
            "type":         atype,
            "severity":     severity,
            "if_score":     row["if_score"],
            "n_bytes":      row["n_bytes"],
            "n_packets":    row["n_packets"],
            "n_dst_ports":  row["n_dst_ports"],
            "failed_ratio": row["failed_ratio"],
            "hour":         int(row["hour"]),
        })
    raw = sorted(results, key=lambda x: x["timestamp"])
    return _deduplicate(raw)


def _deduplicate(anomalies: list[dict]) -> list[dict]:
    """
    Within each anomaly type, collapse windows that are within DEDUP_GAP_MINUTES
    of the previous one — keeping the entry with the lowest (most anomalous) IF score.
    """
    by_type: dict[str, list] = defaultdict(list)
    for a in anomalies:
        by_type[a["type"]].append(a)

    merged: list[dict] = []
    for atype, group in by_type.items():
        group.sort(key=lambda x: x["timestamp"])
        episode = group[0]
        for curr in group[1:]:
            gap = (curr["timestamp"] - episode["timestamp"]).total_seconds() / 60
            if gap <= DEDUP_GAP_MINUTES:
                # Keep whichever is more anomalous (lower score)
                if curr["if_score"] < episode["if_score"]:
                    episode = curr
            else:
                merged.append(episode)
                episode = curr
        merged.append(episode)

    return sorted(merged, key=lambda x: x["timestamp"])


# ══════════════════════════════════════════════════════════════════════════════
#  CONSOLE REPORT
# ══════════════════════════════════════════════════════════════════════════════

def print_report(anomalies: list[dict]) -> None:
    print("\n" + "=" * 72)
    print("  ISOLATION FOREST  —  ANOMALY DETECTION REPORT")
    print("=" * 72)

    if not anomalies:
        print("  No anomalies detected.")
        print("=" * 72)
        return

    for i, a in enumerate(
        sorted(anomalies, key=lambda x: (SEV_ORDER.get(x["severity"], 9), x["timestamp"])), 1
    ):
        prefix = SEV_PREFIX.get(a["severity"], "[   ]")
        print(f"\n  #{i:02d}  {prefix}  {a['severity']}")
        print(f"        Type        : {a['type']}")
        print(f"        Time        : {a['timestamp'].strftime('%Y-%m-%d  %H:%M:%S')}")
        print(f"        Source IP   : {a['src_ip']}")
        print(f"        IF Score    : {a['if_score']:.4f}  (lower = more anomalous)")
        print(f"        Volume      : {a['n_bytes']/1024:.1f} KB  in {a['n_packets']} packets")
        print(f"        Ports hit   : {int(a['n_dst_ports'])}")
        print(f"        Fail ratio  : {a['failed_ratio']:.1%}")

    print("\n" + "-" * 72)
    counts: dict[str, int] = defaultdict(int)
    for a in anomalies:
        counts[a["type"]] += 1
    known   = sum(c for t, c in counts.items() if t != "Unknown")
    unknown = counts.get("Unknown", 0)
    print(f"  Total: {len(anomalies)} anomaly episodes  "
          f"({known} classified  +  {unknown} unclassified)")
    for t, c in sorted(counts.items()):
        print(f"    * {t:<24} {c}")
    print("=" * 72 + "\n")


# ══════════════════════════════════════════════════════════════════════════════
#  VISUALISATION
# ══════════════════════════════════════════════════════════════════════════════

def plot(
    df: pd.DataFrame,
    features: pd.DataFrame,
    anomalies: list[dict],
    window: str,
    out_path: str,
) -> None:

    fig, axes = plt.subplots(
        4, 1, figsize=(17, 13), sharex=True,
        gridspec_kw={"height_ratios": [2, 1, 1, 1.3]},
    )
    fig.patch.set_facecolor("#F4F6FA")
    date_str = df["timestamp"].dt.date.iloc[0].strftime("%Y-%m-%d")
    fig.suptitle(
        f"Network Anomaly Detection  (Isolation Forest)  —  {date_str}",
        fontsize=14, fontweight="bold", y=0.995,
    )

    ts_idx  = df.set_index("timestamp")
    kb      = ts_idx["bytes"].resample(window).sum() / 1024
    conns   = ts_idx["bytes"].resample(window).count()
    failed  = (ts_idx[ts_idx["status"] == "FAILED"]["status"]
               .resample(window).count())

    # IF score: worst (min) score per window across all source IPs
    if_ts = features.groupby("window")["if_score"].min()

    # Anomaly score boundary = highest score among all anomalous windows
    anomaly_rows = features[features["if_label"] == -1]
    score_boundary = anomaly_rows["if_score"].max() if not anomaly_rows.empty else -0.05

    bg = "#EAEFF7"
    ax1, ax2, ax3, ax4 = axes

    # Panel 1 — traffic volume
    ax1.set_facecolor(bg)
    ax1.fill_between(kb.index, kb.values, alpha=0.35, color="#1565C0")
    ax1.plot(kb.index, kb.values, color="#1565C0", linewidth=1.1)
    ax1.set_ylabel("Traffic  (KB / window)", fontsize=9)
    ax1.set_title("Network Traffic Volume", fontsize=10, loc="left", pad=3)
    ax1.grid(True, alpha=0.25, linestyle="--")

    # Panel 2 — connection count
    ax2.set_facecolor(bg)
    ax2.fill_between(conns.index, conns.values, alpha=0.35, color="#2E7D32")
    ax2.plot(conns.index, conns.values, color="#2E7D32", linewidth=1.1)
    ax2.set_ylabel("Packets / window", fontsize=9)
    ax2.set_title("Packet / Connection Count", fontsize=10, loc="left", pad=3)
    ax2.grid(True, alpha=0.25, linestyle="--")

    # Panel 3 — failed connections
    ax3.set_facecolor(bg)
    ax3.bar(failed.index, failed.values,
            width=pd.Timedelta("4min"), color="#C62828", alpha=0.75)
    ax3.set_ylabel("Failed / window", fontsize=9)
    ax3.set_title("Failed / Rejected Connections", fontsize=10, loc="left", pad=3)
    ax3.grid(True, alpha=0.25, linestyle="--")

    # Panel 4 — Isolation Forest anomaly score
    ax4.set_facecolor(bg)
    ax4.plot(if_ts.index, if_ts.values, color="#37474F", linewidth=1.2, label="IF score (min per window)")
    ax4.fill_between(if_ts.index, if_ts.values, if_ts.min(),
                     alpha=0.18, color="#37474F")
    ax4.axhline(score_boundary, color="#E53935", linestyle=":",
                linewidth=1.4, alpha=0.85, label=f"Decision boundary ({score_boundary:.3f})")
    ax4.set_ylabel("Anomaly Score", fontsize=9)
    ax4.set_title("Isolation Forest Score  (lower = more anomalous)",
                  fontsize=10, loc="left", pad=3)
    ax4.grid(True, alpha=0.25, linestyle="--")
    ax4.legend(fontsize=8, loc="upper right")

    # Overlay anomaly markers on all panels
    legend_handles: dict[str, mpatches.Patch] = {}
    label_y_buckets: dict[str, float] = {}

    for a in anomalies:
        color = ANOMALY_COLORS.get(a["type"], "#757575")
        t     = a["timestamp"]
        t_end = t + pd.Timedelta(window)

        for ax in axes:
            ax.axvspan(t, t_end, alpha=0.11, color=color, zorder=0)
            ax.axvline(t, color=color, linestyle="--", linewidth=1.6, alpha=0.8, zorder=1)

        # Stagger labels vertically to avoid overlap
        ymax   = float(kb.max()) or 1.0
        key    = a["type"]
        frac   = label_y_buckets.get(key, 0.92)
        label_y_buckets[key] = max(frac - 0.14, 0.5)

        short = a["type"].replace(" ", "\n")
        ax1.annotate(
            short,
            xy=(t, ymax * frac),
            fontsize=7, color=color, ha="center", fontweight="bold",
            bbox=dict(boxstyle="round,pad=0.25", fc="white",
                      ec=color, alpha=0.92, linewidth=1),
            zorder=5,
        )

        if key not in legend_handles:
            legend_handles[key] = mpatches.Patch(color=color, label=key)

    # X-axis formatting
    ax4.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))
    ax4.xaxis.set_major_locator(mdates.HourLocator(interval=2))
    plt.setp(ax4.xaxis.get_majorticklabels(), rotation=40, ha="right", fontsize=8)
    ax4.set_xlabel("Time (UTC)", fontsize=9)

    if legend_handles:
        fig.legend(
            handles=list(legend_handles.values()),
            loc="lower center", ncol=min(len(legend_handles), 5),
            bbox_to_anchor=(0.5, 0.002), fontsize=9,
            framealpha=0.92, title="Detected Anomaly Types", title_fontsize=9,
        )

    plt.tight_layout(rect=[0, 0.055, 1, 0.975])
    plt.savefig(out_path, dpi=150, bbox_inches="tight",
                facecolor=fig.get_facecolor())
    print(f"[+] Graph saved -> {out_path}")
    plt.show()


# ══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Isolation Forest network anomaly detector  "
                    "(.pcap/.pcapng  or  .log/.csv)"
    )
    parser.add_argument(
        "file", nargs="?",
        default="sample_logs/network_traffic.log",
        help="Input PCAP or log file",
    )
    parser.add_argument(
        "--contamination", type=float, default=DEFAULT_CONTAMINATION,
        help=f"Expected anomaly fraction  (default: {DEFAULT_CONTAMINATION})",
    )
    parser.add_argument(
        "--window", default=DEFAULT_WINDOW,
        help=f"Time aggregation window  (default: {DEFAULT_WINDOW})",
    )
    parser.add_argument(
        "--out", default="anomaly_report_v2.png",
        help="Output graph filename",
    )
    args = parser.parse_args()

    print("=" * 64)
    print("  NETWORK ANOMALY DETECTION  —  Isolation Forest v2")
    print("=" * 64)
    print(f"  Input         : {args.file}")
    print(f"  Window        : {args.window}")
    print(f"  Contamination : {args.contamination:.0%}")
    print(f"  Trees         : {N_ESTIMATORS}")
    print("=" * 64)

    df = load_file(args.file)
    df.sort_values("timestamp", inplace=True)
    df.reset_index(drop=True, inplace=True)
    print(f"[+] {len(df):,} records  |  "
          f"{df['timestamp'].min().strftime('%Y-%m-%d %H:%M')} "
          f"to {df['timestamp'].max().strftime('%H:%M')}")

    print("[*] Building feature vectors ...")
    features = build_features(df, args.window)
    print(f"    {len(features):,} (window, src_ip) groups  x  {len(FEATURE_COLS)} features")

    print("[*] Running Isolation Forest ...")
    features, scaler, model = run_isolation_forest(features, args.contamination)
    n_flagged = (features["if_label"] == -1).sum()
    print(f"    {n_flagged} anomalous windows flagged out of {len(features)}")

    print("[*] Classifying anomaly types ...")
    anomalies = label_anomalies(features)

    print_report(anomalies)
    plot(df, features, anomalies, args.window, args.out)


if __name__ == "__main__":
    main()
