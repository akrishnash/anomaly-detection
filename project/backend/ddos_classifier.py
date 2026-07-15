"""
Stage 2: DDoS / attack subtype classification for flows flagged anomalous by
the unsupervised Stage 1 detector (anomaly_detector.py).

Works on unlabeled data: classification is a transparent rule engine over flow
characteristics (protocol, TCP flag mix, rates, packet sizes, directionality)
plus per-target aggregation across flows. DDoS is a many-flows phenomenon, so
per-flow verdicts are refined by campaign aggregation (many sources hitting one
target escalate to a "distributed" verdict).

Usable three ways:
  - Library:   classify_flow(flow_dict), aggregate_campaigns(anomalous_flows)
  - Pipeline:  called by api.py (offline) and packet_capture.py (online)
  - CLI:       python ddos_classifier.py --input capture.pcap|flows.csv [--output report.json]
"""
import math
from collections import Counter

# UDP services commonly abused for reflection/amplification attacks
AMPLIFICATION_PORTS = {
    53: "DNS", 123: "NTP", 161: "SNMP", 389: "LDAP",
    1900: "SSDP", 11211: "Memcached", 19: "CharGen", 111: "Portmap"
}

WEB_PORTS = {80, 443, 8080, 8443}
BRUTE_FORCE_PORTS = {21: "FTP", 22: "SSH", 23: "Telnet", 445: "SMB", 3389: "RDP", 5900: "VNC"}

# Aggregation thresholds for escalating per-flow verdicts to a distributed campaign
DISTRIBUTED_MIN_SOURCES = 10
PORT_SCAN_MIN_PORTS = 15


def _normalize_protocol(proto) -> str:
    p = str(proto).strip().upper()
    if p in ("6", "6.0", "TCP"):
        return "TCP"
    if p in ("17", "17.0", "UDP"):
        return "UDP"
    if p in ("1", "1.0", "ICMP"):
        return "ICMP"
    return p if p else "OTHER"


def _get(flow: dict, keys, default=0.0):
    """Reads the first present, non-null key from a flow dict."""
    for k in keys:
        if k in flow and flow[k] is not None:
            try:
                v = float(flow[k])
                if not (math.isnan(v) or math.isinf(v)):
                    return v
            except (TypeError, ValueError):
                continue
    return default


def classify_flow(flow: dict) -> dict:
    """
    Classifies a single anomalous flow into an attack subtype.

    Accepts a dict with canonical or feature-extractor keys (both spellings are
    handled): protocol, src_port, dst_port, total_pkts, flow_pkts_s, flow_byts_s,
    pkt_len_mean, flow_duration_s, fwd_bytes, bwd_bytes, syn/rst/fin/ack counts.

    Returns {attack_type, severity, confidence, evidence: [str, ...]}.
    Falls back to "Unknown Anomaly" rather than forcing a DDoS label.
    """
    proto = _normalize_protocol(flow.get("protocol", "TCP"))
    src_port = int(_get(flow, ["src_port"], 0))
    dst_port = int(_get(flow, ["dst_port"], 0))
    pkts = _get(flow, ["total_pkts", "packets"], 0)
    pps = _get(flow, ["flow_pkts_s", "packet_rate"], 0.0)
    bps = _get(flow, ["flow_byts_s", "byte_rate"], 0.0)
    duration = _get(flow, ["flow_duration_s", "duration"], 0.0)
    mean_len = _get(flow, ["pkt_len_mean", "avg_packet_size"], 0.0)
    fwd_bytes = _get(flow, ["fwd_bytes"], 0.0)
    bwd_bytes = _get(flow, ["bwd_bytes"], 0.0)
    syn = _get(flow, ["syn_flag", "syn_count"], 0)
    rst = _get(flow, ["rst_flag", "rst_count"], 0)
    fin = _get(flow, ["fin_flag", "fin_count"], 0)
    ack = _get(flow, ["ack_flag", "ack_count"], 0)

    total_bytes = fwd_bytes + bwd_bytes
    syn_ratio = syn / pkts if pkts > 0 else 0.0
    bwd_ratio = bwd_bytes / total_bytes if total_bytes > 0 else 0.0
    # Direction-agnostic asymmetry: 1.0 = fully one-directional, 0.5 = balanced.
    # flow_generator assigns fwd/bwd by sorted IP order, not true client->server,
    # so flood "one-way" tests must not assume traffic lands in the bwd bucket.
    oneway = max(fwd_bytes, bwd_bytes) / total_bytes if total_bytes > 0 else 1.0

    def verdict(attack_type, severity, confidence, evidence):
        return {
            "attack_type": attack_type,
            "severity": severity,
            "confidence": round(min(confidence, 0.99), 2),
            "evidence": evidence
        }

    # ── SYN Flood (half-open TCP: SYN-dominant, no completed handshakes) ──
    if proto == "TCP" and syn >= 1 and syn_ratio >= 0.5 and ack <= syn * 0.5:
        evidence = [f"SYN-dominant flow ({int(syn)} SYN / {int(pkts)} pkts)"]
        conf = 0.6
        if oneway > 0.9:
            evidence.append("near-zero response traffic (half-open)")
            conf += 0.15
        if rst > 0:
            evidence.append(f"{int(rst)} RST replies (rejected connections)")
            conf += 0.05
        if pps > 50:
            evidence.append(f"high packet rate ({pps:.0f} pkts/s)")
            conf += 0.15
        severity = "Critical" if (pps > 100 or syn > 100) else "High"
        return verdict("SYN Flood", severity, conf, evidence)

    # ── Amplification / Reflection (abused UDP service + oversized replies) ──
    amp_service = AMPLIFICATION_PORTS.get(src_port) or AMPLIFICATION_PORTS.get(dst_port)
    if proto == "UDP" and amp_service and mean_len > 400 and (pps > 10 or bps > 100000):
        evidence = [
            f"{amp_service} service port with oversized packets (mean {mean_len:.0f} B)",
            f"traffic rate {bps:.0f} B/s"
        ]
        if oneway > 0.8:
            evidence.append("one-way reflected traffic toward victim")
        severity = "Critical" if bps > 1000000 else "High"
        return verdict(f"Amplification Attack ({amp_service})", severity, 0.85, evidence)

    # ── UDP Flood (high-rate, one-directional UDP) ──
    if proto == "UDP" and (pps > 50 or pkts > 100) and oneway > 0.8:
        evidence = [
            f"high-rate UDP ({pps:.0f} pkts/s, {int(pkts)} pkts)",
            "little to no return traffic"
        ]
        severity = "Critical" if (pps > 500 or bps > 5000000) else "High"
        return verdict("UDP Flood", severity, 0.8 if pps > 200 else 0.7, evidence)

    # ── ICMP Flood ──
    if proto == "ICMP" and (pps > 20 or pkts > 50):
        evidence = [f"high-rate ICMP ({pps:.0f} pkts/s, {int(pkts)} pkts)"]
        severity = "Critical" if pps > 200 else "High"
        return verdict("ICMP Flood", severity, 0.8, evidence)

    # ── Slowloris (long-lived, trickling connections to a web port) ──
    if proto == "TCP" and dst_port in WEB_PORTS and duration > 30 and pps < 2 and mean_len < 120 and pkts >= 5:
        evidence = [
            f"long-lived web connection ({duration:.0f} s) at trickle rate ({pps:.2f} pkts/s)",
            f"tiny packets (mean {mean_len:.0f} B)"
        ]
        return verdict("Slowloris (Slow HTTP)", "High", 0.75, evidence)

    # ── HTTP Flood (established web connections at abnormal request rates) ──
    if proto == "TCP" and dst_port in WEB_PORTS and ack > 0 and (pps > 20 or pkts > 200) and mean_len < 400:
        evidence = [
            f"established web traffic at {pps:.0f} pkts/s ({int(pkts)} pkts)",
            f"small request-sized packets (mean {mean_len:.0f} B)"
        ]
        severity = "Critical" if pps > 200 else "High"
        return verdict("HTTP Flood", severity, 0.7, evidence)

    # ── Brute Force (repeated small exchanges against an auth service) ──
    if proto == "TCP" and dst_port in BRUTE_FORCE_PORTS and pkts > 10 and mean_len < 200:
        service = BRUTE_FORCE_PORTS[dst_port]
        evidence = [f"repeated small exchanges to {service} port {dst_port} ({int(pkts)} pkts, mean {mean_len:.0f} B)"]
        return verdict(f"Brute Force ({service})", "Medium", 0.65, evidence)

    # ── Data Exfiltration (large one-way transfer) ──
    if max(fwd_bytes, bwd_bytes) > 1000000 and oneway > 0.8 and syn < 2:
        evidence = [f"large one-way transfer ({fwd_bytes / 1e6:.1f} MB outbound)"]
        return verdict("Data Exfiltration", "High", 0.6, evidence)

    # ── Generic volumetric flood (protocol-agnostic rate anomaly) ──
    if pps > 1000 or bps > 5000000:
        evidence = [f"volumetric traffic ({pps:.0f} pkts/s, {bps / 1e6:.1f} MB/s)"]
        return verdict("Volumetric Flood", "Critical", 0.7, evidence)

    # ── Fallback: anomalous, but no attack signature matched ──
    return verdict("Unknown Anomaly", "Medium", 0.4,
                   ["flow deviates from baseline but matches no known attack signature"])


def _entropy(counter: Counter) -> float:
    """Normalized Shannon entropy of a distribution, in [0, 1]."""
    total = sum(counter.values())
    n = len(counter)
    if total == 0 or n <= 1:
        return 0.0
    h = -sum((c / total) * math.log(c / total) for c in counter.values())
    return h / math.log(n)


def aggregate_campaigns(anomalous_flows: list) -> tuple[list, dict]:
    """
    Aggregates per-flow verdicts into attack campaigns and refines labels using
    cross-flow structure (per-flow rules cannot distinguish e.g. one SYN probe
    of a port scan from one spoofed source of a distributed SYN flood).

    Args:
        anomalous_flows: list of dicts, each with at least
            {id, src_ip, dst_ip, dst_port, attack_type, severity, total_pkts}
    Returns:
        campaigns: list of campaign summaries (one per attacked target).
        refinements: {flow_id: (attack_type, severity)} label upgrades to apply.
    """
    campaigns = []
    refinements = {}

    if not anomalous_flows:
        return campaigns, refinements

    # ── Port scan detection: one source probing many ports/hosts ──
    by_src = {}
    for f in anomalous_flows:
        by_src.setdefault(f["src_ip"], []).append(f)
    scan_srcs = set()
    for src, flows in by_src.items():
        ports = {(f["dst_ip"], int(f.get("dst_port", 0))) for f in flows}
        if len(ports) >= PORT_SCAN_MIN_PORTS and all(
            f.get("attack_type") in ("SYN Flood", "Unknown Anomaly", "Port Scan / Recon")
            for f in flows
        ):
            scan_srcs.add(src)
            for f in flows:
                refinements[f["id"]] = ("Port Scan / Recon", "High")

    # ── Campaign aggregation: many flows converging on one target ──
    by_dst = {}
    for f in anomalous_flows:
        if f["src_ip"] in scan_srcs:
            continue
        by_dst.setdefault(f["dst_ip"], []).append(f)

    for dst_ip, flows in by_dst.items():
        srcs = Counter(f["src_ip"] for f in flows)
        types = Counter(f.get("attack_type", "Unknown Anomaly") for f in flows)
        dominant_type = types.most_common(1)[0][0]
        n_sources = len(srcs)
        src_entropy = _entropy(srcs)
        total_pkts = int(sum(f.get("total_pkts", 0) for f in flows))
        dst_ports = sorted({int(f.get("dst_port", 0)) for f in flows})

        distributed = n_sources >= DISTRIBUTED_MIN_SOURCES or (n_sources >= 5 and src_entropy > 0.8)

        if distributed and dominant_type != "Unknown Anomaly":
            label = f"DDoS: {dominant_type} (distributed: {n_sources} sources)"
            severity = "Critical"
            for f in flows:
                if f.get("attack_type") == dominant_type:
                    refinements[f["id"]] = (f"DDoS: {dominant_type}", "Critical")
        elif distributed:
            label = f"DDoS: Unclassified Flood (distributed: {n_sources} sources)"
            severity = "Critical"
        else:
            label = dominant_type
            severity = max((f.get("severity", "Medium") for f in flows),
                           key=lambda s: ["Low", "Medium", "High", "Critical"].index(s)
                           if s in ["Low", "Medium", "High", "Critical"] else 1)

        campaigns.append({
            "target": dst_ip,
            "label": label,
            "attack_type": dominant_type,
            "distributed": bool(distributed),
            "severity": severity,
            "num_flows": len(flows),
            "num_sources": n_sources,
            "source_entropy": round(src_entropy, 3),
            "total_pkts": total_pkts,
            "dst_ports": dst_ports[:20],
            "attack_type_breakdown": dict(types)
        })

    # Port-scan campaigns (grouped by scanning source rather than target)
    for src in scan_srcs:
        flows = by_src[src]
        targets = sorted({f["dst_ip"] for f in flows})
        campaigns.append({
            "target": ", ".join(targets[:5]) + ("..." if len(targets) > 5 else ""),
            "label": f"Port Scan / Recon (from {src})",
            "attack_type": "Port Scan / Recon",
            "distributed": False,
            "severity": "High",
            "num_flows": len(flows),
            "num_sources": 1,
            "source_entropy": 0.0,
            "total_pkts": int(sum(f.get("total_pkts", 0) for f in flows)),
            "dst_ports": sorted({int(f.get("dst_port", 0)) for f in flows})[:20],
            "attack_type_breakdown": {"Port Scan / Recon": len(flows)}
        })

    campaigns.sort(key=lambda c: (c["distributed"], c["num_flows"]), reverse=True)
    return campaigns, refinements


# ── Standalone CLI ────────────────────────────────────────────────────────────

def analyze_file(input_path: str, threshold: float = 0.5) -> dict:
    """
    Full pipeline for a PCAP or flow CSV/Excel file:
    load -> flows -> features -> Stage 1 anomaly scores -> Stage 2 subtypes -> campaigns.
    Returns a JSON-serializable report dict.
    """
    import os
    import pandas as pd
    import preprocessing
    import anomaly_detector

    ext = os.path.splitext(input_path)[1].lower()
    if ext in (".pcap", ".pcapng"):
        from scapy.all import rdpcap
        import flow_generator
        import feature_extractor
        pkts = rdpcap(input_path)
        grouped = flow_generator.group_packets_into_flows(pkts)
        df_raw = feature_extractor.extract_flow_features(grouped)
        num_packets = len(pkts)
    elif ext == ".csv":
        df_raw = pd.read_csv(input_path)
        num_packets = None
    elif ext in (".xlsx", ".xls"):
        df_raw = pd.read_excel(input_path)
        num_packets = None
    else:
        raise ValueError(f"Unsupported input format '{ext}'. Use .pcap, .pcapng, .csv, .xlsx or .xls.")

    if len(df_raw) == 0:
        raise ValueError("Input contains no flows/packets.")

    X_scaled, _, df_canonical = preprocessing.preprocess_dataset(df_raw)
    df_feats = preprocessing.extract_features(df_canonical)

    probs, if_scores, ae_scores = anomaly_detector.score_flows(X_scaled)

    flows_out = []
    anomalous = []
    for i in range(len(df_feats)):
        prob = float(probs[i])
        is_anomaly = prob >= threshold
        flow_info = df_feats.iloc[i].to_dict()
        flow_info["protocol"] = df_canonical.iloc[i].get("protocol", "TCP")
        flow_info["src_port"] = df_canonical.iloc[i].get("src_port", 0)
        flow_info["dst_port"] = df_canonical.iloc[i].get("dst_port", 0)

        if is_anomaly:
            v = classify_flow(flow_info)
        else:
            v = {"attack_type": "Normal", "severity": "Low", "confidence": 1.0 - prob, "evidence": []}

        rec = {
            "id": i,
            "src_ip": str(df_canonical.iloc[i].get("src_ip", "")),
            "dst_ip": str(df_canonical.iloc[i].get("dst_ip", "")),
            "dst_port": int(_get(flow_info, ["dst_port"], 0)),
            "protocol": _normalize_protocol(flow_info["protocol"]),
            "anomaly_score": round(prob, 4),
            "if_score": round(float(if_scores[i]), 4),
            "ae_score": round(float(ae_scores[i]), 4),
            "is_anomaly": bool(is_anomaly),
            "total_pkts": int(_get(flow_info, ["total_pkts"], 0)),
            **v
        }
        flows_out.append(rec)
        if is_anomaly:
            anomalous.append(rec)

    campaigns, refinements = aggregate_campaigns(anomalous)
    for rec in flows_out:
        if rec["id"] in refinements:
            rec["attack_type"], rec["severity"] = refinements[rec["id"]]

    subtype_counts = Counter(r["attack_type"] for r in flows_out if r["is_anomaly"])

    return {
        "input": os.path.basename(input_path),
        "num_packets": num_packets,
        "total_flows": len(flows_out),
        "anomalous_flows": len(anomalous),
        "threshold": threshold,
        "attack_subtypes": dict(subtype_counts),
        "campaigns": campaigns,
        "flows": flows_out
    }


def _print_report(report: dict):
    print("=" * 64)
    print("DDoS CLASSIFICATION REPORT: " + report["input"])
    print("=" * 64)
    if report["num_packets"] is not None:
        print(f"Packets analyzed   : {report['num_packets']}")
    print(f"Total flows        : {report['total_flows']}")
    print(f"Anomalous flows    : {report['anomalous_flows']} (threshold={report['threshold']})")
    print()
    if report["attack_subtypes"]:
        print("Attack subtype breakdown:")
        for name, count in sorted(report["attack_subtypes"].items(), key=lambda x: -x[1]):
            print(f"  {name:<40} {count:>6} flows")
    else:
        print("No anomalous flows detected.")
    if report["campaigns"]:
        print()
        print("Detected campaigns (per-target aggregation):")
        for c in report["campaigns"]:
            print(f"  [{c['severity']:<8}] {c['label']}")
            print(f"             target={c['target']} flows={c['num_flows']} "
                  f"sources={c['num_sources']} pkts={c['total_pkts']} "
                  f"src_entropy={c['source_entropy']}")
    print("=" * 64)


if __name__ == "__main__":
    import argparse
    import json
    import sys

    parser = argparse.ArgumentParser(
        description="Classify DDoS attack subtypes in a PCAP or flow CSV using the "
                    "unsupervised anomaly detector (Stage 1) + rule engine (Stage 2)."
    )
    parser.add_argument("--input", "-i", required=True, help="Path to .pcap/.pcapng/.csv/.xlsx input")
    parser.add_argument("--threshold", "-t", type=float, default=0.5,
                        help="Anomaly score threshold in [0,1] (default 0.5)")
    parser.add_argument("--output", "-o", default=None, help="Optional path to write full JSON report")
    args = parser.parse_args()

    try:
        result = analyze_file(args.input, threshold=args.threshold)
    except Exception as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        sys.exit(1)

    _print_report(result)

    if args.output:
        with open(args.output, "w") as fh:
            json.dump(result, fh, indent=2, default=str)
        print(f"Full JSON report written to {args.output}")
