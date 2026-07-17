"""
Convert benign pcap/pcapng captures into a flow-feature CSV for local-baseline
training (docs/LOCAL_BASELINE_DATASET_PLAN.md, Phase 2).

Critical detail: packets are sliced into fixed time windows (default 30 s)
BEFORE flow grouping, so a training flow means "what a flow looks like within
one sliding-window pass" - exactly how live inference sees traffic in
packet_capture.py. Grouping over a whole capture instead would merge recurring
traffic (e.g. periodic DNS to one resolver) into long fake flows and
reintroduce train/serve skew.

Reuses flow_generator.group_packets_into_flows() and
feature_extractor.extract_flow_features() so the output columns match the
model's FEATURE_NAMES exactly, plus flow identifiers and window metadata.

Streams packets with scapy's PcapReader (rdpcap would load multi-GB captures
into RAM) and appends each window's flows to the output CSV incrementally.

Usage:
    python pcap_to_flows.py --pcap-dir "..\\..\\data\\baseline_train\\wireshark_data" ^
        --window-sec 30 --out "..\\..\\data\\local_baseline\\csv\\benign_flows.csv"
"""
import os
import sys
import glob
import time
import argparse

import pandas as pd

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import flow_generator
import feature_extractor


def restrict_dissection():
    """Stop scapy from dissecting payloads above L4 - big parsing speedup."""
    try:
        from scapy.config import conf
        from scapy.layers.l2 import Ether
        from scapy.layers.inet import IP, TCP, UDP, ICMP
        from scapy.layers.inet6 import IPv6
        conf.layers.filter([Ether, IP, IPv6, TCP, UDP, ICMP])
    except Exception as e:
        print(f"[!] Could not restrict scapy layer dissection ({e}); continuing (slower).")


def flush_window(win_id, packets, window_sec, source, out_path, first_write):
    """Groups one window's packets into flows, extracts features, appends to CSV."""
    flows = flow_generator.group_packets_into_flows(packets)
    if not flows:
        return 0, first_write
    df = feature_extractor.extract_flow_features(flows)
    df["window_start"] = win_id * window_sec
    df["source_pcap"] = source
    df.to_csv(out_path, mode="w" if first_write else "a",
              header=first_write, index=False)
    return len(df), False


def process_pcap(path, window_sec, out_path, first_write):
    """Streams one capture file; returns (n_packets, n_flows, first_write)."""
    from scapy.all import PcapReader

    source = os.path.basename(path)
    print(f"[+] Reading {source} ...")
    t0 = time.time()

    windows = {}          # win_id -> list of packets
    n_pkts = 0
    n_flows = 0
    max_win = None

    reader = PcapReader(path)
    try:
        for pkt in reader:
            n_pkts += 1
            win_id = int(float(pkt.time) // window_sec)
            windows.setdefault(win_id, []).append(pkt)
            if max_win is None or win_id > max_win:
                max_win = win_id
                # Flush windows at least 2 behind the newest (tolerates minor
                # timestamp reordering while keeping memory bounded).
                for wid in [w for w in windows if w < max_win - 1]:
                    added, first_write = flush_window(
                        wid, windows.pop(wid), window_sec, source, out_path, first_write)
                    n_flows += added
            if n_pkts % 100000 == 0:
                rate = n_pkts / (time.time() - t0)
                print(f"    {n_pkts} packets, {n_flows} flows so far ({rate:.0f} pkt/s)")
    except (EOFError, StopIteration):
        pass
    except Exception as e:
        # Truncated captures (killed mid-write) end with a partial record.
        print(f"[!] Stopped reading {source} early after {n_pkts} packets: {e}")
    finally:
        try:
            reader.close()
        except Exception:
            pass

    # Flush remaining windows
    for wid in sorted(windows):
        added, first_write = flush_window(
            wid, windows.pop(wid), window_sec, source, out_path, first_write)
        n_flows += added

    dt = time.time() - t0
    print(f"[+] {source}: {n_pkts} packets -> {n_flows} flows in {dt:.0f}s")
    return n_pkts, n_flows, first_write


def main():
    ap = argparse.ArgumentParser(description="pcap(s) -> windowed flow-feature CSV")
    ap.add_argument("--pcap-dir", required=True, help="Directory containing .pcap/.pcapng files")
    ap.add_argument("--window-sec", type=int, default=30,
                    help="Fixed window length in seconds; must match live context_window (default 30)")
    ap.add_argument("--out", required=True, help="Output CSV path")
    args = ap.parse_args()

    pcaps = sorted(glob.glob(os.path.join(args.pcap_dir, "*.pcap")) +
                   glob.glob(os.path.join(args.pcap_dir, "*.pcapng")))
    if not pcaps:
        print(f"[-] No .pcap/.pcapng files found in {args.pcap_dir}")
        sys.exit(1)

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    restrict_dissection()

    total_pkts = 0
    total_flows = 0
    first_write = True
    for path in pcaps:
        p, f, first_write = process_pcap(path, args.window_sec, args.out, first_write)
        total_pkts += p
        total_flows += f

    print()
    print(f"[+] DONE: {total_pkts} packets -> {total_flows} flows "
          f"({args.window_sec}s windows) from {len(pcaps)} files")
    print(f"[+] Wrote {os.path.abspath(args.out)}")
    if total_flows > 0:
        df = pd.read_csv(args.out)
        print(f"[+] Column check: {list(df.columns)}")
        print(f"[+] Protocol mix: {df['protocol'].value_counts().to_dict()}")


if __name__ == "__main__":
    main()
