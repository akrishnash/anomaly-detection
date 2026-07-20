"""
Flooding / DDoS traffic SIMULATOR for exercising the Aegis-IDS live UI.

Emits attack traffic as L2 frames on the capture NIC (Ethernet 5) so the live
sniffer picks it up. Every mode is crafted to AGGREGATE the way the pipeline
expects, so Stage 1 (IF+AE) flags it and Stage 2 (ddos_classifier) labels it:

  syn    Single-source TCP SYN flood  -> "SYN Flood" (Critical)
  udp    Single-source UDP flood      -> "UDP Flood"
  icmp   ICMP echo flood              -> "ICMP Flood"
  ampl   DNS reflection/amplification -> "Amplification Attack (DNS)"
  ddos   Distributed SYN flood        -> "DDoS: SYN Flood (distributed: N sources)"
  scan   Port scan (many dst ports)   -> "Port Scan / Recon"
  all    Runs syn, udp, ampl, ddos, scan back to back

Frames carry a bogus locally-administered destination MAC, so they hit the wire
and our own sniffer but no real host on the LAN processes them.

IMPORTANT: live capture must be running on Ethernet 5 first. This is a lab tool
for validating your own IDS on your own machine.

Examples (run in a second terminal while capture is live):
    python flood_sim.py syn
    python flood_sim.py ddos --sources 15 --duration 35
    python flood_sim.py all
"""
import sys
import time
import argparse

IFACE = "Ethernet 5"
VICTIM = "192.168.1.123"          # this host - "we are the target"
FAKE_DST_MAC = "02:00:00:00:00:99"  # locally-administered, unused -> inert


def resolve_iface(name):
    from scapy.all import IFACES
    if name in IFACES:
        return name
    clean = name.lower().replace(" ", "").replace("-", "").replace("_", "")
    for key, iface in IFACES.items():
        for cand in (iface.name, iface.description or ""):
            if clean == cand.lower().replace(" ", "").replace("-", "").replace("_", ""):
                return key
    for key, iface in IFACES.items():
        for cand in (iface.name, iface.description or ""):
            if clean in cand.lower().replace(" ", "").replace("-", "").replace("_", ""):
                return key
    return name


def send_stream(packets, iface, pps, duration, label):
    """Sends `packets` (a list, cycled) at ~pps for `duration` seconds."""
    from scapy.all import sendp
    total = int(pps * duration)
    inter = 1.0 / pps if pps > 0 else 0
    print(f"[*] {label}: ~{pps} pkt/s for ~{duration}s ({total} frames)")
    t0 = time.time()
    n = len(packets)
    sent = 0
    try:
        # sendp a repeated pattern; for a single-packet list this is a fast flood,
        # for multi-source lists it round-robins across sources.
        reps = (total // n) + 1
        sendp(packets * reps, iface=iface, count=None, inter=inter, verbose=False)
        sent = n * reps
    except KeyboardInterrupt:
        print("\n[*] interrupted")
    dt = time.time() - t0
    print(f"[+] {label}: sent ~{sent} frames in {dt:.1f}s (~{sent/max(dt,0.1):.0f} pkt/s)")


def build_syn(src, dst, sport, dport):
    from scapy.all import Ether, IP, TCP
    return Ether(dst=FAKE_DST_MAC) / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="S")


def build_udp(src, dst, sport, dport, payload_len):
    from scapy.all import Ether, IP, UDP, Raw
    return (Ether(dst=FAKE_DST_MAC) / IP(src=src, dst=dst) /
            UDP(sport=sport, dport=dport) / Raw(load=b"A" * payload_len))


def build_icmp(src, dst, payload_len):
    from scapy.all import Ether, IP, ICMP, Raw
    return Ether(dst=FAKE_DST_MAC) / IP(src=src, dst=dst) / ICMP() / Raw(load=b"A" * payload_len)


def mode_syn(iface, args):
    pkt = build_syn("185.220.101.50", args.target, 44444, 80)
    send_stream([pkt], iface, args.pps, args.duration, "SYN flood 185.220.101.50 -> %s:80" % args.target)


def mode_udp(iface, args):
    # small-payload high-rate UDP flood to a random victim port
    pkt = build_udp("91.240.118.172", args.target, 40000, 19000, 200)
    send_stream([pkt], iface, args.pps, args.duration, "UDP flood 91.240.118.172 -> %s:19000" % args.target)


def mode_icmp(iface, args):
    pkt = build_icmp("103.85.24.6", args.target, 1000)
    send_stream([pkt], iface, args.pps, args.duration, "ICMP flood 103.85.24.6 -> %s" % args.target)


def mode_ampl(iface, args):
    # DNS reflection: source port 53, oversized replies toward victim (mean_len>400)
    pkt = build_udp("8.8.8.8", args.target, 53, 55555, 1200)
    send_stream([pkt], iface, args.pps, args.duration,
                "DNS amplification 8.8.8.8:53 -> %s (1200B replies)" % args.target)


def _sources_below(victim, n):
    """
    Pick n spoofed source IPs that sort LEXICOGRAPHICALLY BELOW the victim IP.
    flow_generator keys a flow by the smaller IP string and calls it the
    "source"; campaign aggregation then groups by the larger IP ("dst"). For a
    distributed campaign to converge on the victim, every attacker IP must sort
    below it - otherwise the victim becomes the "source" side and each attacker
    shows up as its own separate target (which is what happens with 45.x.x.x).
    """
    # 185.x sorts below 192.168.x; if the victim is even lower, fall back to 10.x.
    for prefix in ("185.220.101.", "10.13.37.", "1.1.1."):
        cand = [f"{prefix}{i+1}" for i in range(n)]
        if all(c < victim for c in cand):
            return cand
    return [f"10.0.{i}.{i+1}" for i in range(n)]  # last-resort, all < most IPs


def mode_ddos(iface, args):
    # Distributed SYN flood: N spoofed sources, each a fixed 5-tuple so it forms
    # its own high-packet flow -> Stage 1 flags each -> campaign sees N sources.
    n = max(args.sources, 10)
    srcs = _sources_below(args.target, n)
    pkts = [build_syn(srcs[i], args.target, 30000 + i, 80) for i in range(n)]
    send_stream(pkts, iface, args.pps, args.duration,
                "Distributed SYN flood: %d sources -> %s:80" % (n, args.target))


def mode_scan(iface, args):
    # Port scan: one source, many destination ports (>=15) -> Port Scan / Recon.
    from scapy.all import sendp
    ports = list(range(20, 20 + max(args.ports, 30)))
    pkts = [build_syn("77.83.36.5", args.target, 55000, p) for p in ports]
    print(f"[*] Port scan 77.83.36.5 -> {args.target} across {len(ports)} ports")
    t0 = time.time()
    # a few passes so each 1-packet flow persists in the window
    sendp(pkts * 3, iface=iface, inter=1.0 / 200, verbose=False)
    print(f"[+] Port scan sent {len(pkts)*3} frames in {time.time()-t0:.1f}s")


MODES = {
    "syn": mode_syn, "udp": mode_udp, "icmp": mode_icmp,
    "ampl": mode_ampl, "ddos": mode_ddos, "scan": mode_scan,
}


def main():
    ap = argparse.ArgumentParser(description="Flooding/DDoS simulator for the Aegis-IDS live UI")
    ap.add_argument("mode", choices=list(MODES.keys()) + ["all"])
    ap.add_argument("--target", default=VICTIM)
    ap.add_argument("--pps", type=int, default=600, help="packets/sec (default 600)")
    ap.add_argument("--duration", type=int, default=35, help="seconds per attack (default 35, > one 30s window)")
    ap.add_argument("--sources", type=int, default=12, help="ddos: number of spoofed sources")
    ap.add_argument("--ports", type=int, default=30, help="scan: number of ports")
    args = ap.parse_args()

    iface = resolve_iface(IFACE)
    print(f"[*] Iface resolved to: {iface}")
    print(f"[*] Target: {args.target}   (frames are inert: fake dst MAC {FAKE_DST_MAC})")

    if args.mode == "all":
        for m in ["syn", "udp", "ampl", "ddos", "scan"]:
            MODES[m](iface, args)
            time.sleep(1)
    else:
        MODES[args.mode](iface, args)

    print("[+] Done. Watch the live UI: flows should appear flagged within one 30s window.")


if __name__ == "__main__":
    main()
