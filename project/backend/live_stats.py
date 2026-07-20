"""
Live terminal dashboard for the Aegis-IDS online pipeline.

Polls the running backend's /api/online/status + /api/dashboard endpoints and
renders a compact, self-refreshing stats panel in the console - handy for
watching detection while attacks are generated, without opening the web UI.

ASCII-only output (the Windows cp1252 console chokes on unicode box glyphs).

Usage (backend must be running; auto-detects the port, or pass --port):
    python live_stats.py
    python live_stats.py --port 8002 --interval 2
    python live_stats.py --count 1        # print one snapshot and exit
"""
import os
import sys
import time
import argparse
import json
from urllib.request import urlopen
from urllib.error import URLError


def fetch(url, timeout=5):
    with urlopen(url, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def detect_port(preferred=None):
    ports = ([preferred] if preferred else []) + [8000, 8001, 8002, 8003, 8004, 8005]
    for p in ports:
        if p is None:
            continue
        try:
            m = fetch(f"http://127.0.0.1:{p}/api/metrics", timeout=2)
            if isinstance(m, dict) and "pipeline_type" in m:
                return p
        except (URLError, OSError, ValueError):
            continue
    return None


def bar(pct, width=30):
    filled = int(round((pct / 100.0) * width))
    return "[" + "#" * filled + "-" * (width - filled) + "]"


def clear():
    # ANSI clear + home; works in Windows Terminal / VT-enabled consoles.
    sys.stdout.write("\x1b[2J\x1b[H")


def render(base):
    try:
        status = fetch(f"{base}/api/online/status")
        dash = fetch(f"{base}/api/dashboard")
    except (URLError, OSError, ValueError) as e:
        return f"[!] backend not reachable at {base}: {e}"

    s = dash.get("stats", {}) or {}
    running = dash.get("running", status.get("is_running", False))
    iface = status.get("interface") or status.get("interface_name") or "-"
    win = status.get("sliding_window_sec", "-")
    buffered = status.get("packet_count", 0)

    lines = []
    lines.append("=" * 64)
    lines.append(" AEGIS-IDS  LIVE STATS        " + time.strftime("%Y-%m-%d %H:%M:%S"))
    lines.append("=" * 64)
    state = "RUNNING" if running else "STOPPED"
    lines.append(f" capture: {state:<8} iface={iface:<12} window={win}s  buffered_pkts={buffered}")
    lines.append("-" * 64)

    rate = float(s.get("detection_rate", 0) or 0)
    lines.append(f" packets(window) : {s.get('total_packets', 0)}")
    lines.append(f" flows(window)   : {s.get('total_flows', 0)}"
                 f"   normal={s.get('normal_flows', 0)}  attack={s.get('attack_flows', 0)}")
    lines.append(f" detection rate  : {rate:5.1f}%  {bar(rate)}")
    lines.append(f" avg ensemble    : {s.get('ensemble_score', 0)}   avg IF={s.get('if_score', 0)}")
    lines.append("-" * 64)

    attacks = dash.get("attacks", []) or []
    lines.append(" attack types (window):")
    if attacks:
        for a in sorted(attacks, key=lambda x: -x.get("value", 0))[:8]:
            lines.append(f"   {a.get('name', '?'):<34} {a.get('value', 0):>5}")
    else:
        lines.append("   (none)")
    lines.append("-" * 64)

    camps = dash.get("campaigns", []) or []
    active = [c for c in camps if c.get("distributed") or c.get("num_sources", 0) >= 3
              or c.get("total_pkts", 0) > 1000]
    lines.append(f" campaigns: {len(camps)} total, showing significant:")
    if active:
        for c in active[:6]:
            lines.append(f"   [{c.get('severity', '?'):<8}] {str(c.get('label', ''))[:48]}")
            lines.append(f"       target={c.get('target', '?')}  srcs={c.get('num_sources', 0)}"
                         f"  flows={c.get('num_flows', 0)}  pkts={c.get('total_pkts', 0)}")
    else:
        lines.append("   (no significant campaigns)")
    lines.append("-" * 64)

    top_src = dash.get("top_src_ips", []) or []
    top_dst = dash.get("top_dst_ips", []) or []
    lines.append(" top sources:      " +
                 ", ".join(f"{t.get('ip')}({t.get('count')})" for t in top_src[:4]))
    lines.append(" top destinations: " +
                 ", ".join(f"{t.get('ip')}({t.get('count')})" for t in top_dst[:4]))
    lines.append("=" * 64)
    lines.append(" Ctrl+C to exit")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description="Live terminal stats for the Aegis-IDS pipeline")
    ap.add_argument("--port", type=int, default=None, help="backend port (auto-detect if omitted)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--interval", type=float, default=3.0, help="refresh seconds (default 3)")
    ap.add_argument("--count", type=int, default=0, help="number of refreshes then exit (0 = forever)")
    args = ap.parse_args()

    port = args.port or detect_port(args.port)
    if port is None:
        print("[!] Could not find a running backend on 8000-8005. Is it up? Pass --port.")
        sys.exit(1)
    base = f"http://{args.host}:{port}"
    print(f"[*] Polling {base} every {args.interval}s ...")
    time.sleep(0.5)

    n = 0
    try:
        while True:
            frame = render(base)
            if args.count != 1:
                clear()
            print(frame, flush=True)
            n += 1
            if args.count and n >= args.count:
                break
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\n[*] stopped.")


if __name__ == "__main__":
    main()
