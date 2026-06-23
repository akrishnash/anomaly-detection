#!/usr/bin/env python3
"""
SecureAI Agent — Cybersecurity Triage with OpenAI Tool Calling
==============================================================
Wraps the Isolation Forest anomaly detector as an OpenAI tool-calling agent.

The agent accepts a natural-language query (e.g. "analyse capture.pcap for threats")
and autonomously:
  1. Calls analyze_traffic → runs Isolation Forest on the file
  2. Calls lookup_cve      → fetches CVE context for each detected attack type
  3. Returns a structured threat report with findings, ATT&CK mappings, and mitigations

Usage:
  export OPENAI_API_KEY=sk-...
  python agent.py sample_logs/network_traffic.log
  python agent.py capture.pcap --contamination 0.03
  python agent.py --interactive          # chat mode
"""

import argparse
import json
import os
import sys
from datetime import datetime

from openai import OpenAI

from anomaly_detector_v2 import (
    build_features,
    label_anomalies,
    load_file,
    run_isolation_forest,
)
from cve_db import lookup_cve as _lookup_cve

# ── OpenAI client ─────────────────────────────────────────────────────────────

client = OpenAI()  # reads OPENAI_API_KEY from env
MODEL  = "gpt-4o"

# ── Tool implementations ───────────────────────────────────────────────────────

def analyze_traffic(
    file_path: str,
    contamination: float = 0.02,
    window: str = "5min",
) -> dict:
    """
    Run the Isolation Forest detector on a PCAP or CSV log.
    Returns JSON-serialisable anomaly list + summary statistics.
    """
    if not os.path.exists(file_path):
        return {"error": f"File not found: {file_path}"}

    try:
        df       = load_file(file_path)
        features = build_features(df, window)
        features, _, _ = run_isolation_forest(features, contamination)
        anomalies = label_anomalies(features)
    except Exception as exc:
        return {"error": str(exc)}

    serialisable = [
        {
            "timestamp":    a["timestamp"].strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip":       a["src_ip"],
            "type":         a["type"],
            "severity":     a["severity"],
            "if_score":     round(float(a["if_score"]), 4),
            "n_bytes":      int(a["n_bytes"]),
            "n_packets":    int(a["n_packets"]),
            "n_dst_ports":  int(a["n_dst_ports"]),
            "failed_ratio": round(float(a["failed_ratio"]), 4),
        }
        for a in anomalies
    ]

    return {
        "file":         file_path,
        "records":      len(df),
        "time_range":   (
            f"{df['timestamp'].min().strftime('%Y-%m-%d %H:%M')} – "
            f"{df['timestamp'].max().strftime('%H:%M')}"
        ),
        "total_anomalies": len(serialisable),
        "anomalies":    serialisable,
    }


def lookup_cve(attack_type: str) -> dict:
    """Fetch CVE context, MITRE ATT&CK mapping, and mitigations for an attack type."""
    return _lookup_cve(attack_type)


# ── OpenAI tool schemas ────────────────────────────────────────────────────────

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "analyze_traffic",
            "description": (
                "Analyse a network traffic file (PCAP or CSV log) for anomalies using "
                "an Isolation Forest model. Returns detected anomaly episodes with type, "
                "severity, source IP, timing, and traffic statistics. "
                "Supports: .pcap, .pcapng, .cap, .csv, .log"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Path to the PCAP or CSV log file to analyse.",
                    },
                    "contamination": {
                        "type": "number",
                        "description": (
                            "Expected fraction of anomalous windows (0.01–0.10). "
                            "Lower = stricter. Default 0.02 (2%)."
                        ),
                    },
                    "window": {
                        "type": "string",
                        "description": (
                            "Time aggregation window for feature engineering. "
                            "e.g. '5min', '10min', '1h'. Default '5min'."
                        ),
                    },
                },
                "required": ["file_path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "lookup_cve",
            "description": (
                "Look up CVEs, MITRE ATT&CK technique, and recommended mitigations "
                "for a given network attack type detected in traffic analysis."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "attack_type": {
                        "type": "string",
                        "enum": [
                            "Port Scan",
                            "Brute Force",
                            "Traffic Spike",
                            "Data Exfiltration",
                            "Night Activity",
                            "Botnet C&C",
                            "Unknown",
                        ],
                        "description": "The attack type as returned by analyze_traffic.",
                    },
                },
                "required": ["attack_type"],
            },
        },
    },
]

SYSTEM_PROMPT = """You are a cybersecurity triage agent with access to two tools:

1. analyze_traffic — runs Isolation Forest on a PCAP or network log to detect anomalies
2. lookup_cve      — fetches CVE context and MITRE ATT&CK mappings for each attack type

When the user provides a file to analyse:
- Always call analyze_traffic first.
- For each unique attack type found, call lookup_cve to enrich the findings.
- Then produce a structured threat report covering:
  • Executive summary (2–3 sentences)
  • Threat findings table (timestamp, source IP, type, severity)
  • CVE context and ATT&CK techniques per attack type
  • Prioritised mitigation recommendations
  • Confidence and caveats (unsupervised model — no ground-truth labels)

Be precise and concise. Flag high/critical findings first.
Never take action beyond analysis — you are an advisory agent."""


# ── Agentic loop ──────────────────────────────────────────────────────────────

TOOL_FN_MAP = {
    "analyze_traffic": analyze_traffic,
    "lookup_cve":      lookup_cve,
}


def run_agent(user_query: str, verbose: bool = False) -> str:
    """
    Run the tool-calling agent loop until the model produces a final response.
    Returns the final text output.
    """
    messages = [
        {"role": "system",  "content": SYSTEM_PROMPT},
        {"role": "user",    "content": user_query},
    ]

    step = 0
    while True:
        step += 1
        if verbose:
            print(f"\n[agent] step {step} — calling {MODEL} ...", file=sys.stderr)

        response = client.chat.completions.create(
            model=MODEL,
            messages=messages,
            tools=TOOLS,
            tool_choice="auto",
        )

        choice = response.choices[0]
        msg    = choice.message
        messages.append(msg)

        if not msg.tool_calls:
            # No more tool calls — final answer
            return msg.content or ""

        # Execute each requested tool
        for tc in msg.tool_calls:
            fn_name = tc.function.name
            fn_args = json.loads(tc.function.arguments)

            if verbose:
                print(f"[tool]  {fn_name}({fn_args})", file=sys.stderr)

            if fn_name not in TOOL_FN_MAP:
                result = {"error": f"Unknown tool: {fn_name}"}
            else:
                result = TOOL_FN_MAP[fn_name](**fn_args)

            messages.append({
                "role":         "tool",
                "tool_call_id": tc.id,
                "content":      json.dumps(result, default=str),
            })


# ── CLI ───────────────────────────────────────────────────────────────────────

def _banner() -> None:
    print("=" * 64)
    print("  SecureAI Agent  —  Cybersecurity Triage")
    print("  Isolation Forest + GPT-4o Tool Calling")
    print("=" * 64)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SecureAI Agent: AI-powered network threat triage"
    )
    parser.add_argument(
        "file", nargs="?",
        help="PCAP or log file to analyse",
    )
    parser.add_argument(
        "--contamination", type=float, default=0.02,
        help="Anomaly fraction for Isolation Forest (default: 0.02)",
    )
    parser.add_argument(
        "--window", default="5min",
        help="Time window for feature engineering (default: 5min)",
    )
    parser.add_argument(
        "--interactive", "-i", action="store_true",
        help="Start interactive chat mode",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Show agent reasoning steps",
    )
    args = parser.parse_args()

    if not os.environ.get("OPENAI_API_KEY"):
        sys.exit("[-] OPENAI_API_KEY not set. Export it and re-run.")

    _banner()

    if args.interactive:
        print("  Interactive mode — type 'quit' to exit\n")
        while True:
            try:
                query = input("You: ").strip()
            except (EOFError, KeyboardInterrupt):
                break
            if query.lower() in {"quit", "exit", "q"}:
                break
            if not query:
                continue
            print("\nAgent: ", end="", flush=True)
            report = run_agent(query, verbose=args.verbose)
            print(report)
            print()
    elif args.file:
        parts = [f"Analyse the network traffic file at '{args.file}' for security threats."]
        if args.contamination != 0.02:
            parts.append(f"Use contamination={args.contamination}.")
        if args.window != "5min":
            parts.append(f"Use time window={args.window}.")
        parts.append("Produce a full threat report.")
        query = " ".join(parts)

        print(f"  File: {args.file}")
        print(f"  Query: {query[:80]}...\n")
        report = run_agent(query, verbose=args.verbose)
        print(report)

        # Save report
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        out  = f"threat_report_{ts}.md"
        with open(out, "w") as f:
            f.write(f"# Threat Report — {args.file}\n\n")
            f.write(f"*Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} by SecureAI Agent*\n\n")
            f.write(report)
        print(f"\n[+] Report saved → {out}")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
