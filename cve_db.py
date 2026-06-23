"""
Static CVE / attack context database.
Maps anomaly types detected by the Isolation Forest to relevant CVEs,
MITRE ATT&CK techniques, and remediation pointers.
"""

CVE_DB: dict[str, dict] = {
    "Port Scan": {
        "description": (
            "Port scanning probes a host or network to discover open services. "
            "It is typically the reconnaissance phase of a multi-stage attack."
        ),
        "mitre": "T1046 — Network Service Discovery",
        "cves": [
            {
                "id": "CVE-2021-44228",
                "summary": "Log4Shell — exploited after port 8080/8443 enumeration reveals Log4j-backed services.",
                "cvss": 10.0,
            },
            {
                "id": "CVE-2022-0847",
                "summary": "Dirty Pipe — local privilege escalation after SSH (port 22) is reached via scan.",
                "cvss": 7.8,
            },
        ],
        "mitigations": [
            "Block unsolicited inbound SYN packets at the perimeter firewall.",
            "Enable port-scan detection on IDS (Snort rule sid:1000001).",
            "Restrict internal host-to-host port enumeration with micro-segmentation.",
        ],
    },
    "Brute Force": {
        "description": (
            "Repeated failed authentication attempts against a single port, "
            "typically SSH (22), RDP (3389), or HTTP (80/443)."
        ),
        "mitre": "T1110 — Brute Force",
        "cves": [
            {
                "id": "CVE-2023-38408",
                "summary": "OpenSSH remote code execution — brute-forced credential access enables exploit delivery.",
                "cvss": 9.8,
            },
            {
                "id": "CVE-2019-0708",
                "summary": "BlueKeep RDP — attackers brute-force weak RDP credentials then pivot with BlueKeep.",
                "cvss": 9.8,
            },
        ],
        "mitigations": [
            "Enforce account lockout after 5 failed attempts.",
            "Deploy fail2ban or equivalent on all internet-facing services.",
            "Require MFA for SSH and RDP; disable password authentication where possible.",
            "Rate-limit inbound connections per source IP at the firewall.",
        ],
    },
    "Traffic Spike": {
        "description": (
            "A sudden, sustained surge in inbound traffic volume — "
            "characteristic of volumetric DDoS or data flood attacks."
        ),
        "mitre": "T1498 — Network Denial of Service",
        "cves": [
            {
                "id": "CVE-2022-26143",
                "summary": "TP-240 amplification DDoS — reflector exploited to produce >4 billion:1 amplification ratio.",
                "cvss": 8.6,
            },
            {
                "id": "CVE-2021-3156",
                "summary": "Sudo heap overflow — exploited post-DDoS once legitimate traffic is disrupted.",
                "cvss": 7.8,
            },
        ],
        "mitigations": [
            "Enable rate-limiting and traffic shaping at the upstream edge.",
            "Activate scrubbing centre / CDN DDoS protection (e.g., Cloudflare Magic Transit).",
            "Alert on traffic volume exceeding 3× 15-minute baseline.",
            "Validate source IPs with BCP-38 anti-spoofing filters.",
        ],
    },
    "Data Exfiltration": {
        "description": (
            "Sustained high-volume outbound transfers from a single internal host — "
            "consistent with an attacker staging and transferring sensitive data."
        ),
        "mitre": "T1048 — Exfiltration Over Alternative Protocol",
        "cves": [
            {
                "id": "CVE-2023-0669",
                "summary": "GoAnywhere MFT RCE — used in Cl0p ransomware campaign that exfiltrated 130+ organisations.",
                "cvss": 7.2,
            },
            {
                "id": "CVE-2021-26855",
                "summary": "ProxyLogon (Exchange) — gave attackers mailbox access enabling large-scale email exfiltration.",
                "cvss": 9.8,
            },
        ],
        "mitigations": [
            "Enforce egress filtering — alert on outbound transfers >500 MB from a single host.",
            "Enable DLP rules on the network boundary.",
            "Inspect and log DNS queries for long or encoded subdomains (DNS tunnelling).",
            "Segment high-value data stores and require explicit egress approval.",
        ],
    },
    "Night Activity": {
        "description": (
            "Significant connection volume occurring during off-hours (00:00–05:59). "
            "Often indicates automated/scripted attacker activity or compromised host beaconing."
        ),
        "mitre": "T1029 — Scheduled Transfer",
        "cves": [
            {
                "id": "CVE-2020-1472",
                "summary": "Zerologon — exploited in off-hours DC attacks by ransomware operators to reset machine passwords.",
                "cvss": 10.0,
            },
            {
                "id": "CVE-2021-34527",
                "summary": "PrintNightmare — privilege escalation used in overnight lateral movement campaigns.",
                "cvss": 8.8,
            },
        ],
        "mitigations": [
            "Alert on any outbound connection from servers during 00:00–05:59 outside of maintenance windows.",
            "Implement time-of-day access controls for privileged accounts.",
            "Require change-management approval for overnight batch jobs.",
        ],
    },
    "Botnet C&C": {
        "description": (
            "Long idle flows with low packet rate and irregular timing — "
            "hallmarks of botnet command-and-control beacon traffic."
        ),
        "mitre": "T1071 — Application Layer Protocol C2",
        "cves": [
            {
                "id": "CVE-2021-44228",
                "summary": "Log4Shell — widely used in Mirai/Muhstik botnet initial access campaigns.",
                "cvss": 10.0,
            },
            {
                "id": "CVE-2017-0144",
                "summary": "EternalBlue (SMB) — Mirai and subsequent botnets exploited this for rapid propagation.",
                "cvss": 9.3,
            },
        ],
        "mitigations": [
            "Block known C&C IP ranges using threat intelligence feeds (e.g., Abuse.ch).",
            "Inspect long-duration low-bandwidth flows — typical C&C beacon signature.",
            "Enable DNS RPZ (Response Policy Zone) to sinkhole known botnet domains.",
            "Hunt for processes making outbound connections on unusual ports.",
        ],
    },
    "Unknown": {
        "description": (
            "The Isolation Forest flagged this window as anomalous but no specific "
            "attack pattern matched the rule-based classifier. Manual review recommended."
        ),
        "mitre": "T1040 — Network Sniffing (investigate further)",
        "cves": [],
        "mitigations": [
            "Capture a full PCAP of the flagged window for manual inspection.",
            "Cross-reference source IP against threat intelligence (VirusTotal, Shodan).",
            "Review host logs for the flagged source IP at the anomaly timestamp.",
        ],
    },
}


def lookup_cve(attack_type: str) -> dict:
    """Return CVE context for a given attack type detected by the anomaly detector."""
    return CVE_DB.get(attack_type, CVE_DB["Unknown"])
