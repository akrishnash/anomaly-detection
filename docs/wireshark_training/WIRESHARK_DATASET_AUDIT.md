# Wireshark Dataset Audit Report

**Dataset Location:** `wireshark_dataset/training_wireshark`  
**Audit Date:** 2026-07-20  

---

## 1. Summary of Capture Files

| File Name | File Size | Packet Count | Capture Duration | Primary Traffic Profile |
| :--- | :--- | :--- | :--- | :--- |
| `capture1.pcapng` | 861.32 MB (903,164,340 B) | 802,310 | 1,526.87 s (~25.45 mins) | Dual IPv6/IPv4, Web & Cloud CDN |
| `capture2.pcapng` | 1,876.47 MB (1,967,622,908 B) | 1,486,422 | 3,964.40 s (~66.07 mins) | High TCP volume, Local Host streaming |
| `capture3.pcapng` | 2,524.68 MB (2,647,315,584 B) | 2,461,100 | 17,932.68 s (~4.98 hours) | Extended baseline, Cloudflare & Google APIs |
| **Total Baseline** | **5.16 GB (5,518,102,832 B)** | **4,749,832** | **23,423.95 s (~6.51 hours)** | **Authentic Local Network Baseline** |

---

## 2. Per-File Detailed Inspection

### File 1: `capture1.pcapng`
- **File Size:** $861.32\,\text{MB}$ ($903,164,340\,\text{bytes}$)
- **Estimated Duration:** $1,526.87\,\text{seconds}$ ($25.45\,\text{minutes}$)
- **Packet Count:** $802,310\,\text{packets}$
- **Protocols Observed:**
  - `IPv6`: $784,771$ ($97.8\%$)
  - `TCP`: $14,533$ ($1.8\%$)
  - `UDP`: $1,945$ ($0.2\%$)
  - `ARP`: $635$
  - `ICMP`: $26$
  - `Other IP`: $400$
- **Top Source IPs:** `2405:201:c012:501e:3890:527:140f:de91` ($626,749$), `2404:6800:4013:813::75` ($67,948$), `2001:4860:482a:7700::` ($16,995$), `192.168.29.114` ($7,962$), `2001:4860:4829:7700::` ($7,559$).
- **Top Destination IPs:** `2404:6800:4013:813::75` ($588,664$), `2405:201:c012:501e:3890:527:140f:de91` ($157,680$), `192.168.29.114` ($7,342$), `2405:201:c012:501e::c0a8:1d01` ($4,650$).

### File 2: `capture2.pcapng`
- **File Size:** $1,876.47\,\text{MB}$ ($1,967,622,908\,\text{bytes}$)
- **Estimated Duration:** $3,964.40\,\text{seconds}$ ($66.07\,\text{minutes}$)
- **Packet Count:** $1,486,422\,\text{packets}$
- **Protocols Observed:**
  - `IPv6`: $1,023,440$ ($68.9\%$)
  - `TCP`: $455,084$ ($30.6\%$)
  - `UDP`: $5,146$ ($0.3\%$)
  - `ARP`: $1,583$
  - `ICMP`: $34$
  - `Other IP`: $1,135$
- **Top Source IPs:** `74.224.107.129` ($263,402$), `2405:201:c012:501e:3890:527:140f:de91` ($250,723$), `192.168.29.114` ($170,862$), `2404:6800:4013:804::cf` ($113,914$).
- **Top Destination IPs:** `2405:201:c012:501e:3890:527:140f:de91` ($771,776$), `192.168.29.114` ($287,994$), `74.224.107.129` ($146,737$).

### File 3: `capture3.pcapng`
- **File Size:** $2,524.68\,\text{MB}$ ($2,647,315,584\,\text{bytes}$)
- **Estimated Duration:** $17,932.68\,\text{seconds}$ ($4.98\,\text{hours}$)
- **Packet Count:** $2,461,100\,\text{packets}$
- **Protocols Observed:**
  - `IPv6`: $2,402,129$ ($97.6\%$)
  - `TCP`: $53,536$ ($2.2\%$)
  - `ARP`: $1,941$
  - `UDP`: $1,689$
  - `ICMP`: $122$
  - `Other IP`: $1,683$
- **Top Source IPs:** `2405:200:161f:1716::d` ($1,422,776$), `2405:201:c012:501e:3890:527:140f:de91` ($554,209$), `2606:4700:9ae9:5cae:73de:c3:3770:961a` ($124,423$).
- **Top Destination IPs:** `2405:201:c012:501e:3890:527:140f:de91` ($1,846,737$), `2405:200:161f:1716::d` ($243,871$), `2606:4700:9ae9:5cae:73de:c3:3770:961a` ($121,430$).

---

## 3. Overall Baseline Assessment

- **Protocol Totals:** `IPv6` ($4,210,340$), `TCP` ($523,153$), `UDP` ($8,780$), `ARP` ($4,159$), `ICMP` ($182$).
- **Suitability:** **PASS**. Clean local network captures without artificial synthetic noise.
- **Traffic Volume:** **SUFFICIENT**. $4.75\,\text{million}$ packets over $6.51\,\text{hours}$ produce thousands of 30s windowed flow samples for training.
