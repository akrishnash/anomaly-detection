import os
import time
import threading
import random
import math
from typing import Optional, List
from collections import deque
import pandas as pd
import numpy as np

# Import pipeline pieces
import flow_generator
import feature_extractor
import preprocessing
import anomaly_detector
import ddos_classifier
import shap_explainer
import database

def resolve_interface_name(target_iface: Optional[str]) -> Optional[str]:
    if not target_iface:
        return None
    try:
        from scapy.all import IFACES
        # 1. Exact match by key
        if target_iface in IFACES:
            return target_iface
        
        # 2. Case-insensitive / normalized name match or description match
        clean_target = target_iface.lower().replace("-", "").replace(" ", "").replace("_", "")
        # First try exact match after cleaning names
        for key, iface in IFACES.items():
            name_clean = iface.name.lower().replace("-", "").replace(" ", "").replace("_", "")
            desc_clean = (iface.description or "").lower().replace("-", "").replace(" ", "").replace("_", "")
            if clean_target == name_clean or clean_target == desc_clean:
                return key
                
        # Then try substring match
        for key, iface in IFACES.items():
            name_clean = iface.name.lower().replace("-", "").replace(" ", "").replace("_", "")
            desc_clean = (iface.description or "").lower().replace("-", "").replace(" ", "").replace("_", "")
            if clean_target in name_clean or clean_target in desc_clean:
                return key
    except Exception:
        pass
    return target_iface

class PacketCaptureManager:
    def __init__(self):
        self.is_running = False
        self.packets = deque()  # Thread-safe packet storage
        self.lock = threading.Lock()
        self.sniff_thread = None
        self.scheduler_thread = None
        
        # Configuration details
        self.interface = None
        self.ip_filter = None
        self.port_filter = None
        self.interface_name = None
        self.pcap_file_path = None
        self.simulated = False
        self.sliding_window_sec = 30
        
        # Latest snapshot data
        self.latest_snapshot = self._get_empty_snapshot()
        self.history = []  # Keep historical snapshots for graphs (up to 30 items)
        
    def _get_empty_snapshot(self):
        return {
            "timestamp": time.time(),
            "total_packets": 0,
            "total_flows": 0,
            "normal_flows": 0,
            "suspicious_flows": 0,
            "attack_flows": 0,
            "detection_rate": 0.0,
            "avg_confidence": 0.0,
            "avg_if_score": 0.0,
            "avg_ensemble_score": 0.0,
            "alerts": [],
            "campaigns": [],
            "charts": {
                "packet_rate": [],
                "flow_rate": [],
                "protocols": {"TCP": 0, "UDP": 0, "Other": 0},
                "attacks": {},
                "top_src_ips": {},
                "top_dst_ips": {}
            }
        }
        
    def start(self, mode_option: int, interface: Optional[str] = None, 
              ip_filter: Optional[str] = None, port_filter: Optional[str] = None, 
              interface_name: Optional[str] = None, pcap_file_path: Optional[str] = None,
              sliding_window_sec: int = 30):
              
        if self.is_running:
            self.stop()
            
        self.is_running = True
        self.interface = interface
        self.ip_filter = ip_filter
        self.port_filter = port_filter
        self.interface_name = interface_name
        self.pcap_file_path = pcap_file_path
        self.sliding_window_sec = sliding_window_sec
        self.packets.clear()
        self.latest_snapshot = self._get_empty_snapshot()
        self.history = []
        
        database.add_log("INFO", f"Starting online detection in Option {mode_option} (window={sliding_window_sec}s)")
        
        # Launch sniffer thread based on selected option
        self.sniff_thread = threading.Thread(
            target=self._run_capture_loop, 
            args=(mode_option,), 
            daemon=True
        )
        self.sniff_thread.start()
        
        # Launch scheduling loop that processes packets and runs predictions every 30 seconds
        self.scheduler_thread = threading.Thread(
            target=self._run_scheduler_loop, 
            daemon=True
        )
        self.scheduler_thread.start()

    def stop(self):
        if not self.is_running:
            return
        self.is_running = False
        database.add_log("INFO", "Stopping online packet detection capture manager.")
        
        # Note: threads will exit since daemon is True and is_running flag is False

    def inject_packet_data(self, pkt_data: dict):
        """
        Option 5: External endpoint packet streaming injection.
        Constructs a mock Scapy-like object or metadata dictionary and inserts it into the queue.
        """
        with self.lock:
            # We construct a simple mock Scapy packet wrapper so it can be parsed by flow_generator
            class MockScapyPacket:
                def __init__(self, d):
                    self.time = d.get("time", time.time())
                    self.src = d.get("src_ip", "192.168.1.100")
                    self.dst = d.get("dst_ip", "10.0.0.1")
                    self.sport = d.get("src_port", 1234)
                    self.dport = d.get("dst_port", 80)
                    self.proto = d.get("protocol", "TCP").upper()
                    self.len = d.get("length", 64)
                    self.syn = d.get("syn_flag", 0)
                    self.rst = d.get("rst_flag", 0)
                    self.fin = d.get("fin_flag", 0)

                def haslayer(self, layer_name):
                    if layer_name == "IP":
                        return True
                    if layer_name in ["TCP", "UDP"]:
                        return self.proto == layer_name
                    return False

                def __getitem__(self, item):
                    if item == "IP":
                        return self
                    if item in ["TCP", "UDP"]:
                        return self
                    raise KeyError(item)

                @property
                def flags(self):
                    # Reconstruct bitmask flags
                    val = 0
                    if self.syn: val |= 0x02
                    if self.rst: val |= 0x04
                    if self.fin: val |= 0x01
                    return val

            pkt = MockScapyPacket(pkt_data)
            self.packets.append(pkt)

    def _run_capture_loop(self, option: int):
        # Determine if we should sniff or simulate
        bpf_filter = ""
        if self.ip_filter:
            bpf_filter += f"host {self.ip_filter}"
        if self.port_filter:
            if bpf_filter:
                bpf_filter += " and "
            bpf_filter += f"port {self.port_filter}"
            
        target_iface = None
        if option == 1:
            target_iface = self.interface
        elif option == 3:
            target_iface = self.interface_name
            
        if target_iface:
            resolved = resolve_interface_name(target_iface)
            if resolved:
                target_iface = resolved
                
        # Option 4: PCAP Live Stream
        if option == 4:
            self._stream_pcap_file()
            return

        # Option 5: Handled completely via inject_packet_data endpoint, we just sleep
        if option == 5:
            while self.is_running:
                time.sleep(1)
            return

        # Default standard sniffing (Option 1, 2, 3)
        try:
            from scapy.all import sniff
            
            def callback(pkt):
                if not self.is_running:
                    return
                with self.lock:
                    self.packets.append(pkt)
                    
            database.add_log("INFO", f"Scapy Sniffer binding to iface={target_iface}, filter={bpf_filter}")
            while self.is_running:
                sniff(
                    iface=target_iface,
                    filter=bpf_filter if bpf_filter else None,
                    prn=callback,
                    timeout=2.0,
                    store=False
                )
        except Exception as e:
            err_msg = str(e)
            import sys
            from scapy.config import conf
            if "winpcap" in err_msg.lower() or "libpcap" in err_msg.lower() or "npcap" in err_msg.lower() or (sys.platform == "win32" and conf.L2socket is None):
                database.add_log(
                    "WARNING",
                    "Scapy Sniffer initialization failed: Npcap/WinPcap is not installed or running. "
                    "Please install Npcap (https://npcap.com/) and run the application as Administrator for live packet capture on Windows. "
                    "Falling back to simulation mode."
                )
            else:
                database.add_log("WARNING", f"Scapy Sniffer initialization failed: {e}. Falling back to simulation mode.")
            self.simulated = True
            self._run_simulation_loop()

    def _stream_pcap_file(self):
        """Simulate a live stream by reading a PCAP file in a background thread."""
        try:
            from scapy.all import rdpcap
            if not self.pcap_file_path or not os.path.exists(self.pcap_file_path):
                database.add_log("ERROR", f"PCAP stream source file not found: {self.pcap_file_path}")
                self.simulated = True
                self._run_simulation_loop()
                return

            database.add_log("INFO", f"Reading PCAP file {self.pcap_file_path} for live streaming...")
            pkts = rdpcap(self.pcap_file_path)
            
            if not pkts:
                database.add_log("WARNING", "PCAP file is empty. Simulating traffic.")
                self.simulated = True
                self._run_simulation_loop()
                return

            idx = 0
            while self.is_running:
                pkt = pkts[idx % len(pkts)]
                # Modify timestamp to current time to avoid immediate eviction by sliding window
                pkt.time = time.time()
                with self.lock:
                    self.packets.append(pkt)
                idx += 1
                # Stream at ~15 packets per second
                time.sleep(1.0 / 15.0)
        except Exception as e:
            database.add_log("ERROR", f"PCAP stream failed: {e}. Defaulting to traffic simulator.")
            self.simulated = True
            self._run_simulation_loop()

    def _run_simulation_loop(self):
        """Generates realistic normal and attack traffic patterns."""
        from scapy.layers.inet import IP, TCP, UDP
        from scapy.all import Raw
        
        database.add_log("INFO", "Traffic Simulator started.")
        
        while self.is_running:
            curr_time = time.time()
            num_pkts = random.randint(10, 45)
            is_attack = random.random() < 0.15 # 15% probability of attack occurrence
            
            pkts_to_add = []
            if is_attack:
                attack_type = random.choice(["scan", "ddos", "exfil", "brute"])
                if attack_type == "scan":
                    src_ip = f"192.168.1.{random.randint(150, 220)}"
                    dst_ip = "192.168.1.1"
                    for _ in range(num_pkts):
                        sport = random.randint(1024, 65535)
                        dport = random.randint(1, 1024)
                        p = IP(src=src_ip, dst=dst_ip)/TCP(sport=sport, dport=dport, flags="S")
                        p.time = curr_time + random.uniform(-0.2, 0.2)
                        pkts_to_add.append(p)
                elif attack_type == "ddos":
                    dst_ip = "192.168.1.10"
                    dport = 80
                    for _ in range(num_pkts):
                        src_ip = f"185.220.101.{random.randint(1, 254)}"
                        sport = random.randint(1024, 65535)
                        p = IP(src=src_ip, dst=dst_ip)/TCP(sport=sport, dport=dport, flags="A")
                        p.time = curr_time + random.uniform(-0.2, 0.2)
                        pkts_to_add.append(p)
                elif attack_type == "exfil":
                    src_ip = "192.168.1.45"
                    dst_ip = "91.198.174.192"
                    sport = random.randint(2000, 5000)
                    dport = 443
                    for _ in range(num_pkts // 2):
                        p = IP(src=src_ip, dst=dst_ip)/TCP(sport=sport, dport=dport, flags="PA")/Raw(load=b"A" * random.randint(1100, 1400))
                        p.time = curr_time + random.uniform(-0.2, 0.2)
                        pkts_to_add.append(p)
                elif attack_type == "brute":
                    src_ip = "192.168.1.72"
                    dst_ip = "192.168.1.250"
                    dport = 22
                    for _ in range(num_pkts // 3):
                        sport = random.randint(3000, 4000)
                        p = IP(src=src_ip, dst=dst_ip)/TCP(sport=sport, dport=dport, flags="S")
                        p.time = curr_time + random.uniform(-0.2, 0.2)
                        pkts_to_add.append(p)
            else:
                # Benign traffic
                for _ in range(num_pkts):
                    src_ip = f"192.168.1.{random.randint(2, 90)}"
                    dst_ip = f"192.168.1.{random.randint(91, 254)}"
                    sport = random.randint(1024, 65535)
                    dport = random.choice([80, 443, 53, 123])
                    
                    if dport == 53 or dport == 123:
                        p = IP(src=src_ip, dst=dst_ip)/UDP(sport=sport, dport=dport)
                    else:
                        flags = random.choice(["A", "PA", "FA"])
                        p = IP(src=src_ip, dst=dst_ip)/TCP(sport=sport, dport=dport, flags=flags)
                        if random.random() < 0.3:
                            p = p/Raw(load=b"X" * random.randint(30, 300))
                    p.time = curr_time + random.uniform(-0.2, 0.2)
                    pkts_to_add.append(p)
                    
            with self.lock:
                self.packets.extend(pkts_to_add)
                
            time.sleep(1.0) # sleep 1 second before generating more packets

    def _run_scheduler_loop(self):
        """Triggers prediction pipeline at sliding window intervals (e.g. 30 seconds)."""
        database.add_log("INFO", f"Scheduler daemon active. Interval = {self.sliding_window_sec}s.")
        
        while self.is_running:
            # Wait for the sliding window interval
            time.sleep(self.sliding_window_sec)
            
            if not self.is_running:
                break
                
            try:
                self.perform_inference()
            except Exception as e:
                database.add_log("ERROR", f"Online sliding window prediction error: {str(e)}")
                import traceback
                traceback.print_exc()

    def perform_inference(self):
        curr_time = time.time()
        window_start = curr_time - self.sliding_window_sec
        
        with self.lock:
            # Evict packets older than the sliding context window
            self.packets = deque([p for p in self.packets if float(p.time) >= window_start])
            active_packets = list(self.packets)
            
        total_packets = len(active_packets)
        
        if total_packets == 0:
            # Empty window
            self.latest_snapshot = self._get_empty_snapshot()
            self.latest_snapshot["timestamp"] = curr_time
            return
            
        # 1. Group into flows
        grouped_flows = flow_generator.group_packets_into_flows(active_packets)
        total_flows = len(grouped_flows)
        
        if total_flows == 0:
            self.latest_snapshot = self._get_empty_snapshot()
            self.latest_snapshot["timestamp"] = curr_time
            self.latest_snapshot["total_packets"] = total_packets
            return
            
        # 2. Extract flow features
        df_flows = feature_extractor.extract_flow_features(grouped_flows)
        
        # 3. Clean & Preprocess
        X_scaled, feature_names, df_canonical = preprocessing.preprocess_dataset(df_flows)
        df_feats = preprocessing.extract_features(df_canonical)
        
        # 4. Unsupervised ensemble scoring (Isolation Forest + Autoencoder)
        probs, if_scores, ae_scores = anomaly_detector.score_flows(X_scaled)

        # Analyze predictions
        normal_count = 0
        suspicious_count = 0
        attack_count = 0

        total_ensemble_score = 0.0
        total_if_score = 0.0
        
        alerts = []
        protocols_count = {"TCP": 0, "UDP": 0, "Other": 0}
        attacks_count = {}
        top_src_ips = {}
        top_dst_ips = {}
        
        # Determine anomaly flags for all rows based on user threshold
        conf_thresh = float(database.get_setting("confidence_threshold", "0.5"))
        is_anomaly_array = (probs >= conf_thresh)
        anomaly_indices = np.where(is_anomaly_array)[0]
        
        # Compute SHAP in batch for anomalies to save time
        shap_results = {}
        if len(anomaly_indices) > 0:
            batch_shap = shap_explainer.explain_predictions_batch(X_scaled[anomaly_indices])
            for idx, res in zip(anomaly_indices, batch_shap):
                shap_results[idx] = res

        db_predictions = []
        campaign_inputs = []

        for i in range(total_flows):
            # Sanitize inputs to prevent NaN/Infinity propagating into metrics or JSON
            raw_prob = float(probs[i])
            raw_if_score = float(if_scores[i])
            prob = 0.0 if (math.isnan(raw_prob) or math.isinf(raw_prob)) else raw_prob
            if_score = 0.0 if (math.isnan(raw_if_score) or math.isinf(raw_if_score)) else raw_if_score

            total_ensemble_score += prob
            total_if_score += if_score
            
            flow_info = df_feats.iloc[i].to_dict()
            proto = df_canonical.iloc[i]["protocol"]
            src_ip = df_canonical.iloc[i]["src_ip"]
            dst_ip = df_canonical.iloc[i]["dst_ip"]
            dst_port = int(df_canonical.iloc[i]["dst_port"])
            
            protocols_count[proto] = protocols_count.get(proto, 0) + 1
            top_src_ips[src_ip] = top_src_ips.get(src_ip, 0) + 1
            top_dst_ips[dst_ip] = top_dst_ips.get(dst_ip, 0) + 1
            
            rule_input = dict(flow_info)
            rule_input["protocol"] = proto
            rule_input["src_port"] = df_canonical.iloc[i].get("src_port", 0)
            rule_input["dst_port"] = dst_port
            threat_verdict = ddos_classifier.classify_flow(rule_input)
            
            rule_is_attack = threat_verdict["attack_type"] not in ["Normal", "Unknown Anomaly"] and threat_verdict["confidence"] >= 0.4
            is_anomaly = bool(is_anomaly_array[i]) or rule_is_attack
            
            if not is_anomaly:
                normal_count += 1
                threat_type = "Normal"
                severity = "Low"
                shap_contrib = []
                explanation_text = "Traffic flow matched the benign baseline signature. No threat detected."
            else:
                attack_count += 1
                threat_type = threat_verdict["attack_type"]
                severity = threat_verdict["severity"]
                if rule_is_attack and prob < 0.5:
                    prob = max(prob, float(threat_verdict["confidence"]))
                
                shap_contrib, explanation_text = shap_results.get(i, ([], "Threat signature detected."))
                if threat_verdict["evidence"]:
                    explanation_text += " Signature evidence: " + "; ".join(threat_verdict["evidence"]) + "."
                campaign_inputs.append({
                    "id": i,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "attack_type": threat_type,
                    "severity": severity,
                    "total_pkts": flow_info.get("total_pkts", 0)
                })
                
            alert_item = {
                "id": i,
                "timestamp": datetime_string(curr_time),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": proto,
                "dst_port": dst_port,
                "prediction": 1 if is_anomaly else 0,
                "confidence": round(prob * 100, 2) if is_anomaly else round((1 - prob) * 100, 2),
                "attack_type": threat_type,
                "severity": severity,
                "if_score": round(if_score, 4),
                "ensemble_score": round(prob, 4),
                "shap_explanation": shap_contrib,
                "explanation_text": explanation_text,
                "flow_details": {k: (0.0 if (pd.isna(v) or np.isinf(v)) else (round(float(v), 4) if isinstance(v, (float, np.floating)) else int(v))) for k, v in flow_info.items() if k not in ["src_ip", "dst_ip", "protocol"]}
            }
            alerts.append(alert_item)
            
            db_predictions.append({
                "mode": "Online",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": proto,
                "dst_port": dst_port,
                "prediction": 1 if is_anomaly else 0,
                "confidence": prob * 100 if is_anomaly else (1 - prob) * 100,
                "attack_type": threat_type,
                "if_score": if_score,
                "ensemble_score": prob,
                "shap_explanation": shap_contrib
            })

        # Aggregate anomalies into campaigns (distributed attacks, port scans)
        # and apply cross-flow label refinements before persisting/reporting
        campaigns, refinements = ddos_classifier.aggregate_campaigns(campaign_inputs)
        for idx, (new_type, new_severity, reason) in refinements.items():
            alerts[idx]["attack_type"] = new_type
            alerts[idx]["severity"] = new_severity
            alerts[idx]["refinement_reason"] = reason
            db_predictions[idx]["attack_type"] = new_type

        # Attack subtype counts for charts (after refinement)
        for a in alerts:
            if a["prediction"] == 1:
                attacks_count[a["attack_type"]] = attacks_count.get(a["attack_type"], 0) + 1

        # Batch insert predictions
        database.add_predictions_batch(db_predictions)
                
        # Detection rate is (attack flows / total flows) * 100
        detection_rate = (attack_count / total_flows) * 100 if total_flows > 0 else 0.0
        
        avg_ensemble_score = total_ensemble_score / total_flows if total_flows > 0 else 0.0
        avg_if_score = total_if_score / total_flows if total_flows > 0 else 0.0
        
        # Sort alerts by confidence score descending
        alerts = sorted(alerts, key=lambda x: x["confidence"], reverse=True)
        
        # Build snapshot charts data
        timestamp_label = datetime_time_string(curr_time)
        
        self.latest_snapshot = {
            "timestamp": curr_time,
            "total_packets": total_packets,
            "total_flows": total_flows,
            "normal_flows": normal_count,
            "suspicious_flows": suspicious_count, # placeholder or calculated separately
            "attack_flows": attack_count,
            "detection_rate": round(detection_rate, 2),
            "avg_confidence": round(avg_ensemble_score * 100, 2),
            "avg_if_score": round(avg_if_score, 4),
            "avg_ensemble_score": round(avg_ensemble_score, 4),
            "alerts": alerts,
            "campaigns": campaigns,
            "charts": {
                "packet_rate": [{"time": timestamp_label, "packets": total_packets}],
                "flow_rate": [{"time": timestamp_label, "flows": total_flows}],
                "protocols": protocols_count,
                "attacks": attacks_count,
                "top_src_ips": dict(sorted(top_src_ips.items(), key=lambda x: x[1], reverse=True)[:5]),
                "top_dst_ips": dict(sorted(top_dst_ips.items(), key=lambda x: x[1], reverse=True)[:5])
            }
        }
        
        # Append snapshot to history
        self.history.append(self.latest_snapshot)
        if len(self.history) > 30:
            self.history.pop(0)
            
        database.add_log("INFO", f"Online sliding window processing: {total_packets} pkts, {total_flows} flows. Detection Rate: {detection_rate:.2f}%")

def datetime_string(epoch_time):
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(epoch_time))

def datetime_time_string(epoch_time):
    return time.strftime("%H:%M:%S", time.localtime(epoch_time))
