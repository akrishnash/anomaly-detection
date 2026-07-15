import numpy as np
import pandas as pd

def extract_flow_features(grouped_flows) -> pd.DataFrame:
    """
    Computes CICFlowMeter-like feature attributes for grouped flows.
    Returns:
        DataFrame: Features with columns matching the 10 core features and flow identifiers.
    """
    flow_data = []
    
    for flow_key, pkts in grouped_flows.items():
        src_ip, dst_ip, sport, dport, proto = flow_key
        
        times = [p["time"] for p in pkts]
        t_start = min(times)
        t_end = max(times)
        duration = t_end - t_start
        
        # Avoid division by zero
        if duration <= 0:
            duration = 0.0001
            
        fwd_bytes = sum(p["len"] for p in pkts if p["direction"] == "fwd")
        bwd_bytes = sum(p["len"] for p in pkts if p["direction"] == "bwd")
        fwd_pkts = sum(1 for p in pkts if p["direction"] == "fwd")
        bwd_pkts = sum(1 for p in pkts if p["direction"] == "bwd")
        total_pkts = len(pkts)
        syn_count = sum(p["syn"] for p in pkts)
        rst_count = sum(p["rst"] for p in pkts)
        fin_count = sum(p["fin"] for p in pkts)
        ack_count = sum(p.get("ack", 0) for p in pkts)
        
        flow_byts_s = (fwd_bytes + bwd_bytes) / duration
        flow_pkts_s = total_pkts / duration
        pkt_len_mean = np.mean([p["len"] for p in pkts])
        
        flow_data.append({
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": sport,
            "dst_port": dport,
            "protocol": proto,
            "flow_byts_s": float(flow_byts_s),
            "flow_pkts_s": float(flow_pkts_s),
            "fwd_bytes": float(fwd_bytes),
            "bwd_bytes": float(bwd_bytes),
            "fwd_packets": int(fwd_pkts),
            "bwd_packets": int(bwd_pkts),
            "total_pkts": int(total_pkts),
            "syn_flag": int(syn_count),
            "rst_flag": int(rst_count),
            "fin_flag": int(fin_count),
            "ack_flag": int(ack_count),
            "flow_duration_s": float(duration),
            "pkt_len_mean": float(pkt_len_mean)
        })
        
    return pd.DataFrame(flow_data)
