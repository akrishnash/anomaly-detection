from collections import defaultdict

def group_packets_into_flows(packets):
    """
    Groups a list of Scapy packets into bidirectional flows.
    Returns:
        flows: Dict mapping bidirectional flow_key -> list of packet metadata dicts.
    """
    flows = defaultdict(list)
    
    for pkt in packets:
        # We need IP layer
        if not pkt.haslayer("IP"):
            continue
            
        ip_layer = pkt["IP"]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        if pkt.haslayer("TCP"):
            proto = "TCP"
        elif pkt.haslayer("UDP"):
            proto = "UDP"
        elif pkt.haslayer("ICMP"):
            proto = "ICMP"
        else:
            proto = "Other"

        sport = 0
        dport = 0
        syn_val = 0
        rst_val = 0
        fin_val = 0
        ack_val = 0

        if proto == "TCP":
            tcp = pkt["TCP"]
            sport = tcp.sport
            dport = tcp.dport
            flags = tcp.flags
            # Parse TCP flags
            syn_val = 1 if flags & 0x02 else 0
            rst_val = 1 if flags & 0x04 else 0
            fin_val = 1 if flags & 0x01 else 0
            ack_val = 1 if flags & 0x10 else 0
        elif proto == "UDP":
            udp = pkt["UDP"]
            sport = udp.sport
            dport = udp.dport
            
        pkt_len = len(pkt)
        timestamp = float(pkt.time)
        
        # Bidirectional flow key (IPs and Ports sorted to group both directions of traffic together)
        if src_ip < dst_ip:
            flow_key = (src_ip, dst_ip, sport, dport, proto)
            direction = "fwd"
        else:
            flow_key = (dst_ip, src_ip, dport, sport, proto)
            direction = "bwd"
            
        flows[flow_key].append({
            "time": timestamp,
            "len": pkt_len,
            "direction": direction,
            "syn": syn_val,
            "rst": rst_val,
            "fin": fin_val,
            "ack": ack_val
        })
        
    return flows
