import numpy as np
import joblib
from scapy.all import rdpcap, IP, TCP, UDP

# Step 2 me train hua model load karein
model = joblib.load("threat_model.pkl")

LABEL_MAP = {
    0: ("Benign Traffic", "Normal operational communication"),
    1: ("Reconnaissance (Port Scan)", "Multiple destination ports swept"),
    2: ("Botnet C2 Beaconing", "Strict automated pulse detected (Zero Timing Jitter)"),
    3: ("Volumetric DoS/DDoS", "Abnormal packet surge velocity")
}

def analyze_pcap_file(pcap_path):
    """
    PCAP file ko Rx-only mode me read karke AI model se scan karta hai.
    """
    try:
        packets = rdpcap(pcap_path)
    except Exception:
        return []

    results = []
    flow_packets = []
    
    for pkt in packets:
        if IP in pkt:
            flow_packets.append(pkt)
            if len(flow_packets) >= 20:
                features = extract_flow_features(flow_packets)
                if features:
                    pred = model.predict([features])[0]
                    proba = max(model.predict_proba([features])[0]) * 100
                    if pred != 0:
                        threat_name, signature = LABEL_MAP[pred]
                        results.append({
                            "src": flow_packets[0][IP].src,
                            "dst": flow_packets[0][IP].dst,
                            "threat": threat_name,
                            "confidence": f"{proba:.1f}%",
                            "signature": signature,
                            "packet_count": len(flow_packets)
                        })
                flow_packets = []
    return results

def extract_flow_features(packets):
    sizes = [len(p) for p in packets]
    times = [float(p.time) for p in packets]
    dst_ports = set()
    for p in packets:
        if TCP in p:
            dst_ports.add(p[TCP].dport)
        elif UDP in p:
            dst_ports.add(p[UDP].dport)

    iats = np.diff(times) if len(times) > 1 else [0.0]

    return [
        len(sizes),
        float(np.mean(sizes)),
        float(np.std(sizes)) if len(sizes) > 1 else 0.0,
        float(np.mean(iats)),
        float(np.std(iats)) if len(iats) > 1 else 0.0,
        len(dst_ports) if dst_ports else 1
    ]