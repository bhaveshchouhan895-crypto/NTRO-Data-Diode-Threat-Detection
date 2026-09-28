from scapy.all import Ether, IP, TCP, wrpcap
import time

packets = []
base_time = time.time()

# 1. Normal/Benign Packets (50 packets)
for i in range(50):
    pkt = IP(src="192.168.1.50", dst="10.0.0.1") / TCP(sport=1024 + i, dport=80)
    pkt.time = base_time + (i * 0.1)
    packets.append(pkt)

# 2. Port Scan Attack (30 unique ports swept in short time)
for p in range(20, 50):
    pkt = IP(src="192.168.1.199", dst="10.0.0.1") / TCP(sport=5555, dport=p)
    pkt.time = base_time + 10.0 + (p * 0.01)
    packets.append(pkt)

# 3. Volumetric Burst (DDoS)
for i in range(400):
    pkt = IP(src="203.0.113.5", dst="10.0.0.1") / TCP(sport=8080, dport=443)
    pkt.time = base_time + 15.0 + (i * 0.0005)
    packets.append(pkt)

wrpcap("sample_traffic.pcap", packets)
print("✅ 'sample_traffic.pcap' file ban chuki hai!")