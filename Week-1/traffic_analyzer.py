# traffic_analyzer.py
"""
Analyzes HTTPS traffic metadata from a PCAP file.
Generates packet counts and packet size distribution chart.
"""

import pyshark
import matplotlib.pyplot as plt
from collections import Counter

# Load capture file
capture = pyshark.FileCapture('traffic_capture.pcapng', display_filter='tls')

packet_sizes = []
ip_counts = Counter()

for packet in capture:
    try:
        size = int(packet.length)
        src_ip = packet.ip.src
        dst_ip = packet.ip.dst

        packet_sizes.append(size)
        ip_counts[src_ip] += 1
        ip_counts[dst_ip] += 1
    except AttributeError:
        continue  # Skip packets without IP info

# Show top IPs
print("\nTop IP addresses by packet count:")
for ip, count in ip_counts.most_common(5):
    print(f"{ip}: {count} packets")

# Generate histogram of packet sizes
plt.hist(packet_sizes, bins=20, edgecolor='black')
plt.title("Packet Size Distribution")
plt.xlabel("Packet Size (bytes)")
plt.ylabel("Frequency")
plt.savefig("packet_size_distribution.png")
plt.show()
