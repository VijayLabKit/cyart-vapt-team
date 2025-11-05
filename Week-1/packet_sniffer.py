#!/usr/bin/env python3
"""
packet_sniffer.py
Capture packets using Scapy, count protocols and produce a bar-chart PNG.
Usage: sudo python3 packet_sniffer.py -i <iface> -c 100 -o capture.pcap
"""
import argparse
from collections import Counter
from scapy.all import sniff, wrpcap
import matplotlib.pyplot as plt

def parse_args():
    p = argparse.ArgumentParser(description="Simple Scapy packet sniffer + protocol chart")
    p.add_argument("-i", "--iface", required=True, help="Interface to sniff (e.g., eth0, wlan0, lo)")
    p.add_argument("-c", "--count", type=int, default=100, help="Number of packets to capture (default 100)")
    p.add_argument("-o", "--out", default="capture.pcap", help="Output pcap filename")
    p.add_argument("-p", "--png", default="protocols_chart.png", help="Output PNG chart filename")
    return p.parse_args()

def proto_name(pkt):
    # Identify top-level protocol name (simple heuristic)
    if pkt.haslayer("TCP"):
        return "TCP"
    if pkt.haslayer("UDP"):
        return "UDP"
    if pkt.haslayer("ICMP") or pkt.haslayer("ICMPv6"):
        return "ICMP"
    if pkt.haslayer("ARP"):
        return "ARP"
    # fallback: use highest layer name
    try:
        return pkt.lastlayer().name
    except Exception:
        return "OTHER"

def main():
    args = parse_args()
    print(f"Capturing {args.count} packets on {args.iface} — press Ctrl+C to stop early")
    packets = sniff(iface=args.iface, count=args.count)
    print(f"Captured {len(packets)} packets — saving to {args.out}")
    wrpcap(args.out, packets)

    # Count protocols
    counts = Counter()
    for pkt in packets:
        counts[proto_name(pkt)] += 1

    print("Protocol counts:", counts)
    # Chart
    labels = list(counts.keys())
    values = [counts[l] for l in labels]

    plt.figure(figsize=(8,5))
    plt.bar(labels, values)
    plt.title(f"Protocol distribution ({len(packets)} packets) on {args.iface}")
    plt.xlabel("Protocol")
    plt.ylabel("Packet count")
    plt.tight_layout()
    plt.savefig(args.png)
    print(f"Chart saved to {args.png}")

if __name__ == "__main__":
    main()
