#!/usr/bin/env python3
"""
test_packets.py

Scapy-based SYN packet generator for lab testing (Task 03).
Sends SYNs to a range of destination ports to simulate a simple port scan.

Usage (run as root):
  sudo python3 test_packets.py --target 127.0.0.1 --start 1 --end 200 --delay 0.01
"""

from typing import List
import argparse
import time
from scapy.all import IP, TCP, send  # requires python3-scapy

def parse_ports(start: int, end: int) -> List[int]:
    """Return a list of ports from start to end (inclusive)."""
    return list(range(start, end + 1))

def send_syn_scan(target: str, ports: List[int], delay: float = 0.01) -> None:
    """
    Send TCP SYN packets to target:ports.

    Args:
        target: destination IP or hostname (lab/Vm only).
        ports: list of destination ports to send SYNs to.
        delay: seconds to wait between packets to avoid flooding the NIC.
    """
    for dport in ports:
        pkt = IP(dst=target) / TCP(dport=dport, flags="S")
        # send at L3 (will craft L2 automatically). verbose=False to reduce noise.
        send(pkt, verbose=False)
        time.sleep(delay)

def main() -> None:
    p = argparse.ArgumentParser(description="Scapy SYN port-scan generator (lab use only).")
    p.add_argument("--target", "-t", required=True, help="Target IP (e.g., 127.0.0.1)")
    p.add_argument("--start", type=int, default=1, help="Start port (default 1)")
    p.add_argument("--end", type=int, default=1024, help="End port (default 1024)")
    p.add_argument("--delay", type=float, default=0.01, help="Delay between packets (seconds)")
    args = p.parse_args()

    ports = parse_ports(args.start, args.end)
    print(f"[+] Sending SYN packets to {args.target} ports {args.start}-{args.end} (delay={args.delay}s)")
    send_syn_scan(args.target, ports, args.delay)
    print("[+] Done.")

if __name__ == "__main__":
    main()
