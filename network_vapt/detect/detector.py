import re
import os
from collections import defaultdict
from config.mongo import logs_col, alerts_col

# Configurable threshold (default 10)
PORT_SCAN_THRESHOLD = int(os.getenv("PORT_SCAN_THRESHOLD", "10"))

IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
PORT_RE = re.compile(r"\b(\d{1,5})\b")

def run_detection():
    ip_ports = defaultdict(set)
    total_logs = 0

    # Look at all NETWORK logs
    cursor = logs_col.find({"log_type": "NETWORK"}, projection={"raw": 1, "source_ip": 1, "port": 1})
    for doc in cursor:
        total_logs += 1
        src = doc.get("source_ip")
        port = doc.get("port")

        if src and isinstance(port, int):
            ip_ports[src].add(port)
            continue

        raw = doc.get("raw", "")
        ips = IP_RE.findall(raw)
        ports = PORT_RE.findall(raw)
        if ips and ports:
            try:
                ip_ports[ips[0]].add(int(ports[0]))
            except Exception:
                pass

    print(f"[+] Analyzed {total_logs} logs")
    print(f"[+] Found {len(ip_ports)} unique source IPs")

    alerts_generated = 0
    for ip, ports in ip_ports.items():
        print(f"[DEBUG] {ip} touched {len(ports)} unique ports: {sorted(list(ports))}")
        if len(ports) >= PORT_SCAN_THRESHOLD:
            try:
                alerts_col.insert_one({
                    "type": "PORT_SCAN",
                    "source_ip": ip,
                    "ports": sorted(list(ports)),
                    "confidence": "HIGH"
                })
                alerts_generated += 1
            except Exception as e:
                print(f"[!] Alert insert error for {ip}: {e}")

    print(f"[+] Detection completed — {alerts_generated} alerts generated")
