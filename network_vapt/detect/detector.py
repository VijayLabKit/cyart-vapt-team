import re
from collections import defaultdict
from config.mongo import logs_col, alerts_col

def run_detection():
    ip_ports = defaultdict(set)

    for log in logs_col.find({"log_type": "NETWORK"}):
        raw = log.get("raw", "")

        ips = re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", raw)
        ports = re.findall(r"\b(22|80|443|21|25|53|3389)\b", raw)

        if len(ips) >= 2 and ports:
            src = ips[0]
            port = int(ports[0])
            ip_ports[src].add(port)

    for ip, ports in ip_ports.items():
        if len(ports) >= 10:
            alerts_col.insert_one({
                "type": "PORT_SCAN",
                "source_ip": ip,
                "ports": list(ports),
                "confidence": "HIGH"
            })

