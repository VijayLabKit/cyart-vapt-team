import re

IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")

def parse_dns(lines):
    results = []
    for line in lines:
        lower = line.lower()
        if "query" in lower and "dns" in lower or "port 53" in lower:
            parts = line.split()
            if len(parts) < 3:
                continue
            ts = parts[0]
            ips = IP_RE.findall(line)
            src = ips[0] if ips else None
            dst = ips[1] if len(ips) > 1 else None
            results.append({
                "timestamp": ts,
                "source_ip": src,
                "destination_ip": dst,
                "port": 53,
                "protocol": "UDP",
                "action": "QUERY",
                "service": "dns",
                "log_type": "DNS"
            })
    return results
