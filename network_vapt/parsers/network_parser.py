import re

IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")

def safe_int(val, default=None):
    try:
        return int(val)
    except Exception:
        return default

def parse_network(lines):
    results = []
    for line in lines:
        parts = line.split()
        if len(parts) < 5:
            # Try regex extraction fallback
            ips = IP_RE.findall(line)
            if len(ips) >= 2:
                ts = parts[0] if parts else None
                port_match = re.search(r"\b(\d{1,5})\b", line)
                port = safe_int(port_match.group(1)) if port_match else None
                proto = "TCP" if "tcp" in line.lower() else "UDP" if "udp" in line.lower() else None
                results.append({
                    "timestamp": ts,
                    "source_ip": ips[0],
                    "destination_ip": ips[1],
                    "port": port,
                    "protocol": proto,
                    "action": "ALLOW",
                    "service": "unknown",
                    "log_type": "NETWORK"
                })
            continue

        ts, src, dst = parts[0], parts[1], parts[2]
        port = safe_int(parts[3])
        proto = parts[4].upper()
        results.append({
            "timestamp": ts,
            "source_ip": src,
            "destination_ip": dst,
            "port": port,
            "protocol": proto,
            "action": "ALLOW",
            "service": "unknown",
            "log_type": "NETWORK"
        })
    return results
