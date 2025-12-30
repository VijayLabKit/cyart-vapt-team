def parse_network(lines):
    results = []
    for line in lines:
        parts = line.split()
        if len(parts) >= 5:
            results.append({
                "timestamp": parts[0],
                "source_ip": parts[1],
                "destination_ip": parts[2],
                "port": int(parts[3]),
                "protocol": parts[4],
                "action": "ALLOW",
                "service": "unknown",
                "log_type": "NETWORK"
            })
    return results
