def parse_dns(lines):
    results = []
    for line in lines:
        if "query" in line.lower():
            parts = line.split()
            results.append({
                "timestamp": parts[0],
                "source_ip": parts[-2],
                "destination_ip": parts[-1],
                "port": 53,
                "protocol": "UDP",
                "action": "QUERY",
                "service": "dns",
                "log_type": "DNS"
            })
    return results

