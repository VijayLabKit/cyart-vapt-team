#!/usr/bin/env python3
import sys
from config.mongo import vulns_col, logs_col
from enrich.nvd_matcher import query_nvd

def discover_services(limit=10):
    # Simple heuristic: use distinct 'service' from parsed logs
    services = logs_col.distinct("service")
    services = [s for s in services if s and s != "unknown"]
    return services[:limit] if limit else services

def save_vulns(vulns):
    if not vulns:
        return 0
    try:
        vulns_col.insert_many(vulns, ordered=False)
        return len(vulns)
    except Exception as e:
        print(f"[!] Vuln insert error: {e}")
        return 0

if __name__ == "__main__":
    if len(sys.argv) >= 2:
        services = sys.argv[1:]
    else:
        services = discover_services()

    total = 0
    for service in services:
        results = query_nvd(service)
        count = save_vulns(results)
        print(f"[+] {service}: saved {count} CVEs")
        total += count

    print(f"[+] Total CVEs saved: {total}")
