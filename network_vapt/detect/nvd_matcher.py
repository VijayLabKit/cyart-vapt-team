import requests
import os

API_KEY = os.getenv("NVD_API_KEY")

def query_nvd(service):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"keywordSearch": service}
    headers = {"apiKey": API_KEY}
    r = requests.get(url, params=params, headers=headers, timeout=15)
    if r.status_code != 200:
        return []
    data = r.json()
    vulns = []
    for item in data.get("vulnerabilities", []):
        cve = item["cve"]
        vulns.append({
            "service": service,
            "cve_id": cve["id"],
            "severity": cve["metrics"]["cvssMetricV31"][0]["cvssData"]["baseSeverity"],
            "score": cve["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"]
        })
    return vulns
