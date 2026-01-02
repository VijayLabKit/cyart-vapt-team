import requests
import os

API_KEY = os.getenv("NVD_API_KEY")

def query_nvd(service):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"keywordSearch": service}
    headers = {}
    if API_KEY:
        headers["apiKey"] = API_KEY

    try:
        r = requests.get(url, params=params, headers=headers, timeout=15)
        r.raise_for_status()
    except requests.RequestException as e:
        print(f"[!] NVD query error: {e}")
        return []

    data = r.json()
    vulns = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        metrics = cve.get("metrics", {})
        cvss = None
        if "cvssMetricV31" in metrics:
            cvss = metrics["cvssMetricV31"][0].get("cvssData", {})
        elif "cvssMetricV30" in metrics:
            cvss = metrics["cvssMetricV30"][0].get("cvssData", {})

        vulns.append({
            "service": service,
            "cve_id": cve.get("id"),
            "severity": cvss.get("baseSeverity"),
            "score": cvss.get("baseScore")
        })
    return vulns
