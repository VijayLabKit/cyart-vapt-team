# CYART VAPT Team - Week 2 Deliverables

**Author:** Ishan Chowdhury  
**Role:** VAPT Intern  
**Week:** 2  

---

## Overview

This repository contains all the documentation, scan results, proof-of-concept, reports, and evidence collected during Week 2 of the VAPT internship. Tasks include vulnerability scanning, reconnaissance, exploitation, post-exploitation, and a full VAPT capstone project simulation on Metasploitable2 and DVWA.

---

## Folder Structure

### CSV Files
- `scans_192-168-132-135.csv` — Nmap scan results in CSV format.

### DOCX Files
- `VAPT Report.docx` — Comprehensive VAPT report.
- `report_vulnweb.docx` — Recon and asset mapping for `vulnweb.com`.
- `report_192-168-132-135.docx` — Nmap and Nikto scan analysis.

### Email
- `escalation_email_192-168-132-135.docx` — 100-word PoC escalation email to developers.

### Notes
- `VAPT_2.txt` — Notes and observations from Week 2.

### Remediation Checklist
- `remediation_checklist_192-168-132-135.md` — Prioritized remediation steps.

### Screenshots
Screenshots of scan outputs and tools usage:
- `Screenshot 2025-10-08 181848.png`
- `Screenshot 2025-10-08 221210.png`
- ...
- `Screenshot 2025-10-09 151050.png`  

### Summary
- `exploit_summary_cyart.docx` — Exploitation results.
- `non-technical_summary.docx` — 100-word summary for management.
- `recon_summary_cyart.docx` — 50-word reconnaissance summary.

### TXT Files
- `dig_cyart.txt` — DNS dig outputs.
- `nikto_cyart.txt` — Nikto web scan results.
- `nmap_cyart_allport.txt` — Full Nmap TCP port scan.
- `nmap_cyart_basic.txt` — Nmap basic service/version scan.
- `nmap_cyart_vuln.txt` — Nmap scripts scan output.
- `remediation.txt` — Notes for remediation actions.
- `reverse_dns_cyart.txt` — Reverse DNS lookups.
- `subfinder_cyart.txt` — Subfinder subdomain enumeration.
- `sublist3r_cyart.txt` — Sublist3r subdomain enumeration.
- `whatweb_cyart.txt` — Website technology stack.
- `whois_cyart.txt` — WHOIS lookups.

---

## Tasks Covered

1. **Vulnerability Scanning**
   - Tools: Nmap, Nikto, OpenVAS.
   - Activities: Full TCP port scans, version detection, vulnerability prioritization, PoC email.
   - Outputs: CSV, DOCX, TXT, and email files.

2. **Reconnaissance**
   - Tools: Maltego, Shodan, Sublist3r, Amass.
   - Activities: Asset mapping, subdomain enumeration, tech stack identification.
   - Outputs: Recon summary DOCX, TXT files.

3. **Exploitation**
   - Tools: Metasploit, Burp Suite, sqlmap.
   - Activities: Exploit simulations on Metasploitable2.
   - Outputs: Exploit summary DOCX, screenshots.

4. **Post-Exploitation**
   - Tools: Meterpreter, Volatility.
   - Activities: Privilege escalation attempts, hash collection (Windows 10 local VM).
   - Outputs: Screenshots and notes (VAPT_2.txt).

5. **Capstone Project: Full VAPT Cycle**
   - Tools: DVWA, Kali Linux, Metasploit, sqlmap.
   - Activities: SQL Injection on DVWA, log OpenVAS findings, remediation recommendations.
   - Outputs: PTES report DOCX (200-word), non-technical summary DOCX (100-word).

---

## Key Findings

- Multiple open ports identified via Nmap (21, 22, 23, 25, 53, 80, 111, 139, 445, 3306, etc.).
- Web services running outdated versions (Apache 2.2.8, ProFTPD 1.3.1, MySQL 5.0.51a).
- SQL Injection vulnerability discovered on DVWA (`http://192.168.132.130/dvwa/index.php`).
- Subdomains and exposed services identified for `vulnweb.com`.
- Exploitation tests on Metasploitable2 were successful for certain modules (Tomcat, FTP, SSH).

---

## How to Use

1. Clone the repository:
```bash
git clone https://github.com/VijayLabKit/cyart-vapt-team.git
