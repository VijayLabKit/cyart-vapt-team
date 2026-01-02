# Network VAPT – Log Ingestion, Detection & Vulnerability Mapping

**Author:** Ishan Chowdhury  
**Position:** VAPT Intern  
**Organization:** CyArt  
**Platform:** Kali Linux  
**Database:** MongoDB Atlas  

---

## 📌 Overview
This project implements a modular **Network Vulnerability Assessment & Penetration Testing (VAPT)** pipeline. It ingests raw network logs, stores them securely in MongoDB Atlas, detects suspicious behavior, and enriches findings with CVE data from the **National Vulnerability Database (NVD)**.

---

## 🎯 Objectives
- Collect raw network logs from Linux systems  
- Normalize and store logs in MongoDB Atlas  
- Perform behavioral detection (e.g., port scans)  
- Prepare detection results for CVE/NVD correlation  
- Provide centralized visibility for SOC monitoring  

---

## 🏗️ Architecture
**Components:**
- **Log Sources:** Linux network logs (connections, neighbor discovery, route updates)
- **Ingestion Engine:** Python scripts on Kali Linux (SSH + parsers)
- **Database:** MongoDB Atlas (logs, alerts, vulns)
- **Detection Engine:** Behavioral analysis (port scan detection)
- **Enrichment Layer:** NVD API for CVE matching
- **Reporting:** Alerts and vulnerability summaries

📎 Refer to `POC/diagrams/network_vapt_architecture.png` for the full diagram.

---

## 📂 Project Structure
```
network_vapt/
├── config/
│   ├── mongo.py
│   └── mongo_alerts.py
├── ingest/
│   ├── main_ingest.py
│   ├── network_parser.py
│   └── dns_parser.py
├── detect/
│   └── detector.py
├── enrich/
│   └── main_enrich.py
├── main_detect.py
├── requirements.txt
├── POC/
│   ├── screenshots/
│   └── diagrams/
└── README.md
```

---

## 🔄 Workflow

### 1️⃣ Ingestion
- SSH to remote log server  
- Fetch `connections_*.log` files  
- Parse & normalize entries  
- Insert into `logs` collection  

### 2️⃣ Storage
- Logs stored in `network_vapt.logs`
- Verified ingestion of **40,000+ entries**
- Ensures persistence, scalability, and SOC visibility

### 3️⃣ Detection
- Scans stored logs for:
  - Abnormal port usage
  - Repeated connections
- Generates `PORT_SCAN` alerts
- Alerts stored in `alerts` collection
- Deduplication via upsert logic

### 4️⃣ Enrichment
- Maps ports → services → CPEs
- Queries NVD API for CVEs
- Stores results in `vulns` collection

---

## 🗄️ Database Collections

| Collection | Purpose |
|----------|--------|
| logs | Raw network logs |
| alerts | Detection results |
| vulns | CVE/NVD matches |

---

## 🧪 Setup & Commands (Kali Linux)

### Environment Setup
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Configure Environment Variables
```bash
export VAPT_DB_USER="your_db_user"
export VAPT_DB_PASSWORD="your_db_password"
export VAPT_DB_HOST="your_cluster_url"
export DB_NAME="network_vapt"
export LOG_SERVER_PASSWORD="your_ssh_password"
```

### Run Pipeline
```bash
# Ingest logs
python3 -m ingest.main_ingest

# Verify logs
python3 - <<EOF
from config.mongo import logs_col
print(logs_col.count_documents({}))
print(logs_col.find_one())
EOF

# Run detection
python3 main_detect.py

# Check alerts
python3 config/mongo_alerts.py

# Run enrichment (optional)
python3 -m enrich.main_enrich
```

---

## 🔍 Verification (MongoDB Atlas)
- Login to MongoDB Atlas  
- Navigate: `cyartcluster → network_vapt → logs`
- Confirm:
  - Document count
  - Raw log visibility
  - Correct `log_type`

---

## 🚀 Status
- ✅ Log Ingestion: Completed  
- ✅ Centralized Storage: Completed  
- ✅ Detection Engine: Completed  
- ✅ MongoDB Atlas Verification: Completed  
- ✅ NVD Readiness: Completed  

---

## 📌 Conclusion
This project delivers a **production-style Network VAPT pipeline** with modular SOC architecture. It enables scalable log ingestion, behavioral detection, and vulnerability mapping using open-source tools and cloud infrastructure. The system is ready for continuous monitoring and future threat correlation via NVD.
