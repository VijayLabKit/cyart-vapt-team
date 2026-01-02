Network VAPT – Log Ingestion, Detection & Vulnerability Mapping

Author: Ishan ChowdhuryPosition: VAPT InternOrganization: CyArtPlatform: Kali LinuxDatabase: MongoDB Atlas

📌 Project Overview

This project implements a modular Network-based Vulnerability Assessment & Penetration Testing (VAPT) pipeline. It collects raw network logs from Linux systems, stores them securely in MongoDB Atlas, analyzes them for suspicious behavior, and prepares the data for CVE correlation using the National Vulnerability Database (NVD).

The architecture follows SOC-style principles, separating ingestion, detection, and enrichment into distinct, auditable stages.

🎯 Objectives

Collect raw network logs from Linux systems

Normalize and store logs securely in MongoDB Atlas

Perform behavioral detection on stored logs

Prepare detection results for CVE/NVD correlation

Provide centralized visibility for security analysis

🏗️ Architecture Overview

Components:

Log Sources: Linux network logs (connections, neighbor discovery, route updates)

Ingestion Engine: Python scripts on Kali Linux using SSH

Central Database: MongoDB Atlas (logs, alerts, vulns collections)

Detection Engine: Port scan detection via behavioral analysis

Enrichment Layer: NVD API integration for CVE matching

Reporting: Alert summaries and vulnerability findings

Refer to POC/diagrams/network_vapt_architecture.png for the full architecture diagram.

📂 Project Structure

network_vapt/
├── config/
│   ├── mongo.py
│   └── mongo_alerts.py
├── ingest/
│   ├── main_ingest.py
│   └── network_parser.py
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

🔄 Workflow Explanation

1️⃣ Log Ingestion

SSH to remote log server

Fetch connections_*.log files

Parse and normalize entries

Insert into logs collection

Each log includes:

Raw log line

log_type: NETWORK

Timestamp (server-side)

2️⃣ Centralized Storage (MongoDB Atlas)

Logs stored in network_vapt.logs

Verified ingestion of 40,000+ entries

Ensures persistence, scalability, and remote SOC-style access

3️⃣ Detection Engine

Scans stored logs for behavioral indicators:

Abnormal port usage

Repeated connections

Triggers PORT_SCAN alerts

Alerts stored in alerts collection

Deduplication via upsert logic

4️⃣ NVD / CVE Enrichment

Maps ports to services

Identifies CPEs

Queries NVD API for CVEs

Stores results in vulns collection

🗄️ Database Collections

Collection

Purpose

logs

Raw network logs

alerts

Detection results

vulns

CVE/NVD matches

All collections verified using MongoDB Atlas Data Explorer.

✅ Verification & Validation

✔ Logs successfully ingested (40,000+ entries)

✔ Logs visible in MongoDB Atlas

✔ Detection engine runs without errors

✔ Alerts generated and deduplicated

✔ Database schema matches detection logic

✔ Environment variables validated

✔ Secure DB connection verified

🧪 Commands to Run the Project (Kali Linux)

1️⃣ Setup Virtual Environment

python3 -m venv venv
source venv/bin/activate

2️⃣ Install Dependencies

pip install -r requirements.txt

3️⃣ Set Environment Variables

export VAPT_DB_USER="your_db_user"
export VAPT_DB_PASSWORD="your_db_password"
export VAPT_DB_HOST="your_cluster_url"
export DB_NAME="network_vapt"
export LOG_SERVER_PASSWORD="your_ssh_password"

4️⃣ Run Log Ingestion

python3 -m ingest.main_ingest

5️⃣ Verify Logs

python3 - <<EOF
from config.mongo import logs_col
print(logs_col.count_documents({}))
print(logs_col.find_one())
EOF

6️⃣ Run Detection

python3 main_detect.py

7️⃣ Check Alerts

python3 config/mongo_alerts.py

8️⃣ Run Enrichment (Optional)

python3 -m enrich.main_enrich

🔍 Manual Verification (MongoDB Atlas)

Login to MongoDB Atlas

Navigate to: cyartcluster → network_vapt → logs

Confirm:

Document count

Raw log visibility

Correct log_type

🚀 Final Status

✅ Log Ingestion: Completed

✅ Centralized Storage: Completed

✅ Detection Engine: Completed

✅ MongoDB Atlas Verification: Completed

✅ NVD Readiness: Completed

📌 Conclusion

This project demonstrates a production-grade Network VAPT pipeline with modular SOC-style architecture. It enables scalable log ingestion, behavioral detection, and vulnerability mapping using open-source tools and cloud infrastructure. The system is ready for continuous monitoring and future threat correlation via NVD.