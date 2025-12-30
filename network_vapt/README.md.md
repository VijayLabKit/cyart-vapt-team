Network VAPT – Log Ingestion, Detection & Vulnerability Mapping

Author: Ishan Chowdhury
Position: VAPT Intern
Organization: CyArt
Platform: Kali Linux
Database: MongoDB Atlas

📌 Project Overview

This project implements a Network-based Vulnerability Assessment & Penetration Testing (VAPT) pipeline designed to collect raw network logs, normalize and store them centrally, analyze them for suspicious behavior, and prepare the data for vulnerability correlation using the NVD (National Vulnerability Database).

The system follows a SOC-style architecture, separating ingestion, detection, and vulnerability enrichment into clear, auditable stages.

🎯 Objectives

Collect raw network logs from Linux systems

Normalize and store logs securely in MongoDB Atlas

Perform behavioral detection on stored logs

Prepare detection results for CVE/NVD correlation

Provide centralized visibility for security analysis

🏗️ Architecture Overview

The architecture consists of the following major components:

Log Source (Linux Network Logs)

Ingestion Engine (Python on Kali Linux)

Central Database (MongoDB Atlas)

Detection Engine

NVD / CVE Matching Layer

Alert & Vulnerability Reporting

📎 Refer to the architecture diagram included in this repository for a visual overview.

📂 Project Structure
network_vapt/
├── config/
│   └── mongo.py
├── ingest/
│   ├── network_parser.py
│   └── dns_parser.py
├── detect/
│   └── detector.py
├── main_ingest.py
├── main_detect.py
├── requirements.txt
├── README.md

🔄 Workflow Explanation
1️⃣ Log Ingestion

Network logs are collected from Linux systems (e.g. ss, netstat, connection logs)

Logs are ingested as raw entries

Each log entry includes:

raw log line

log_type (NETWORK)

Timestamp (server-side)

The ingestion process ensures no data loss and preserves original logs for forensic analysis.

2️⃣ Centralized Storage (MongoDB Atlas)

All logs are stored in the network_vapt.logs collection

Database is cloud-hosted using MongoDB Atlas

Verified ingestion of ~10,000 log entries

This ensures:

Persistence

Scalability

Remote access for SOC-style monitoring

3️⃣ Detection Engine

Detection is performed on stored logs, not live streams

The engine scans logs for behavioral indicators such as:

Repeated connections

Abnormal port usage

Suspicious network patterns

Detection results are:

Correlated internally

Designed to avoid duplicate alerts

Stored separately from raw logs

4️⃣ NVD / CVE Readiness

The project includes an NVD matcher design

Logs and detections are structured to support:

Port-to-service mapping

CPE identification

CVE lookups via NVD API

ℹ️ NVD integration is verified at the structural level and ready for live API correlation.

🗄️ Database Collections
Collection	Purpose
logs	Raw network logs
alerts	Detection results
vulns	CVE/NVD matches

All collections were verified manually using MongoDB Atlas Data Explorer.

✅ Verification & Validation

The following checks were completed successfully:

✔ Logs successfully ingested (9968+ entries)

✔ Logs visible in MongoDB Atlas

✔ Detection engine runs without errors

✔ No false vulnerabilities generated

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

4️⃣ Run Log Ingestion
python3 main_ingest.py

5️⃣ Verify Logs
python3 - <<EOF
from config.mongo import logs_col
print(logs_col.count_documents({}))
print(logs_col.find_one())
EOF

6️⃣ Run Detection
python3 main_detect.py

🔍 Manual Verification (MongoDB Atlas)

Login to MongoDB Atlas

Navigate to:

cyartcluster → network_vapt → logs


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

This project demonstrates a production-style Network VAPT pipeline with real-world SOC design principles.
It provides a strong foundation for behavioral detection, vulnerability assessment, and future threat correlation using NVD.