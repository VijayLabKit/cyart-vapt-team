#!/usr/bin/env python3
from pymongo import MongoClient
import os
from dotenv import load_dotenv

load_dotenv()

# Load credentials from environment
DB_NAME = os.getenv("DB_NAME", "network_vapt")
DB_USER = os.getenv("DB_USER", "network_vapt_user")
DB_HOST = os.getenv("DB_HOST", "cyartcluster.wuwqq50.mongodb.net")
DB_PASSWORD = os.getenv("VAPT_DB_PASSWORD")

if not DB_PASSWORD:
    raise RuntimeError("VAPT_DB_PASSWORD not set")

# Connect to MongoDB Atlas
uri = (
    f"mongodb+srv://{DB_USER}:{DB_PASSWORD}"
    f"@{DB_HOST}/{DB_NAME}"
    "?retryWrites=true&w=majority&authSource=admin"
)

client = MongoClient(uri, serverSelectionTimeoutMS=8000)
db = client[DB_NAME]
alerts_col = db["alerts"]

# Query alerts
alerts = list(alerts_col.find().sort("source_ip"))

if not alerts:
    print("[+] No alerts found in the database")
else:
    print(f"[+] Found {len(alerts)} alerts:")
    for alert in alerts:
        print(f" - {alert['type']} from {alert['source_ip']} on ports {alert['ports']}")
