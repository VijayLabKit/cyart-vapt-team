from pymongo import MongoClient
from dotenv import load_dotenv
import os

load_dotenv()

DB_NAME = "network_vapt"
DB_USER = "network_vapt_user"
DB_HOST = "cyartcluster.wuwqq50.mongodb.net"

password = os.getenv("VAPT_DB_PASSWORD")
if not password:
    raise RuntimeError("VAPT_DB_PASSWORD not set")

uri = (
    f"mongodb+srv://{DB_USER}:{password}"
    f"@{DB_HOST}/{DB_NAME}"
    "?retryWrites=true&w=majority&authSource=admin"
)

client = MongoClient(uri)
db = client[DB_NAME]

logs_col = db["logs"]
alerts_col = db["alerts"]
vulns_col = db["vulnerabilities"]
