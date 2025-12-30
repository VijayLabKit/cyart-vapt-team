import paramiko
import os
from config.mongo import logs_col

HOST = "100.100.227.30"
USER = "logadmin"
NET_DIR = "/var/log/central/infra/network"

def fetch_network_logs():
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(
        HOST,
        username=USER,
        password=os.getenv("LOG_SERVER_PASSWORD")
    )

    cmd = f"cat {NET_DIR}/connections_*.log"
    _, stdout, _ = ssh.exec_command(cmd)
    lines = stdout.read().decode().splitlines()
    ssh.close()
    return lines

lines = fetch_network_logs()

docs = []
for line in lines:
    if line.strip():
        docs.append({
            "raw": line,
            "log_type": "NETWORK"
        })

if docs:
    logs_col.insert_many(docs)

print(f"[+] Inserted {len(docs)} raw network logs into MongoDB")

