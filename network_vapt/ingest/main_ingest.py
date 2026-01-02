#!/usr/bin/env python3
import paramiko
import os
import sys
from config.mongo import logs_col
from parsers.dns_parser import parse_dns
from parsers.network_parser import parse_network

# Environment variables
HOST = os.getenv("LOG_SERVER_HOST", "100.100.227.30")
USER = os.getenv("LOG_SERVER_USER", "logadmin")
NET_DIR = os.getenv("LOG_SERVER_NET_DIR", "/var/log/central/infra/network")
PASSWORD = os.getenv("LOG_SERVER_PASSWORD")

def fetch_network_logs():
    if not PASSWORD:
        print("[!] LOG_SERVER_PASSWORD not set in environment", file=sys.stderr)
        return []

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        print(f"[+] Connecting to {USER}@{HOST}...")
        ssh.connect(HOST, username=USER, password=PASSWORD, timeout=10)

        # Force bash to expand wildcards
        cmd = f"bash -lc 'cat {NET_DIR}/connections_*.log'"
        print(f"[+] Running remote command: {cmd}")
        _, stdout, stderr = ssh.exec_command(cmd, timeout=30)

        out = stdout.read().decode(errors="ignore")
        err = stderr.read().decode(errors="ignore")

        print(f"[DEBUG] Raw stdout length: {len(out)}")
        if err.strip():
            print(f"[!] Remote error: {err.strip()}", file=sys.stderr)

        return out.splitlines()
    except Exception as e:
        print(f"[!] SSH connection or command error: {e}", file=sys.stderr)
        return []
    finally:
        try:
            ssh.close()
        except Exception:
            pass

def build_docs(lines):
    raw_docs = [{"raw": ln, "log_type": "NETWORK"} for ln in lines if ln.strip()]
    parsed_net = parse_network(lines)
    parsed_dns = parse_dns(lines)
    return raw_docs + parsed_net + parsed_dns

def insert_bulk(docs, chunk=1000):
    inserted = 0
    for i in range(0, len(docs), chunk):
        batch = docs[i:i+chunk]
        if not batch:
            continue
        try:
            res = logs_col.insert_many(batch, ordered=False)
            inserted += len(res.inserted_ids)
        except Exception as e:
            print(f"[!] Mongo insert error: {e}", file=sys.stderr)
    return inserted

if __name__ == "__main__":
    lines = fetch_network_logs()
    if not lines:
        print("[!] No logs fetched from remote server")
        sys.exit(1)

    docs = build_docs(lines)
    count = insert_bulk(docs)
    print(f"[+] Inserted {count} documents into MongoDB logs")
