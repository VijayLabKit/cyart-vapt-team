#!/usr/bin/env python3
"""
nmap_automation.py

Automates Nmap scans (SYN -sS + version detection -sV), parses results,
and generates a human-readable scan_report.txt plus the raw nmap output file.

Designed to run on Kali Linux.

Requirements:
  - nmap installed and in PATH (verify with `nmap -v`)
  - Python 3.8+
  - (optional) python-nmap if you prefer more advanced parsing (not mandatory here)

Usage examples:
  sudo python3 nmap_automation.py 192.168.56.101
  python3 nmap_automation.py example.com --top-ports 200
  sudo python3 nmap_automation.py 10.0.2.15 --udp --output-dir ./results

Notes:
  - SYN scan (-sS) typically requires root privileges on Linux. If you cannot run
    as root, use the --no-syn flag to use TCP connect (-sT) instead.
  - UDP scans are much slower and less reliable; use --udp only when needed.
"""

import argparse
import subprocess
import shutil
import sys
import os
from datetime import datetime
import textwrap

# -------------------------
# Helper functions
# -------------------------
def check_dependencies():
    """Ensure nmap is installed."""
    if shutil.which("nmap") is None:
        print("ERROR: 'nmap' not found in PATH. Install Nmap (apt install nmap) and try again.")
        sys.exit(1)

def run_command(cmd, capture_stdout=True):
    """Run command and return (returncode, stdout, stderr). stdout/stderr are strings."""
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE if capture_stdout else None,
                              stderr=subprocess.PIPE, text=True, check=False)
        return proc.returncode, proc.stdout if proc.stdout is not None else "", proc.stderr if proc.stderr is not None else ""
    except FileNotFoundError:
        return 127, "", f"Command not found: {cmd[0]}"
    except Exception as e:
        return 1, "", str(e)

def parse_nmap_normal_output(nmap_text):
    """
    Parse nmap normal output to extract host(s) and open ports.
    Returns: list of hosts, each host is dict: {'host': ip_or_name, 'state': 'up'/'down', 'ports': [ {port, proto, state, service, extra} ... ]}
    This is a lightweight parser sufficient for common outputs.
    """
    lines = nmap_text.splitlines()
    hosts = []
    cur_host = None
    in_port_section = False

    for i, raw in enumerate(lines):
        line = raw.strip()
        # Host line examples:
        # Nmap scan report for 192.168.56.101
        if line.startswith("Nmap scan report for"):
            if cur_host:
                hosts.append(cur_host)
            host_id = line[len("Nmap scan report for"):].strip()
            cur_host = {"host": host_id, "state": None, "ports": []}
            in_port_section = False
            continue

        # Host status line: Host is up (0.0010s latency).
        if cur_host and line.startswith("Host is"):
            cur_host["state"] = line
            continue

        # Start of ports table
        if cur_host and (line.startswith("PORT") and "STATE" in line and "SERVICE" in line):
            in_port_section = True
            continue

        # Empty line ends port section
        if in_port_section and line == "":
            in_port_section = False
            continue

        # Lines within port section look like:
        # 22/tcp   open  ssh     OpenSSH 7.2 (protocol 2.0)
        # 80/tcp   open  http    Apache httpd 2.4.7 ((Ubuntu))
        if in_port_section and cur_host:
            # split into max 4 parts: port_proto, state, service, rest
            parts = line.split(None, 3)
            if len(parts) >= 3:
                port_proto = parts[0]  # e.g., "22/tcp"
                state = parts[1]       # e.g., "open"
                service = parts[2]     # e.g., "ssh"
                extra = parts[3] if len(parts) == 4 else ""
                # Separate port and proto
                if '/' in port_proto:
                    port, proto = port_proto.split('/', 1)
                else:
                    port, proto = port_proto, "tcp"
                try:
                    portnum = int(port)
                except ValueError:
                    portnum = port
                cur_host["ports"].append({
                    "port": portnum,
                    "proto": proto,
                    "state": state,
                    "service": service,
                    "extra": extra.strip()
                })
            else:
                # Not a standard port line; skip
                pass

    if cur_host:
        hosts.append(cur_host)
    return hosts

def generate_report_text(target, hosts, scan_cmd, raw_output_path, timestamp_utc):
    """Construct human readable report text."""
    lines = []
    lines.append("Scan Report")
    lines.append("=" * 72)
    lines.append(f"Scan timestamp (UTC): {timestamp_utc}")
    lines.append(f"Target provided: {target}")
    lines.append(f"Nmap command used: {scan_cmd}")
    lines.append(f"Raw nmap output saved to: {raw_output_path}")
    lines.append("")
    if not hosts:
        lines.append("No hosts found or scan returned no data.")
    for h in hosts:
        lines.append("-" * 72)
        lines.append(f"Host: {h.get('host')}")
        if h.get('state'):
            lines.append(f"Status: {h.get('state')}")
        lines.append("")
        if not h.get('ports'):
            lines.append("No open TCP ports detected (or port section not present in output).")
        else:
            lines.append(f"{'Port':<7} {'Proto':<6} {'State':<8} {'Service':<15} {'Product/Version (if detected)'}")
            lines.append("-" * 72)
            for p in sorted(h['ports'], key=lambda x: (str(x['port']), x['proto'])):
                lines.append(f"{str(p['port']):<7} {p['proto']:<6} {p['state']:<8} {p['service']:<15} {p['extra']}")
        lines.append("")
    lines.append("=" * 72)
    lines.append("Notes and recommendations:")
    lines.append(" - Review open services and ensure only required services are exposed.")
    lines.append(" - For Telnet (port 23) use SSH instead; Telnet sends credentials in cleartext.")
    lines.append(" - For SMB/NetBIOS (ports 139/445), ensure patches and restrict exposure.")
    lines.append(" - Consider running authenticated vulnerability scans for deeper CVE detection.")
    lines.append("")
    lines.append("Scan completed.")
    return "\n".join(lines)

# -------------------------
# Main program
# -------------------------
def main():
    check_dependencies()

    parser = argparse.ArgumentParser(description="Nmap SYN automation and report generator")
    parser.add_argument("target", help="Target IP or hostname to scan (authorized target only!)")
    parser.add_argument("--no-syn", action="store_true", help="Do not use SYN (-sS). Use TCP connect (-sT) instead (useful if not root).")
    parser.add_argument("--udp", action="store_true", help="Also run a UDP scan (-sU). Warning: slow.")
    parser.add_argument("--top-ports", type=int, default=1000, help="Scan top X ports (default 1000). Use 0 for default nmap behavior (recommended leave default).")
    parser.add_argument("--output-dir", default=".", help="Directory to save reports and raw output (default: current dir)")
    parser.add_argument("--timeout", type=int, default=0, help="Seconds to wait for nmap to finish (0 = no timeout)")

    args = parser.parse_args()

    target = args.target
    outdir = os.path.abspath(args.output_dir)
    os.makedirs(outdir, exist_ok=True)

    timestamp_utc = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%SZ")
    # Decide scan type
    syn_flag = "-sS" if not args.no_syn else "-sT"
    udp_flag = "-sU" if args.udp else None

    # Build nmap command (normal human readable output)
    normal_outfile = os.path.join(outdir, "syn_scan.txt")
    # Build argument list
    nmap_cmd = ["nmap"]
    # add sync or tcp connect
    nmap_cmd.append(syn_flag)
    # include service/version detection
    nmap_cmd.append("-sV")
    # faster timing template
    nmap_cmd.append("-T4")
    # top ports tweak
    if args.top_ports and args.top_ports > 0:
        nmap_cmd.extend(["--top-ports", str(args.top_ports)])
    # UDP optional
    if udp_flag:
        nmap_cmd.append(udp_flag)
    # output normal to file
    nmap_cmd.extend(["-oN", normal_outfile])
    # target
    nmap_cmd.append(target)

    # Inform user
    print("About to run nmap with the following command:")
    print(" ".join(nmap_cmd))
    if syn_flag == "-sS":
        if os.geteuid() != 0:
            print("WARNING: SYN scan (-sS) usually requires root privileges. Consider running with sudo.")
    print("Running nmap... (this may take a while depending on options and network)")

    # Execute nmap and capture stdout/stderr
    ret, out, err = run_command(nmap_cmd, capture_stdout=True)
    if ret != 0:
        print(f"nmap exited with code {ret}. stderr:\n{err}")
        # still attempt to read outfile if present
    else:
        print(f"nmap finished, normal output saved to: {normal_outfile}")

    # Read raw nmap normal output (if exists)
    raw_text = ""
    try:
        with open(normal_outfile, "r", encoding="utf-8", errors="replace") as f:
            raw_text = f.read()
    except FileNotFoundError:
        # fallback: use captured stdout
        raw_text = out or ""
        print("Warning: couldn't find the normal output file; using captured stdout instead.")

    # Parse the normal output
    hosts = parse_nmap_normal_output(raw_text)

    # Build report text and write to scan_report.txt
    scan_cmd_repr = " ".join(nmap_cmd)
    report_text = generate_report_text(target, hosts, scan_cmd_repr, normal_outfile, timestamp_utc)
    report_path = os.path.join(outdir, "scan_report.txt")
    with open(report_path, "w", encoding="utf-8") as rf:
        rf.write(report_text)

    print(f"Human-readable report written to: {report_path}")

    # Also save a short JSON-like summary for quick consumption (optional)
    summary_path = os.path.join(outdir, "scan_summary.txt")
    try:
        with open(summary_path, "w", encoding="utf-8") as sf:
            sf.write(f"Scan Summary for target {target} at {timestamp_utc}\n\n")
            for h in hosts:
                sf.write(f"Host: {h.get('host')}\n")
                for p in h.get("ports", []):
                    sf.write(f" - {p['port']}/{p['proto']}: {p['state']} ({p['service']}) {p.get('extra','')}\n")
                sf.write("\n")
        print(f"Quick summary written to: {summary_path}")
    except Exception as e:
        print(f"Could not write summary file: {e}")

    print("\nDone. Next steps (suggested):")
    print(" - Review the 'scan_report.txt' and 'syn_scan.txt' files.")
    print(" - For vulnerable services, research CVEs using vendor+version and NVD/CVE databases.")
    print(" - Add screenshots of interesting output and attach 'nmap_automation.py' to your final report.")

if __name__ == "__main__":
    main()
