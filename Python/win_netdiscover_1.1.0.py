"""
Network Discovery Utility
Author: Jason
Version: 1.1.0
Status: Functional / Tested

PURPOSE
-------
This script performs lightweight Windows-based subnet discovery by:

1. Sending ICMP echo requests (ping) across a specified subnet
2. Forcing population of the local ARP cache
3. Parsing the ARP table to identify live Layer-2 hosts
4. Performing reverse DNS lookups for hostname resolution
5. Filtering multicast, broadcast, and invalid MAC entries
6. Exporting results to structured CSV and formatted TXT reports

The tool is designed for:
- Home lab environments
- Active Directory / Windows DNS validation
- Infrastructure verification
- Lightweight management network auditing

This script is intended for controlled internal environments only.
It is not a replacement for enterprise scanners such as Nmap.

CHANGE LOG
----------
v1.1.0
- Added CSV export capability
- Added formatted TXT report generation
- Implemented timestamped output filenames
- Refactored output logic to store results before print
- Improved report header formatting
- Runtime tested on Windows 10 / Windows 11

v1.0.1
- Fixed import typo: ThreadPoolExecuter → ThreadPoolExecutor
- Corrected naming mismatch in threading logic
- Redacted internal subnet prior to publication
- Script runtime tested and verified functional

v1.0.0
- Initial script creation (not runtime tested)
"""

import socket
import subprocess
import ipaddress
import platform
import csv
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor


# -----------------------------
# CONFIG
# -----------------------------
SUBNET = "10.10.10.0/24"
OUTPUT_CSV = f"dns_scan_{datetime.now().strftime('%Y-%m-%d_%H-%M')}.csv"
OUTPUT_TXT = f"dns_scan_{datetime.now().strftime('%Y-%m-%d_%H-%M')}.txt"


# -----------------------------
# FUNCTIONS
# -----------------------------
def resolve_hostname(ip):
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except Exception:
        return "UnKnown"


def ping(ip):
    system = platform.system().lower()

    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", "500", str(ip)]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", str(ip)]

    try:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass


def is_valid_host(ip, mac):
    try:
        ip_obj = ipaddress.ip_address(ip)

        if ip_obj.is_multicast:
            return False

        if ip == "255.255.255.255" or ip.endswith(".255"):
            return False

        if mac.lower() in ["ff-ff-ff-ff-ff-ff", "ff:ff:ff:ff:ff:ff"]:
            return False

        return True

    except ValueError:
        return False


def get_arp_entries():
    output = subprocess.check_output(["arp", "-a"]).decode(errors="ignore")
    hosts = []

    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 2 and "." in parts[0]:
            ip, mac = parts[0], parts[1]

            if is_valid_host(ip, mac):
                hostname = resolve_hostname(ip)
                hosts.append((hostname, ip, mac))

    return hosts


# -----------------------------
# DISCOVERY
# -----------------------------
def discover(subnet):
    net = ipaddress.ip_network(subnet, strict=False)

    print(f"[*] Scanning {subnet} ...")

    with ThreadPoolExecutor(max_workers=100) as executor:
        for ip in net.hosts():
            executor.submit(ping, ip)

    results = get_arp_entries()

    return results


# -----------------------------
# OUTPUT FUNCTIONS
# -----------------------------
def write_csv(results):
    with open(OUTPUT_CSV, mode="w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["Hostname", "IP Address", "MAC Address"])
        writer.writerows(results)

    print(f"[+] CSV report saved: {OUTPUT_CSV}")


def write_txt(results):
    with open(OUTPUT_TXT, "w") as file:
        file.write("Windows DNS / ARP Scan Report\n")
        file.write(f"Subnet: {SUBNET}\n")
        file.write(f"Generated: {datetime.now()}\n")
        file.write("-" * 60 + "\n\n")

        file.write(f"{'Hostname':25} {'IP Address':15} MAC Address\n")
        file.write("-" * 60 + "\n")

        for hostname, ip, mac in results:
            file.write(f"{hostname:25} {ip:15} {mac}\n")

    print(f"[+] TXT report saved: {OUTPUT_TXT}")


# -----------------------------
# MAIN
# -----------------------------
if __name__ == "__main__":
    results = discover(SUBNET)

    print("\n[*] Live Hosts Discovered:\n")
    for hostname, ip, mac in results:
        print(f"{hostname:25} {ip:15} -> {mac}")

    write_csv(results)
    write_txt(results)
