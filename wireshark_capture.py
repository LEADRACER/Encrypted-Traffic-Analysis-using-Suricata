"""
Wireshark Capture Module
Captures HTTPS traffic using tshark
"""

import subprocess
import os
import sys

print("\n=== WIRESHARK CAPTURE MODULE ===")

interface = input("Enter interface (e.g. wlan0 / eth0): ").strip()
duration = input("Enter capture duration (seconds): ").strip()

if not duration.isdigit():
    print("[!] Duration must be a number")
    sys.exit(1)

OUTDIR = "project_output/captures"
os.makedirs(OUTDIR, exist_ok=True)

pcap_file = f"{OUTDIR}/wireshark_capture.pcap"

print(f"\n[*] Capturing HTTPS traffic on {interface} for {duration} seconds...")

cmd = [
    "sudo", "tshark",
    "-i", interface,
    "-a", f"duration:{duration}",
    "-f", "tcp port 443",
    "-w", pcap_file
]

try:
    subprocess.run(cmd, check=True)
    print(f"[✓] Capture saved at {pcap_file}")
except subprocess.CalledProcessError:
    print("[!] Wireshark capture failed")
    sys.exit(1)

