"""
Suricata IDS Module
Captures TLS metadata from live traffic
"""

import subprocess
import os
import time
import sys

print("\n=== SURICATA IDS MODULE ===")

interface = input("Enter interface (e.g. eth0 / wlan0 / usb0): ").strip()
runtime = input("Enter Suricata run time (seconds): ").strip()

if not runtime.isdigit():
    print("[!] Runtime must be numeric")
    sys.exit(1)

OUTDIR = "project_output/suricata_logs"
os.makedirs(OUTDIR, exist_ok=True)

print("\n[*] Starting Suricata IDS...")
print("[!] IMPORTANT: Generate HTTPS traffic NOW (open browser or run curl)")
print("[!] Examples: https://google.com, https://github.com\n")

cmd = [
    "sudo", "suricata",
    "-i", interface,
    "-l", OUTDIR
]

proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

time.sleep(int(runtime))

proc.terminate()
proc.wait()

eve_file = f"{OUTDIR}/eve.json"

if os.path.exists(eve_file) and os.path.getsize(eve_file) > 0:
    print(f"[✓] Suricata log generated: {eve_file}")
else:
    print("[!] Suricata ran, but no traffic was captured")
    print("[!] Ensure HTTPS traffic during runtime")
    sys.exit(0)


