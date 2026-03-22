"""
Wireshark Capture Module
Captures HTTPS traffic using tshark
"""

import subprocess
import os
import sys
import argparse

def main():
    parser = argparse.ArgumentParser(description="Capture HTTPS traffic")
    parser.add_argument("--interface", required=True, help="Network interface (e.g. eth0)")
    parser.add_argument("--duration", required=True, help="Capture duration in seconds")
    args = parser.parse_args()

    OUTDIR = "project_output/captures"
    os.makedirs(OUTDIR, exist_ok=True)

    pcap_file = f"{OUTDIR}/wireshark_capture.pcap"

    print(f"\n[*] Capturing HTTPS traffic on {args.interface} for {args.duration} seconds...")

    cmd = [
        "sudo", "tshark",
        "-i", args.interface,
        "-a", f"duration:{args.duration}",
        "-f", "tcp port 443",
        "-w", pcap_file
    ]

    try:
        subprocess.run(cmd, check=True)
        print(f"[✓] Capture saved at {pcap_file}")
    except subprocess.CalledProcessError:
        print("[!] Wireshark capture failed")
        sys.exit(1)

if __name__ == "__main__":
    main()
