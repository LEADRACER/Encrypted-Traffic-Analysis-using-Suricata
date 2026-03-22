"""
Reliable Wireshark Capture Module
Captures HTTPS traffic strictly enforcing process timeouts and graceful exits.
"""

import subprocess
import os
import sys
import argparse

def main():
    parser = argparse.ArgumentParser(description="Reliable HTTPS Traffic Capture")
    parser.add_argument("--interface", required=True, help="Network interface (e.g. eth0)")
    parser.add_argument("--duration", required=True, type=int, help="Capture duration in seconds")
    args = parser.parse_args()

    OUTDIR = "project_output/captures"
    os.makedirs(OUTDIR, exist_ok=True)

    pcap_file = f"{OUTDIR}/wireshark_capture.pcap"
    print(f"\n[*] TRACK Phase: Capturing HTTPS traffic on {args.interface} for {args.duration} s...")

    cmd = [
        "sudo", "tshark",
        "-i", args.interface,
        "-a", f"duration:{args.duration}",
        "-f", "tcp port 443",
        "-w", pcap_file
    ]

    try:
        # Give tshark a grace buffer to flush to disk before killing the process
        subprocess.run(cmd, check=True, timeout=args.duration + 5, stderr=subprocess.DEVNULL)
        if os.path.exists(pcap_file) and os.path.getsize(pcap_file) > 100:
            print(f"[✓] Capture safely committed to {pcap_file}")
        else:
            print("[!] Warning: Capture completed but generating minimal or no traffic data.")
    except subprocess.TimeoutExpired:
        print("[!] FATAL: Wireshark capture timed out process execution.")
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print(f"[!] FATAL: Wireshark capture failed. Exit code {e.returncode} (Check sudo/permissions)")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[!] User aborted capture manually.")
        sys.exit(1)

if __name__ == "__main__":
    main()
