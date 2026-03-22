"""
Master Controller Script
Controls Track, Prevent, Block project workflow
"""

import argparse
import subprocess
import sys

def run(cmd):
    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError:
        print(f"[!] Error running command: {' '.join(cmd)}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Track, Prevent, Block Encrypted Traffic Controller")
    parser.add_argument("--capture", action="store_true", help="Run Wireshark capture (Track)")
    parser.add_argument("--interface", type=str, default="eth0", help="Network interface")
    parser.add_argument("--duration", type=int, default=30, help="Capture/Suricata duration (seconds)")
    
    parser.add_argument("--suricata", action="store_true", help="Run Suricata engine")
    parser.add_argument("--ips", action="store_true", help="Run Suricata directly in Inline IPS Mode (Prevent)")
    
    parser.add_argument("--analyze", action="store_true", help="Run ML Analysis (Track)")
    parser.add_argument("--block", action="store_true", help="Dynamically isolate anomalous IPs via Firewall (Block)")
    
    parser.add_argument("--all", action="store_true", help="Run full Track, Prevent, Block pipeline")

    args = parser.parse_args()

    if not (args.all or args.capture or args.suricata or args.analyze):
        parser.print_help()
        sys.exit(0)

    print("\n===== ADVANCED PROJECT CONTROLLER =====")

    if args.all or args.capture:
        # Phase 1: Track & Capture
        run([sys.executable, "wireshark_capture.py", "--interface", args.interface, "--duration", str(args.duration)])
    
    if args.all or args.suricata:
        # Phase 2: Prevent (via --ips flag + Rules)
        cmd = [sys.executable, "suricata_run.py", "--interface", args.interface, "--duration", str(args.duration)]
        if args.ips or args.all:
            print("[*] Enabling PREVENT functionality (IPS)...")
            cmd.append("--ips")
        run(cmd)
    
    if args.all or args.analyze:
        # Phase 3: Track Context & Block Actively
        cmd = [sys.executable, "analysis.py"]
        if args.block or args.all:
            print("[*] Enabling BLOCK functionality (Firewall ML response)...")
            cmd.append("--block")
        run(cmd)
        
    print("\n[✓] Selected operations completed successfully.")

if __name__ == "__main__":
    main()
