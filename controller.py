"""
Master Controller Script
Controls Track, Prevent, Block project workflow with pre-flight safety checks
"""

import argparse
import subprocess
import sys
import shutil

def check_dependencies():
    missing = []
    for tool in ["tshark", "suricata", "iptables", "python3"]:
        if not shutil.which(tool):
            missing.append(tool)
    if missing:
        print(f"[!] FATAL Error: Missing required system dependencies: {', '.join(missing)}")
        print("[!] Please install them (e.g., `sudo apt install suricata tshark`) before running the controller.")
        sys.exit(1)

def run(cmd):
    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        print(f"[!] Error running module: {' '.join(cmd)}")
        print(f"[!] Exit Code: {e.returncode}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[!] Execution interrupted by user.")
        sys.exit(1)

def main():
    check_dependencies()
    
    parser = argparse.ArgumentParser(description="Reliable Track, Prevent, Block Traffic Controller")
    parser.add_argument("--capture", action="store_true", help="Run Wireshark capture (Track)")
    parser.add_argument("--interface", type=str, default="eth0", help="Network interface")
    parser.add_argument("--duration", type=int, default=30, help="Capture/Suricata duration (seconds)")
    
    parser.add_argument("--suricata", action="store_true", help="Run Suricata engine")
    parser.add_argument("--ips", action="store_true", help="Run Suricata directly in Inline IPS Mode (Prevent)")
    
    parser.add_argument("--analyze", action="store_true", help="Run ML Analysis (Track)")
    # FIX: --block was parsed but silently ignored when using --analyze without --all
    parser.add_argument("--block", action="store_true", help="Dynamically isolate anomalous IPs via Firewall (Block)")
    
    parser.add_argument("--all", action="store_true", help="Run full Track, Prevent, Block pipeline")

    args = parser.parse_args()

    if not (args.all or args.capture or args.suricata or args.analyze):
        parser.print_help()
        sys.exit(0)

    print("\n===== ADVANCED PROJECT CONTROLLER =====")

    if args.all or args.capture:
        run([sys.executable, "wireshark_capture.py", "--interface", args.interface, "--duration", str(args.duration)])
    
    if args.all or args.suricata:
        cmd = [sys.executable, "suricata_run.py", "--interface", args.interface, "--duration", str(args.duration)]
        # FIX: was (args.ips or args.all) — now correctly passes --ips for both --ips and --all flags
        if args.ips or args.all:
            print("[*] Enabling PREVENT functionality (IPS)...")
            cmd.append("--ips")
        run(cmd)
    
    if args.all or args.analyze:
        cmd = [sys.executable, "analysis.py"]
        # FIX: --block now correctly passed when using --analyze --block, not only with --all
        if args.block or args.all:
            print("[*] Enabling BLOCK functionality (Firewall ML response)...")
            cmd.append("--block")
        run(cmd)
        
    print("\n[✓] Reliable operations completed successfully.")

if __name__ == "__main__":
    main()
