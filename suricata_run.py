"""
Suricata IDS/IPS Module
Captures TLS metadata from live traffic and supports Inline NFQ Blocking (IPS Mode)
"""

import subprocess
import os
import time
import sys
import argparse

def setup_nfq():
    print("[*] PREVENT Phase: Setting up iptables NFQUEUE for Suricata IPS mode...")
    # Map all traffic to NFQUEUE so Suricata can decide to pass or drop
    subprocess.run(["sudo", "iptables", "-I", "INPUT", "-j", "NFQUEUE"], check=True)
    subprocess.run(["sudo", "iptables", "-I", "OUTPUT", "-j", "NFQUEUE"], check=True)

def cleanup_nfq():
    print("[*] Cleaning up iptables NFQUEUE...")
    # Clean up exact rules created
    try:
        subprocess.run(["sudo", "iptables", "-D", "INPUT", "-j", "NFQUEUE"], check=True, stderr=subprocess.DEVNULL)
        subprocess.run(["sudo", "iptables", "-D", "OUTPUT", "-j", "NFQUEUE"], check=True, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        pass

def main():
    parser = argparse.ArgumentParser(description="Run Suricata IDS/IPS")
    parser.add_argument("--interface", required=True, help="Network interface")
    parser.add_argument("--duration", type=int, required=True, help="Duration in seconds")
    parser.add_argument("--ips", action="store_true", help="Run in Intrusion Prevention System (Inline) mode")
    args = parser.parse_args()

    OUTDIR = "project_output/suricata_logs"
    os.makedirs(OUTDIR, exist_ok=True)
    
    RULES_DIR = "suricata/rules"
    os.makedirs(RULES_DIR, exist_ok=True)
    
    # Generate Drop or Alert rules
    rule_file = f"{RULES_DIR}/custom.rules"
    action = "drop" if args.ips else "alert"
    
    with open(rule_file, "w") as f:
        # Prevent logic: if it matches this suspicious JA3, immediately Drop the packet.
        f.write(f'{action} tls any any -> any any (msg:"Suspicious JA3 TLS specific client"; ja3.hash; content:"e7d705a3286e19ea42f587b344ee6865"; sid:1000001; rev:3;)\n')
        # We can add more specific drop rules here

    mode_name = "IPS (Prevention)" if args.ips else "IDS (Detection)"
    print(f"\n[*] Starting Suricata in {mode_name} Mode...")

    if args.ips:
        setup_nfq()
        # NFQ inline mode
        cmd = [
            "sudo", "suricata",
            "-S", rule_file,
            "-l", OUTDIR,
            "-q", "0"  # Queue number 0
        ]
    else:
        # Standard sniffing mode
        cmd = [
            "sudo", "suricata",
            "-i", args.interface,
            "-l", OUTDIR,
            "-S", rule_file
        ]

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(args.duration)
        proc.terminate()
        proc.wait()
    finally:
        if args.ips:
            cleanup_nfq()

    eve_file = f"{OUTDIR}/eve.json"

    if os.path.exists(eve_file) and os.path.getsize(eve_file) > 0:
        print(f"[✓] Suricata logs cleanly generated at: {eve_file}")
    else:
        print("[!] Suricata ran, but no traffic was captured")
        sys.exit(0)

if __name__ == "__main__":
    main()
