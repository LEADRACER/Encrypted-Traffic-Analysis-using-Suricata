
Suricata IDS/IPS Module
Captures live traffic with absolute fallback signal handling for NFQUEUE safety.
"""

import subprocess
import os
import sys
import argparse
import signal
import atexit

# Global flag to track if NFQ is active, allowing bullet-proof cleanup
nfq_active = False

def setup_nfq():
    global nfq_active
    print("[*] PREVENT Phase: Setting up iptables NFQUEUE for Suricata IPS mode...")
    try:
        subprocess.run(["sudo", "iptables", "-I", "INPUT", "-j", "NFQUEUE"], check=True, stderr=subprocess.DEVNULL)
        subprocess.run(["sudo", "iptables", "-I", "OUTPUT", "-j", "NFQUEUE"], check=True, stderr=subprocess.DEVNULL)
        nfq_active = True
    except subprocess.CalledProcessError:
        print("[!] FATAL: Failed to configure NFQUEUE. Ensure you have sudo permissions.")
        sys.exit(1)

def cleanup_nfq():
    """Runs unequivocally on exit avoiding frozen outbound traffic on the host"""
    global nfq_active
    if nfq_active:
        print("\n[*] SAFETY CLEANUP: Aggressively stripping NFQUEUE iptables rules...")
        try:
            subprocess.run(["sudo", "iptables", "-D", "INPUT", "-j", "NFQUEUE"], check=False, stderr=subprocess.DEVNULL)
            subprocess.run(["sudo", "iptables", "-D", "OUTPUT", "-j", "NFQUEUE"], check=False, stderr=subprocess.DEVNULL)
            nfq_active = False
            print("[✓] Host networking safely restored.")
        except Exception as e:
            print(f"[!] Warning during cleanup: {e}")

def signal_handler(signum, frame):
    print(f"\n[!] Caught Signal {signum}. Triggering graceful shutdown...")
    sys.exit(0)  # Triggers atexit safely

# Bind safety nets
atexit.register(cleanup_nfq)
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

def main():
    parser = argparse.ArgumentParser(description="Reliable Suricata IDS/IPS")
    parser.add_argument("--interface", required=True, help="Network interface")
    parser.add_argument("--duration", type=int, required=True, help="Duration in seconds")
    parser.add_argument("--ips", action="store_true", help="Run in Intrusion Prevention System (Inline) mode")
    args = parser.parse_args()

    OUTDIR = "project_output/suricata_logs"
    os.makedirs(OUTDIR, exist_ok=True)
    
    RULES_DIR = "suricata/rules"
    os.makedirs(RULES_DIR, exist_ok=True)
    
    rule_file = f"{RULES_DIR}/custom.rules"
    action = "drop" if args.ips else "alert"
    
    with open(rule_file, "w") as f:
        f.write(f'{action} tls any any -> any any (msg:"Suspicious JA3 TLS specific client"; ja3.hash; content:"e7d705a3286e19ea42f587b344ee6865"; sid:1000001; rev:4;)\n')

    mode_name = "IPS (Prevention)" if args.ips else "IDS (Detection)"
    print(f"\n[*] Starting Suricata in {mode_name} Mode on {args.interface}...")

    if args.ips:
        setup_nfq()
        cmd = ["sudo", "suricata", "-S", rule_file, "-l", OUTDIR, "-q", "0"]
    else:
        cmd = ["sudo", "suricata", "-i", args.interface, "-l", OUTDIR, "-S", rule_file]

    # FIX: proc initialized to None before Popen so KeyboardInterrupt handler
    # doesn't crash with NameError if Popen itself fails before proc is assigned
    proc = None
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            proc.wait(timeout=args.duration)
        except subprocess.TimeoutExpired:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
    except KeyboardInterrupt:
        print("\n[!] User aborted execution manually.")
        if proc is not None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        sys.exit(1)

    eve_file = f"{OUTDIR}/eve.json"
    if os.path.exists(eve_file) and os.path.getsize(eve_file) > 0:
        print(f"[✓] Suricata logs cleanly generated at: {eve_file}")
    else:
        print("[!] Suricata ran safely, but no pertinent traffic was captured.")
        sys.exit(0)

if __name__ == "__main__":
    main()
