"""
Suricata IDS/IPS Module - Real-Time Support
Captures live traffic with absolute fallback signal handling for NFQUEUE safety.
"""

import subprocess
import os
import sys
import argparse
import signal
import atexit
import time
import threading
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

nfq_active = False
suricata_proc = None

# Alert configuration
ALERT_EMAIL_ENABLED = False  # Set to True to enable email alerts
ALERT_EMAIL_FROM = "alerts@yourdomain.com"
ALERT_EMAIL_TO = "admin@yourdomain.com"
ALERT_SMTP_SERVER = "localhost"
ALERT_SMTP_PORT = 587
ALERT_USERNAME = ""
ALERT_PASSWORD = ""

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
    global nfq_active, suricata_proc
    if suricata_proc and suricata_proc.poll() is None:
        print("[*] Stopping Suricata process...")
        suricata_proc.terminate()
        try:
            suricata_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            suricata_proc.kill()
    if nfq_active:
        print("\n[*] SAFETY CLEANUP: Aggressively stripping NFQUEUE iptables rules...")
        try:
            subprocess.run(["sudo", "iptables", "-D", "INPUT", "-j", "NFQUEUE"], check=False, stderr=subprocess.DEVNULL)
            subprocess.run(["sudo", "iptables", "-D", "OUTPUT", "-j", "NFQUEUE"], check=False, stderr=subprocess.DEVNULL)
            nfq_active = False
            print("[✓] Host networking safely restored.")
        except Exception as e:
            print(f"[!] Warning during cleanup: {e}")

def send_alert(subject, message):
    """Send email alert"""
    if not ALERT_EMAIL_ENABLED:
        return
    
    try:
        msg = MIMEMultipart()
        msg['From'] = ALERT_EMAIL_FROM
        msg['To'] = ALERT_EMAIL_TO
        msg['Subject'] = subject
        
        msg.attach(MIMEText(message, 'plain'))
        
        server = smtplib.SMTP(ALERT_SMTP_SERVER, ALERT_SMTP_PORT)
        server.starttls()
        if ALERT_USERNAME and ALERT_PASSWORD:
            server.login(ALERT_USERNAME, ALERT_PASSWORD)
        text = msg.as_string()
        server.sendmail(ALERT_EMAIL_FROM, ALERT_EMAIL_TO, text)
        server.quit()
        print(f"[+] Alert sent: {subject}")
    except Exception as e:
        print(f"[!] Failed to send alert: {e}")

def signal_handler(signum, frame):
    print(f"\n[!] Caught Signal {signum}. Triggering graceful shutdown...")
    cleanup_nfq()
    sys.exit(0)

atexit.register(cleanup_nfq)
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

def main():
    global suricata_proc
    parser = argparse.ArgumentParser(description="Real-Time Suricata IDS/IPS")
    parser.add_argument("--interface", required=True, help="Network interface")
    parser.add_argument("--duration", type=int, default=None, help="Duration in seconds (omit for real-time)")
    parser.add_argument("--ips", action="store_true", help="Run in Intrusion Prevention System (Inline) mode")
    parser.add_argument("--realtime", action="store_true", help="Run in continuous real-time mode")
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
    if args.realtime or args.duration is None:
        print(f"\n[*] Starting Suricata in REAL-TIME {mode_name} Mode on {args.interface}...")
    else:
        print(f"\n[*] Starting Suricata in {mode_name} Mode on {args.interface}...")

    if args.ips:
        setup_nfq()
        cmd = ["sudo", "suricata", "-S", rule_file, "-l", OUTDIR, "-q", "0"]
    else:
        cmd = ["sudo", "suricata", "-i", args.interface, "-l", OUTDIR, "-S", rule_file]

    if args.realtime or args.duration is None:
        try:
            suricata_proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print("[*] Suricata running in real-time mode. Press Ctrl+C to stop.")
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[*] Stopping Suricata...")
            cleanup_nfq()
    else:
        try:
            suricata_proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                suricata_proc.wait(timeout=args.duration)
            except subprocess.TimeoutExpired:
                suricata_proc.terminate()
                try:
                    suricata_proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    suricata_proc.kill()
        except KeyboardInterrupt:
            print("\n[!] User aborted execution manually.")
            if suricata_proc:
                suricata_proc.terminate()
                try:
                    suricata_proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    suricata_proc.kill()
            cleanup_nfq()
            sys.exit(1)
        
        eve_file = f"{OUTDIR}/eve.json"
        if os.path.exists(eve_file) and os.path.getsize(eve_file) > 0:
            print(f"[✓] Suricata logs cleanly generated at: {eve_file}")
            check_for_alerts(eve_file)
        else:
            print("[!] Suricata ran safely, but no pertinent traffic was captured.")

def check_for_alerts(eve_file):
    """Check Suricata logs for alert events and trigger notifications"""
    try:
        alert_count = 0
        with open(eve_file, 'r') as f:
            for line in f:
                if '"event_type":"alert"' in line:
                    alert_count += 1
                    # Try to extract alert details
                    try:
                        import json
                        data = json.loads(line)
                        alert = data.get('alert', {})
                        signature = alert.get('signature', 'Unknown Signature')
                        severity = alert.get('severity', 'Unknown')
                        src_ip = data.get('src_ip', 'Unknown')
                        dest_ip = data.get('dest_ip', 'Unknown')
                        
                        alert_msg = f"Suricata Alert: {signature} from {src_ip} to {dest_ip} (Severity: {severity})"
                        print(f"[!] {alert_msg}")
                        
                        # Send email alert for high severity alerts
                        if severity in [1, 2, 3]:  # High severity
                            send_alert(
                                f"High Severity Suricata Alert: {signature}",
                                f"Time: {datetime.now().isoformat()}\n"
                                f"Signature: {signature}\n"
                                f"Source IP: {src_ip}\n"
                                f"Destination IP: {dest_ip}\n"
                                f"Severity: {severity}\n"
                                f"Full event: {line[:200]}..."
                            )
                    except:
                        pass  # Skip if we can't parse the JSON
        
        if alert_count > 0:
            print(f"[*] Total alerts detected: {alert_count}")
        else:
            print("[*] No alerts detected in Suricata logs")
            
    except Exception as e:
        print(f"[!] Error checking for alerts: {e}")

if __name__ == "__main__":
    main()
