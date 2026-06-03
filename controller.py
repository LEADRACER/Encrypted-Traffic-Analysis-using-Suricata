"""
Enhanced Controller Module with Security and Process Management
Implements secure NFQUEUE setup, API authentication, and robust process orchestration
"""

import subprocess
import sys
import argparse
import time
import threading
import os
import signal
import json
import hashlib
import secrets
from pathlib import Path

# Configuration
API_CONFIG_PATH = Path("config/api_keys.json")
PROCESS_STATE_PATH = Path("project_output/process_state.json")

class ProcessSupervisor:
    """Centralized process management with health checks and graceful shutdown"""
    
    def __init__(self):
        self.processes = {}
        self.lock = threading.Lock()
        
    def register_process(self, name, process):
        """Register a process for tracking"""
        with self.lock:
            self.processes[name] = {
                'process': process,
                'start_time': time.time(),
                'status': 'running'
            }
        self.save_state()
    
    def stop_process(self, name):
        """Stop a registered process gracefully"""
        with self.lock:
            if name in self.processes:
                proc_info = self.processes[name]
                proc = proc_info['process']
                if proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                proc_info['status'] = 'stopped'
                self.save_state()
    
    def stop_all(self):
        """Stop all registered processes"""
        with self.lock:
            for name in list(self.processes.keys()):
                self.stop_process(name)
    
    def save_state(self):
        """Save process state to file"""
        try:
            os.makedirs(os.path.dirname(PROCESS_STATE_PATH), exist_ok=True)
            state = {
                'processes': {
                    k: {'status': v['status'], 'start_time': v['start_time']}
                    for k, v in self.processes.items()
                },
                'timestamp': time.time()
            }
            with open(PROCESS_STATE_PATH, 'w') as f:
                json.dump(state, f, indent=2)
        except Exception as e:
            print(f"[!] Warning: Could not save process state: {e}")

# Global supervisor instance
supervisor = ProcessSupervisor()

def generate_api_key():
    """Generate a secure random API key"""
    return secrets.token_urlsafe(32)

def load_or_generate_api_keys():
    """Load existing API keys or generate new ones"""
    if API_CONFIG_PATH.exists():
        with open(API_CONFIG_PATH, 'r') as f:
            return json.load(f)
    
    # Generate keys
    keys = {
        'dashboard_key': generate_api_key(),
        'analysis_key': generate_api_key()
    }
    os.makedirs(os.path.dirname(API_CONFIG_PATH), exist_ok=True)
    with open(API_CONFIG_PATH, 'w') as f:
        json.dump(keys, f, indent=2)
    os.chmod(API_CONFIG_PATH, 0o600)
    print(f"[+] Generated new API keys in {API_CONFIG_PATH}")
    return keys

def validate_api_key(provided_key, required_key='dashboard_key'):
    """Validate API key against stored keys"""
    keys = load_or_generate_api_keys()
    return secrets.compare_digest(provided_key, keys.get(required_key, ''))

def setup_secure_nfq(queue_num=0):
    """Setup NFQUEUE with specific queue number and validation"""
    print(f"[*] PREVENT Phase: Setting up iptables NFQUEUE (queue {queue_num})...")
    
    try:
        # Check if rule already exists
        check_cmd = ["sudo", "iptables", "-C", "INPUT", "-j", "NFQUEUE", "--queue-num", str(queue_num)]
        exists = subprocess.run(check_cmd, stderr=subprocess.DEVNULL).returncode == 0
        
        if not exists:
            subprocess.run([
                "sudo", "iptables", "-I", "INPUT", "-j", "NFQUEUE", "--queue-num", str(queue_num)
            ], check=True, stderr=subprocess.DEVNULL)
            subprocess.run([
                "sudo", "iptables", "-I", "OUTPUT", "-j", "NFQUEUE", "--queue-num", str(queue_num)
            ], check=True, stderr=subprocess.DEVNULL)
            print(f"[✓] NFQUEUE rules added (queue {queue_num})")
        else:
            print(f"[*] NFQUEUE rules already exist (queue {queue_num})")
            
        return True
    except subprocess.CalledProcessError as e:
        print(f"[!] FATAL: Failed to configure NFQUEUE: {e}")
        print("[!] Ensure you have sudo permissions and iptables is available")
        return False

def cleanup_nfq(queue_num=0):
    """Clean up NFQUEUE rules with specific queue numbers"""
    print("\n[*] SAFETY CLEANUP: Removing NFQUEUE iptables rules...")
    
    try:
        subprocess.run([
            "sudo", "iptables", "-D", "INPUT", "-j", "NFQUEUE", "--queue-num", str(queue_num)
        ], check=False, stderr=subprocess.DEVNULL)
        subprocess.run([
            "sudo", "iptables", "-D", "OUTPUT", "-j", "NFQUEUE", "--queue-num", str(queue_num)
        ], check=False, stderr=subprocess.DEVNULL)
        print("[✓] Host networking safely restored.")
    except Exception as e:
        print(f"[!] Warning during cleanup: {e}")

def main():
    parser = argparse.ArgumentParser(description="Enhanced Traffic Analysis Controller")
    parser.add_argument("--interface", type=str, default="eth0", help="Network interface")
    parser.add_argument("--duration", type=int, default=60, help="Capture/Suricata duration (seconds)")
    parser.add_argument("--realtime", action="store_true", help="Run in continuous real-time mode")
    parser.add_argument("--rotate-interval", type=int, default=300, help="Capture file rotation interval (seconds)")
    parser.add_argument("--max-files", type=int, default=5, help="Max capture files to keep")
    parser.add_argument("--ips", action="store_true", help="Enable IPS mode for Suricata")
    parser.add_argument("--block", action="store_true", help="Enable dynamic IP blocking")
    parser.add_argument("--analyze-interval", type=int, default=5, help="Analysis polling interval (seconds)")
    parser.add_argument("--capture", action="store_true", help="Run Wireshark capture")
    parser.add_argument("--suricata", action="store_true", help="Run Suricata engine")
    parser.add_argument("--analyze", action="store_true", help="Run ML Analysis")
    parser.add_argument("--all", action="store_true", help="Run full Track, Prevent, Block pipeline")
    parser.add_argument("--api-key", type=str, help="API key for dashboard authentication")
    
    args = parser.parse_args()
    
    # Load API keys for reference
    load_or_generate_api_keys()
    
    print("\n===== ENHANCED TRAFFIC ANALYSIS CONTROLLER =====")
    print(f"[*] Interface: {args.interface}")
    print(f"[*] Mode: {'Real-time' if args.realtime else 'Fixed duration'}")
    
    if args.realtime:
        run_realtime_pipeline(args)
    else:
        run_fixed_pipeline(args)

def run_fixed_pipeline(args):
    """Run fixed-duration capture ??? suricata ??? analysis pipeline"""
    print("\n[*] Phase 1: Wireshark Capture...")
    run_capture(args.interface, args.duration, args.rotate_interval, args.max_files)
    
    print("\n[*] Phase 2: Suricata Analysis...")
    run_suricata(args.interface, args.duration, args.ips)
    
    print("\n[*] Phase 3: ML Analysis & Response...")
    run_analysis(args.block, args.analyze_interval)
    
    print("\n[???] Pipeline completed successfully")

def run_realtime_pipeline(args):
    """Run continuous real-time pipeline with process management"""
    print("\n[*] Starting REAL-TIME pipeline with process supervision...")
    print("[*] Press Ctrl+C to stop\n")
    
    threads = []
    
    def capture_thread():
        cmd = ["python3", "wireshark_capture.py", "--interface", args.interface, "--realtime",
               "--rotate-interval", str(args.rotate_interval), "--max-files", str(args.max_files)]
        try:
            proc = subprocess.Popen(cmd, cwd="/root/Builds/Encrypted-Traffic-Analysis-using-Suricata")
            supervisor.register_process('wireshark', proc)
            proc.wait()
        except Exception as e:
            print(f"[!] Capture thread error: {e}")
    
    def suricata_thread():
        cmd = ["python3", "suricata_run.py", "--interface", args.interface, "--duration", "0",
               "--realtime"]
        if args.ips:
            cmd.append("--ips")
        try:
            proc = subprocess.Popen(cmd, cwd="/root/Builds/Encrypted-Traffic-Analysis-using-Suricata")
            supervisor.register_process('suricata', proc)
            proc.wait()
        except Exception as e:
            print(f"[!] Suricata thread error: {e}")
    
    def analysis_thread():
        cmd = ["python3", "analysis.py", "--interval", str(args.analyze_interval)]
        if args.block:
            cmd.append("--block")
        try:
            proc = subprocess.Popen(cmd, cwd="/root/Builds/Encrypted-Traffic-Analysis-using-Suricata")
            supervisor.register_process('analysis', proc)
            proc.wait()
        except Exception as e:
            print(f"[!] Analysis thread error: {e}")
    
    # Start threads based on flags
    if args.all or args.capture or args.realtime:
        t = threading.Thread(target=capture_thread, daemon=True)
        t.start()
        threads.append(t)
        time.sleep(1)
        
    if args.all or args.suricata or args.realtime:
        t = threading.Thread(target=suricata_thread, daemon=True)
        t.start()
        threads.append(t)
        time.sleep(1)
        
    if args.all or args.analyze or args.realtime:
        t = threading.Thread(target=analysis_thread, daemon=True)
        t.start()
        threads.append(t)
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Stopping real-time pipeline...")
        supervisor.stop_all()

def run_capture(interface, duration, rotate_interval=300, max_files=5):
    cmd = ["python3", "wireshark_capture.py", "--interface", interface, "--duration", str(duration)]
    cmd.extend(["--rotate-interval", str(rotate_interval), "--max-files", str(max_files)])
    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        print(f"[!] Capture failed: {e}")
        sys.exit(1)

def run_suricata(interface, duration, ips=False):
    cmd = ["python3", "suricata_run.py", "--interface", interface, "--duration", str(duration)]
    if ips:
        cmd.append("--ips")
    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        print(f"[!] Suricata failed: {e}")
        sys.exit(1)

def run_analysis(block=False, interval=5):
    cmd = ["python3", "analysis.py", "--interval", str(interval)]
    if block:
        cmd.append("--block")
    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        print(f"[!] Analysis failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
