#!/usr/bin/env python3
"""
Enhanced HTTP server that automatically starts Wireshark capture and Suricata
for real-time dashboard monitoring with full pipeline control capabilities
"""
import http.server
import socketserver
import os
import sys
import subprocess
import threading
import time
import signal
import argparse
from pathlib import Path

# Global variables to track subprocesses
wireshark_process = None
suricata_process = None

def signal_handler(sig, frame):
    """Handle shutdown signals to cleanly terminate subprocesses"""
    print("\n[*] Shutting down server and stopping capture processes...")
    
    # Stop Wireshark process
    global wireshark_process, suricata_process
    if wireshark_process:
        print("[*] Stopping Wireshark capture...")
        wireshark_process.terminate()
        try:
            wireshark_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            wireshark_process.kill()
    
    # Stop Suricata process
    if suricata_process:
        print("[*] Stopping Suricata...")
        suricata_process.terminate()
        try:
            suricata_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            suricata_process.kill()
    
    print("[*] All processes stopped.")
    sys.exit(0)

def start_wireshark_capture():
    """Start Wireshark capture in real-time mode"""
    global wireshark_process
    try:
        # Get the project root directory (parent of dashboard)
        project_dir = Path(__file__).parent.parent
        interface = "eth0"  # Default interface
        
        # Ensure output directory exists
        wireshark_log_dir = project_dir / "project_output" / "wireshark_logs"
        wireshark_log_dir.mkdir(parents=True, exist_ok=True)
        
        cmd = [
            "sudo", "tshark",
            "-i", interface,
            "-a", "duration:0",  # Infinite capture
            "-f", "tcp port 443",
            "-T", "json",
            "-l"  # Line-buffered output
        ]
        
        print(f"[*] Starting Wireshark capture on {interface}...")
        wireshark_process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            bufsize=1,
            cwd=str(project_dir)
        )
        
        # Start a thread to process and save the output
        def process_wireshark_output():
            output_file = wireshark_log_dir / "realtime.json"
            # Write header
            with open(output_file, 'w') as f:
                f.write("# Wireshark Real-time Analysis Output\n")
                f.write("# Format: JSON lines\n")
                f.write("# Started: " + time.strftime("%Y-%m-%d %H:%M:%S") + "\n\n")
            
            # Process output
            with open(output_file, 'a') as f:
                for line in wireshark_process.stdout:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        # Each line is a JSON array containing one packet object
                        # We'll need to parse this and extract relevant info
                        import json
                        packet_data = json.loads(line)
                        if isinstance(packet_data, list) and len(packet_data) > 0:
                            packet = packet_data[0]
                            # Re-wrap in _source format if needed for consistency
                            if '_source' not in packet:
                                packet = {'_source': packet}
                            # Write as JSON line
                            f.write(json.dumps(packet) + '\n')
                            f.flush()
                    except Exception as e:
                        # Skip malformed lines
                        pass
        
        # Start processing thread
        wireshark_thread = threading.Thread(target=process_wireshark_output, daemon=True)
        wireshark_thread.start()
        
        return True
    except Exception as e:
        print(f"[!] Failed to start Wireshark capture: {e}")
        return False

def start_suricata():
    """Start Suricata in real-time mode"""
    global suricata_process
    try:
        # Get the project root directory (parent of dashboard)
        project_dir = Path(__file__).parent.parent
        interface = "eth0"  # Default interface
        
        # Ensure output directory exists
        suricata_log_dir = project_dir / "project_output" / "suricata_logs"
        suricata_log_dir.mkdir(parents=True, exist_ok=True)
        
        # Ensure rules directory exists
        rules_dir = project_dir / "suricata" / "rules"
        rules_dir.mkdir(parents=True, exist_ok=True)
        
        # Create a simple rules file if it doesn't exist
        rule_file = rules_dir / "custom.rules"
        if not rule_file.exists():
            with open(rule_file, "w") as f:
                f.write('alert tls any any -> any any (msg:"Suspicious JA3 TLS specific client"; ja3.hash; content:"e7d705a3286e19ea42f587b344ee6865"; sid:1000001; rev:4;)\n')
        
        cmd = [
            "sudo", "suricata",
            "-i", interface,
            "-l", str(suricata_log_dir),
            "-S", str(rule_file)
        ]
        
        print(f"[*] Starting Suricata on {interface}...")
        suricata_process = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd=str(project_dir)
        )
        
        return True
    except Exception as e:
        print(f"[!] Failed to start Suricata: {e}")
        return False

class MyHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        # Add CORS headers to allow fetch requests
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.end_headers()
        
    def do_GET(self):
        # Handle API requests
        if self.path.startswith('/api/'):
            self.serve_api_file()
        else:
            # Serve static files normally
            super().do_GET()
            
    def serve_api_file(self):
        """Serve files from the project directory via API endpoints"""
        # Remove /api prefix
        path = self.path[4:]  # Remove '/api/'
        
        # Map API paths to actual file paths
        if path == 'suricata/eve.json':
            file_path = Path(__file__).parent.parent / 'project_output' / 'suricata_logs' / 'eve.json'
        elif path == 'wireshark/realtime.json':
            file_path = Path(__file__).parent.parent / 'project_output' / 'wireshark_logs' / 'realtime.json'
        elif path == 'analysis/summary.json':
            file_path = Path(__file__).parent.parent / 'project_output' / 'analysis' / 'summary.json'
        elif path == 'start-pipeline':
            self.handle_start_pipeline()
            return
        elif path == 'stop-pipeline':
            self.handle_stop_pipeline()
            return
        else:
            self.send_error(404, "File not found")
            return
            
        # Check if file exists
        if not file_path.exists():
            self.send_error(404, "File not found")
            return
            
        # Serve the file
        try:
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            with open(file_path, 'rb') as f:
                self.wfile.write(f.read())
        except Exception as e:
            self.send_error(500, f"Error reading file: {e}")

    def handle_start_pipeline(self):
        """Handle start pipeline API request"""
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length == 0:
            self.send_error(400, "No data provided")
            return
            
        try:
            import json
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data.decode('utf-8'))
            
            # Start pipeline components in background threads
            interface = data.get('interface', 'eth0')
            duration = data.get('duration', 60)
            realtime = data.get('realtime', False)
            ips = data.get('ips', False)
            block = data.get('block', False)
            analyze = data.get('analyze', False)
            capture = data.get('capture', False)
            all_flag = data.get('all', False)
            
            # Start components based on flags
            if all_flag or capture or realtime:
                threading.Thread(
                    target=self.run_capture_component,
                    args=(interface, duration, realtime, 300, 5),
                    daemon=True
                ).start()
                
            if all_flag or ips or realtime:
                threading.Thread(
                    target=self.run_suricata_component,
                    args=(interface, duration, realtime, ips),
                    daemon=True
                ).start()
                
            if all_flag or analyze or realtime:
                threading.Thread(
                    target=self.run_analysis_component,
                    args=(block, 5),
                    daemon=True
                ).start()
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            response = {"success": True, "message": "Pipeline started"}
            self.wfile.write(json.dumps(response).encode('utf-8'))
        except Exception as e:
            self.send_error(500, f"Error starting pipeline: {e}")

    def handle_stop_pipeline(self):
        """Handle stop pipeline API request"""
        try:
            # In a real implementation, we would track and stop the threads
            # For now, we'll just return success
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            import json
            response = {"success": True, "message": "Pipeline stop requested"}
            self.wfile.write(json.dumps(response).encode('utf-8'))
        except Exception as e:
            self.send_error(500, f"Error stopping pipeline: {e}")

    def run_capture_component(self, interface, duration, realtime, rotate_interval, max_files):
        """Run Wireshark capture component"""
        try:
            cmd = ["python3", str(Path(__file__).parent.parent / "wireshark_capture.py"), 
                   "--interface", interface]
            if realtime or duration == 0:
                cmd.extend(["--realtime"])
            else:
                cmd.extend(["--duration", str(duration)])
            cmd.extend(["--rotate-interval", str(rotate_interval), "--max-files", str(max_files)])
            
            subprocess.run(cmd)
        except Exception as e:
            print(f"[!] Capture component error: {e}")

    def run_suricata_component(self, interface, duration, realtime, ips):
        """Run Suricata component"""
        try:
            cmd = ["python3", str(Path(__file__).parent.parent / "suricata_run.py"),
                   "--interface", interface]
            if realtime or duration == 0:
                cmd.extend(["--realtime"])
            else:
                cmd.extend(["--duration", str(duration)])
            if ips:
                cmd.append("--ips")
            
            subprocess.run(cmd)
        except Exception as e:
            print(f"[!] Suricata component error: {e}")

    def run_analysis_component(self, block, interval):
        """Run analysis component"""
        try:
            cmd = ["python3", str(Path(__file__).parent.parent / "analysis.py"),
                   "--interval", str(interval)]
            if block:
                cmd.append("--block")
            
            subprocess.run(cmd)
        except Exception as e:
            print(f"[!] Analysis component error: {e}")

def run_capture(interface, duration=0, realtime=False, rotate_interval=300, max_files=5):
    """Run Wireshark capture"""
    cmd = ["python3", str(Path(__file__).parent.parent / "wireshark_capture.py"), 
           "--interface", interface]
    if realtime or duration == 0:
        cmd.extend(["--realtime"])
    else:
        cmd.extend(["--duration", str(duration)])
    cmd.extend(["--rotate-interval", str(rotate_interval), "--max-files", str(max_files)])
    
    try:
        subprocess.run(cmd)
    except Exception as e:
        print(f"[!] Capture error: {e}")

def run_suricata(interface, duration=0, realtime=False, ips=False):
    """Run Suricata"""
    cmd = ["python3", str(Path(__file__).parent.parent / "suricata_run.py"),
           "--interface", interface]
    if realtime or duration == 0:
        cmd.extend(["--realtime"])
    else:
        cmd.extend(["--duration", str(duration)])
    if ips:
        cmd.append("--ips")
    
    try:
        subprocess.run(cmd)
    except Exception as e:
        print(f"[!] Suricata error: {e}")

def run_analysis(block=False, interval=5):
    """Run analysis module"""
    cmd = ["python3", str(Path(__file__).parent.parent / "analysis.py"),
           "--interval", str(interval)]
    if block:
        cmd.append("--block")
    
    try:
        subprocess.run(cmd)
    except Exception as e:
        print(f"[!] Analysis error: {e}")

def start_pipeline_components(args):
    """Start pipeline components based on arguments"""
    threads = []
    
    # Start Wireshark capture if requested
    if getattr(args, 'capture', False) or getattr(args, 'all', False) or getattr(args, 'realtime', False):
        print("[*] Starting Wireshark capture...")
        capture_thread = threading.Thread(
            target=run_capture,
            args=(args.interface, args.duration, args.realtime, args.rotate_interval, args.max_files),
            daemon=True
        )
        capture_thread.start()
        threads.append(capture_thread)
        time.sleep(1)
    
    # Start Suricata if requested
    if getattr(args, 'suricata', False) or getattr(args, 'all', False) or getattr(args, 'realtime', False):
        print("[*] Starting Suricata...")
        suricata_thread = threading.Thread(
            target=run_suricata,
            args=(args.interface, args.duration, args.realtime, args.ips),
            daemon=True
        )
        suricata_thread.start()
        threads.append(suricata_thread)
        time.sleep(1)
    
    # Start analysis if requested
    if getattr(args, 'analyze', False) or getattr(args, 'all', False) or getattr(args, 'realtime', False):
        print("[*] Starting analysis module...")
        analysis_thread = threading.Thread(
            target=run_analysis,
            args=(args.block, args.analyze_interval),
            daemon=True
        )
        analysis_thread.start()
        threads.append(analysis_thread)
    
    return threads

if __name__ == "__main__":
    # Set up signal handlers for clean shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Change to dashboard directory
    os.chdir(Path(__file__).parent)
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Encrypted Traffic Analysis Dashboard with Pipeline Control")
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
    
    args = parser.parse_args()
    
    PORT = 8080
    
    print("[*] Starting Encrypted Traffic Analysis Dashboard Server...")
    print("[*] Initializing real-time data sources...")
    
    # Start pipeline components if requested
    pipeline_threads = []
    if any([args.capture, args.suricata, args.analyze, args.all, args.realtime]):
        print("[*] Starting pipeline components...")
        pipeline_threads = start_pipeline_components(args)
        time.sleep(3)  # Give components time to start
    
    # Start Wireshark capture for dashboard (always start for live data)
    print("[*] Starting Wireshark capture for dashboard...")
    wireshark_started = start_wireshark_capture()
    time.sleep(3)  # Give Wireshark time to start
    
    # Start Suricata for dashboard (always start for live data)
    print("[*] Starting Suricata for dashboard...")
    suricata_started = start_suricata()
    time.sleep(3)  # Give Suricata time to start
    
    if wireshark_started and suricata_started:
        print("[*] Both data sources started successfully")
    elif wireshark_started:
        print("[!] Warning: Only Wireshark started successfully")
    elif suricata_started:
        print("[!] Warning: Only Suricata started successfully")
    else:
        print("[!] Error: Failed to start both data sources")
        print("[*] Dashboard will still run but may not show live data")
    
    try:
        with socketserver.TCPServer(("", PORT), MyHTTPRequestHandler) as httpd:
            print(f"[*] Serving dashboard at http://localhost:{PORT}")
            print("[*] Press Ctrl+C to stop server and all processes")
            httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Keyboard interrupt received...")
        signal_handler(None, None)
    except Exception as e:
        print(f"[!] Server error: {e}")
        signal_handler(None, None)