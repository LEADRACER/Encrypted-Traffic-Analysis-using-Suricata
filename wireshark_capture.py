#!/usr/bin/env python3
"""
Reliable Wireshark Capture Module with Real-time Analysis
Captures HTTPS traffic and provides real-time analysis for dashboard consumption
"""

import subprocess
import os
import sys
import argparse
import time
import json
import threading
from datetime import datetime

# Global flag for clean shutdown
running = True

def signal_handler(sig, frame):
    global running
    print("\n[*] Received shutdown signal, stopping capture...")
    running = False
    sys.exit(0)

def analyze_packet(packet_line):
    """Analyze a packet line from tshark JSON output and extract relevant fields"""
    try:
        packet = json.loads(packet_line)
        
        # Extract basic packet info
        layers = packet.get('_source', {}).get('layers', {})
        
        # Initialize result with basic fields
        result = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "event_type": "unknown",
            "src_ip": None,
            "src_port": None,
            "dest_ip": None,
            "dest_port": None,
            "proto": None
        }
        
        # IP layer
        ip_layer = layers.get('ip') or layers.get('ipv6')
        if ip_layer:
            result["src_ip"] = ip_layer.get('ip.src') or ip_layer.get('ipv6.src')
            result["dest_ip"] = ip_layer.get('ip.dst') or ip_layer.get('ipv6.dst')
        
        # Transport layer
        transport = layers.get('tcp') or layers.get('udp')
        if transport:
            result["src_port"] = transport.get('tcp.srcport') or transport.get('udp.srcport')
            result["dest_port"] = transport.get('tcp.dstport') or transport.get('udp.dstport')
            if layers.get('tcp'):
                result["proto"] = "TCP"
            elif layers.get('udp'):
                result["proto"] = "UDP"
        
        # Try to determine higher layer protocol
        if layers.get('http'):
            result["event_type"] = "http"
            result["proto"] = "TCP"
            # Add HTTP-specific fields
            http = layers['http']
            result["http_hostname"] = http.get('http.host')
            result["http_url"] = http.get('http.request.uri')
            result["http_user_agent"] = http.get('http.user_agent')
            
        elif layers.get('tls'):
            result["event_type"] = "tls"
            result["proto"] = "TCP"
            # Add TLS-specific fields
            tls = layers['tls']
            result["tls_version"] = tls.get('tls.record.version')
            # Note: JA3 extraction would require more complex processing
            
        elif layers.get('dns'):
            result["event_type"] = "dns"
            result["proto"] = "UDP"
            # Add DNS-specific fields
            dns = layers['dns']
            result["dns_qry_name"] = dns.get('dns.qry.name')
            result["dns_qry_type"] = dns.get('dns.qry.type')
            if 'dns.a' in dns:
                result["dns_a"] = dns['dns.a']
            if 'dns.aaaa' in dns:
                result["dns_aaaa"] = dns['dns.aaaa']
                
        # If we have IP info but couldn't classify further, mark as generic IP traffic
        if result["event_type"] == "unknown" and result["src_ip"] and result["dest_ip"]:
            result["event_type"] = "ip"
            
        # Only return if we have useful information
        if result["src_ip"] and result["dest_ip"]:
            return result
            
    except (json.JSONDecodeError, KeyError, TypeError, ValueError) as e:
        # Silently skip malformed packets
        pass
    
    return None

def main():
    global running
    
    # Set up signal handler for clean shutdown
    import signal
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    parser = argparse.ArgumentParser(description="Real-time HTTPS Traffic Capture and Analysis")
    parser.add_argument("--interface", required=True, help="Network interface (e.g. eth0)")
    parser.add_argument("--duration", type=int, default=0, help="Capture duration in seconds (0 for infinite)")
    parser.add_argument("--realtime", action="store_true", help="Run in continuous real-time mode")
    parser.add_argument("--output", "-o", default="project_output/wireshark_logs/realtime.json", 
                       help="Output file for JSON analysis results")
    parser.add_argument("--buffer-time", type=int, default=2, 
                       help="Flush buffer every N seconds")
    args = parser.parse_args()
    
    # Create output directory
    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    
    # Determine capture mode
    if args.realtime or args.duration == 0:
        duration_arg = ""  # Infinite capture
        mode = "REAL-TIME"
    else:
        duration_arg = f"duration:{args.duration}"
        mode = f"FIXED DURATION ({args.duration}s)"
    
    print(f"\n[*] TRACK Phase: Capturing HTTPS traffic on {args.interface} [{mode}]...")
    print(f"[*] Output: {args.output}")
    print(f"[*] Press Ctrl+C to stop\n")
    
    # Build tshark command for JSON output
    cmd = [
        "sudo", "tshark",
        "-i", args.interface,
        "-a", duration_arg if duration_arg else None,
        "-f", "tcp port 443",
        "-T", "json",
        "-l"  # Line-buffered output
    ]
    
    # Remove None values
    cmd = [x for x in cmd if x is not None]
    
    try:
        # Start tshark process
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            bufsize=1
        )
        
        # Open output file for writing
        with open(args.output, 'w') as outfile:
            # Write header comment
            outfile.write("# Wireshark Real-time Analysis Output\n")
            outfile.write("# Format: JSON lines\n")
            outfile.write("# Started: " + datetime.utcnow().isoformat() + "\n\n")
            
            last_flush = time.time()
            
            # Process output line by line
            for line in process.stdout:
                if not running:
                    break
                    
                line = line.strip()
                if not line:
                    continue
                    
                try:
                    # Each line is a JSON array containing one packet object
                    packet_data = json.loads(line)
                    if isinstance(packet_data, list) and len(packet_data) > 0:
                        packet = packet_data[0]
                        # Re-wrap in _source format if needed
                        if '_source' not in packet:
                            packet = {'_source': packet}
                        # Analyze the packet
                        analysis_result = analyze_packet(json.dumps(packet))
                        if analysis_result:
                            # Write as JSON line
                            outfile.write(json.dumps(analysis_result) + '\n')
                            
                            # Flush periodically
                            if time.time() - last_flush > args.buffer_time:
                                outfile.flush()
                                last_flush = time.time()
                                
                except json.JSONDecodeError:
                    # Skip malformed JSON lines
                    continue
                except Exception as e:
                    # Log error but continue
                    print(f"[!] Warning: Error processing packet: {e}", file=sys.stderr)
                    continue
            
            # Final flush
            outfile.flush()
        
        # Wait for process to complete
        stdout, stderr = process.communicate()
        
        if process.returncode != 0 and running:
            print(f"[!] tshark exited with code {process.returncode}")
            if stderr:
                print(f"[!] tshark stderr: {stderr[:200]}...")
        
    except subprocess.TimeoutExpired:
        print("[!] FATAL: Wireshark capture timed out process execution.")
        running = False
        sys.exit(1)
    except Exception as e:
        print(f"[!] FATAL: Wireshark capture failed: {e}")
        running = False
        sys.exit(1)
    finally:
        running = False
        print("\n[*] Capture stopped.")

if __name__ == "__main__":
    main()