"""
Reliable Advanced Offline Analysis Module
Aggressively parses Suricata logs discarding corrupt JSON safely.
Runs ML Anomaly Detection and ACTIVELY BLOCKS anomalous IPs with Try/Catch barriers.
"""

import json
import pandas as pd
import os
import sys
import argparse
import subprocess
import traceback
import time
import ipaddress

CDN_SUBNETS = [
    "1.1.1.1/32", "1.0.0.1/32", "8.8.8.8/32", "8.8.4.4/32",
    "104.16.0.0/12", "172.64.0.0/13", "131.0.72.0/22",
    "8.34.208.0/20", "8.35.200.0/21", "34.0.0.0/10"
]

def is_safelisted(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_private or ip.is_loopback:
            return True
        for subnet in CDN_SUBNETS:
            if ip in ipaddress.ip_network(subnet):
                return True
        return False
    except ValueError:
        return True

def parse_eve(eve_file):
    tls_records = []
    flow_records = []
    
    with open(eve_file, 'r') as f:
        for line_num, line in enumerate(f, 1):
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                event_type = data.get("event_type")
                
                if event_type == "tls":
                    tls = data.get("tls", {})
                    tls_records.append({
                        "timestamp": data.get("timestamp"),
                        "src_ip": data.get("src_ip"),
                        "dest_ip": data.get("dest_ip"),
                        "tls_version": tls.get("version", "Unknown"),
                        "sni": tls.get("sni", "Missing"),
                        "ja3": tls.get("ja3", {}).get("hash", "N/A"),
                        "ja3s": tls.get("ja3s", {}).get("hash", "N/A")
                    })
                
                elif event_type == "flow":
                    flow = data.get("flow", {})
                    flow_records.append({
                        "timestamp": data.get("timestamp"),
                        "src_ip": data.get("src_ip"),
                        "dest_ip": data.get("dest_ip"),
                        "dest_port": data.get("dest_port", 0),
                        "bytes_toclient": flow.get("bytes_toclient", 0),
                        "bytes_toserver": flow.get("bytes_toserver", 0),
                        "pkts_toclient": flow.get("pkts_toclient", 0),
                        "pkts_toserver": flow.get("pkts_toserver", 0),
                        "age": flow.get("age", 0)
                    })
                    
            except json.JSONDecodeError:
                continue
            except Exception:
                continue
                
    return pd.DataFrame(tls_records), pd.DataFrame(flow_records)

def detect_anomalies(flow_df, tls_df=None, contamination=0.1):
    if flow_df.empty:
        return flow_df
        
    try:
        from sklearn.ensemble import IsolationForest
    except ImportError:
        print("[!] Sklearn not installed. Cannot run ML Anomaly Detection.")
        flow_df['anomaly'] = 1  
        flow_df['anomaly_score'] = 0.0
        return flow_df

    if 'timestamp' in flow_df.columns:
        flow_df = flow_df.copy()
        flow_df['ts_parsed'] = pd.to_datetime(flow_df['timestamp'], errors='coerce')
        flow_df = flow_df.sort_values(by=['src_ip', 'dest_ip', 'ts_parsed'])
        flow_df['time_diff'] = flow_df.groupby(['src_ip', 'dest_ip'])['ts_parsed'].diff().dt.total_seconds().fillna(0)
        flow_df['inter_arrival_variance'] = flow_df.groupby(['src_ip', 'dest_ip'])['time_diff'].transform(lambda x: x.rolling(window=3, min_periods=1).var().fillna(0))
        flow_df['bytes_per_sec'] = (flow_df['bytes_toclient'] + flow_df['bytes_toserver']) / (flow_df['age'] + 0.001)
        flow_df['avg_packet_size'] = (flow_df['bytes_toclient'] + flow_df['bytes_toserver']) / (flow_df['pkts_toclient'] + flow_df['pkts_toserver'] + 0.001)

    if tls_df is not None and not tls_df.empty and 'ja3' in tls_df.columns:
        ja3_counts = tls_df.groupby('src_ip')['ja3'].nunique().reset_index()
        ja3_counts.rename(columns={'ja3': 'unique_ja3_count'}, inplace=True)
        flow_df = flow_df.merge(ja3_counts, on='src_ip', how='left')
        flow_df['unique_ja3_count'] = flow_df['unique_ja3_count'].fillna(1)
        
        tls_versions = tls_df.groupby('src_ip')['tls_version'].apply(lambda x: 1 if any(v in ['TLSv1.0', 'TLSv1.1', 'SSLv3', 'Unknown'] for v in x) else 0).reset_index()
        tls_versions.rename(columns={'tls_version': 'weak_tls'}, inplace=True)
        flow_df = flow_df.merge(tls_versions, on='src_ip', how='left')
        flow_df['weak_tls'] = flow_df['weak_tls'].fillna(0)
    else:
        flow_df['unique_ja3_count'] = 1
        flow_df['weak_tls'] = 0

    features = ['bytes_toclient', 'bytes_toserver', 'pkts_toclient', 'pkts_toserver', 'age', 'inter_arrival_variance', 'bytes_per_sec', 'avg_packet_size', 'unique_ja3_count', 'weak_tls']
    
    for f in features:
        if f not in flow_df.columns:
            flow_df[f] = 0

    X = flow_df[features].fillna(0)
    for col in X.columns:
        X[col] = pd.to_numeric(X[col], errors='coerce').fillna(0)
    
    if len(X) < 5:
        flow_df['anomaly'] = 1  
        flow_df['anomaly_score'] = 0.0
        return flow_df
        
    try:
        clf = IsolationForest(contamination=contamination, random_state=42)
        flow_df['anomaly'] = clf.fit_predict(X)
        flow_df['anomaly_score'] = clf.decision_function(X)
        
        # Explicit Hard-blocks for advanced evasion that bypasses normal volume thresholding
        flow_df.loc[flow_df['weak_tls'] == 1, 'anomaly'] = -1
        flow_df.loc[flow_df['unique_ja3_count'] >= 5, 'anomaly'] = -1
    except Exception as e:
        print(f"[!] ML Generation failed: {e}")
        flow_df['anomaly'] = 1
        flow_df['anomaly_score'] = 0.0
        
    return flow_df

def apply_firewall_blocks(flow_df):
    if 'anomaly' not in flow_df.columns:
        return

    anomalies = flow_df[flow_df['anomaly'] == -1]
    if anomalies.empty:
        print("[*] No anomalies identified for blocking.")
        return

    print("\n[*] ACTIVE RESPONSE: Analyzing IP addresses for blocking...")
    ips_to_block = set()
    for _, row in anomalies.iterrows():
        src = row.get('src_ip')
        dst = row.get('dest_ip')
        if pd.notna(src) and not is_safelisted(str(src)) and str(src) not in ['None', 'NaN']:
            ips_to_block.add(src)
        if pd.notna(dst) and not is_safelisted(str(dst)) and str(dst) not in ['None', 'NaN']:
            ips_to_block.add(dst)
            
    for ip in ips_to_block:
        print(f"[!] BLOCKING ANOMALOUS IP: {ip}")
        try:
            subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True, stderr=subprocess.DEVNULL)
            subprocess.run(["sudo", "iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"], check=True, stderr=subprocess.DEVNULL)
            print(f"  [✓] Successfully added firewall DROP rule for {ip}")
        except subprocess.CalledProcessError:
            print(f"  [x] Failed to apply block for {ip} (verify sudo permissions)")
            
    print(f"[*] Processed strict firewall blocks for {len(ips_to_block)} unique anomalous IP addresses.")

def generate_report(tls_df, flow_df, outdir):
    try:
        import plotly.express as px
        import plotly.io as pio
        
        if not tls_df.empty and 'tls_version' in tls_df.columns:
            tls_fig = px.pie(tls_df, names='tls_version', title='TLS Version Distribution')
            tls_html = pio.to_html(tls_fig, full_html=False)
            
            ja3_counts = tls_df['ja3'].value_counts().reset_index()
            ja3_counts.columns = ['ja3', 'count']
            ja3_fig = px.bar(ja3_counts.head(10), x='ja3', y='count', title='Top 10 JA3 Fingerprints')
            ja3_html = pio.to_html(ja3_fig, full_html=False)
        else:
            tls_html = "<p>No parsable TLS records found.</p>"
            ja3_html = ""
        
        # FIX: Use 'anomaly' column directly instead of flow_df.get() which is a dict method, not DataFrame method
        has_anomaly_col = not flow_df.empty and 'anomaly' in flow_df.columns
        
        if has_anomaly_col:
            anomalies = flow_df[flow_df['anomaly'] == -1].copy()
            if not anomalies.empty:
                display_cols = [c for c in ['timestamp', 'src_ip', 'dest_ip', 'dest_port', 'bytes_toclient', 'bytes_toserver', 'anomaly_score'] if c in anomalies.columns]
                anomalies_html = anomalies[display_cols].to_html(classes="table", index=False)
            else:
                anomalies_html = "<p>No anomalies detected (all traffic appears normal).</p>"
                
            scatter_fig = px.scatter(flow_df, x='bytes_toserver', y='bytes_toclient', 
                                    color=flow_df['anomaly'].astype(str),
                                    title='Flow Bytes: Server vs Client (Anomaly=-1 is active block)')
            scatter_html = pio.to_html(scatter_fig, full_html=False)
        else:
            anomalies_html = "<p>No usable flow records for ML modeling detected.</p>"
            scatter_html = ""
        
        # FIX: Use has_anomaly_col guard instead of flow_df.get('anomaly', 1) which crashes on DataFrame
        num_blocked = len(flow_df[flow_df['anomaly'] == -1]) if has_anomaly_col else 0
        
        html_content = f"""
        <html>
        <head>
            <title>Advanced Encrypted Traffic Analysis Report</title>
            <style>
                body {{ font-family: 'Segoe UI', Tahoma, Arial, sans-serif; margin: 40px; background-color: #f0f2f5; color: #333; }}
                h1 {{ color: #1a252f; text-align: center; margin-bottom: 40px; }}
                h2 {{ color: #e74c3c; border-bottom: 2px solid #e74c3c; padding-bottom: 10px; margin-top: 30px; }}
                h2.blue {{ color: #2c3e50; border-bottom: 2px solid #3498db; }}
                .container {{ background: white; padding: 30px; border-radius: 10px; margin-bottom: 40px; }}
                table {{ width: 100%; border-collapse: collapse; margin-top: 20px; font-size: 14px; }}
                th, td {{ border: 1px solid #e0e0e0; padding: 12px; text-align: left; }}
                th {{ background-color: #2c3e50; color: white; }}
                tr:nth-child(even) {{ background-color: #f8f9fa; }}
                .summary-stats {{ display: flex; justify-content: space-around; background: #2c3e50; color: white; padding: 20px; border-radius: 10px; margin-bottom: 30px; }}
                .stat-box {{ text-align: center; }}
                .stat-box h3 {{ color: #ecf0f1; margin: 0; font-size: 16px; font-weight: normal; }}
                .stat-box p {{ font-size: 32px; font-weight: bold; margin: 10px 0 0 0; color: #e74c3c; }}
            </style>
        </head>
        <body>
            <h1>TRACK, PREVENT, BLOCK: Active Report</h1>
            
            <div class="summary-stats">
                <div class="stat-box">
                    <h3>Total TLS Connections</h3>
                    <p style="color: #3498db;">{len(tls_df)}</p>
                </div>
                <div class="stat-box">
                    <h3>Total Flows Analyzed</h3>
                    <p style="color: #3498db;">{len(flow_df)}</p>
                </div>
                <div class="stat-box">
                    <h3>Anomalies Blocked Firewall-side</h3>
                    <p>{num_blocked}</p>
                </div>
            </div>
            
            <div class="container">
                <h2 class="blue">TLS Details & JA3 Fingerprinting (Track)</h2>
                {tls_html}
                <br>
                {ja3_html}
            </div>
            
            <div class="container">
                <h2>Machine Learning Active Response (Block)</h2>
                {scatter_html}
                <br>
                <h3>Anomalous Flows Detail (Assigned Firewall Drop rules):</h3>
                <div style="overflow-x:auto;">
                    {anomalies_html}
                </div>
            </div>
        </body>
        </html>
        """
        
        report_path = os.path.join(outdir, "report.html")
        with open(report_path, "w") as f:
            f.write(html_content)
        print(f"[✓] Safety-Hardened HTML Report generated at {report_path}")
        
    except Exception as e:
        print(f"[!] Warning: Plotly reporting failed ({e}). Proceeding silently.")


def write_summary_json(tls_df, flow_df, outdir):
    """Write a JSON summary file for dashboard consumption"""
    try:
        import json
        from datetime import datetime
        
        # Calculate metrics
        total_tls = len(tls_df)
        total_flows = len(flow_df)
        
        has_anomaly_col = not flow_df.empty and 'anomaly' in flow_df.columns
        anomalies_count = len(flow_df[flow_df['anomaly'] == -1]) if has_anomaly_col else 0
        
        # Get unique blocked IPs (from anomalies)
        blocked_ips = []
        if has_anomaly_col and not flow_df.empty:
            anomalies = flow_df[flow_df['anomaly'] == -1]
            for _, row in anomalies.iterrows():
                src = row.get('src_ip')
                dst = row.get('dest_ip')
                if pd.notna(src) and str(src) not in ['None', 'NaN']:
                    blocked_ips.append(str(src))
                if pd.notna(dst) and str(dst) not in ['None', 'NaN']:
                    blocked_ips.append(str(dst))
            # Deduplicate
            blocked_ips = list(set(blocked_ips))
        
        summary = {
            "timestamp": datetime.now().isoformat(),
            "total_tls_connections": total_tls,
            "total_flows_analyzed": total_flows,
            "anomalies_detected": anomalies_count,
            "blocked_ips_count": len(blocked_ips),
            "blocked_ips_list": blocked_ips[:50]  # Limit to first 50
        }
        
        summary_path = os.path.join(outdir, "summary.json")
        with open(summary_path, "w") as f:
            json.dump(summary, f, indent=2)
        print(f"[✓] Summary JSON generated at {summary_path}")
        
    except Exception as e:
        print(f"[!] Warning: Failed to write summary JSON: {e}")

def main():
    parser = argparse.ArgumentParser(description="Reliable Analysis & Blocker Module")
    parser.add_argument("--eve", default="project_output/suricata_logs/eve.json", help="Path to logs")
    parser.add_argument("--outdir", default="project_output/analysis", help="Output directory")
    parser.add_argument("--block", action="store_true", help="Dynamically block IPs")
    parser.add_argument("--contamination", type=float, default=0.1, help="ML Contamination factor for IsolationForest")
    parser.add_argument("--interval", type=int, default=20, help="Loop interval in seconds")
    args = parser.parse_args()
    
    os.makedirs(args.outdir, exist_ok=True)
    
    # Run in Real-Time Infinite Loop
    while True:
        if not os.path.exists(args.eve):
            print(f"[!] Warning: Log file missing at {args.eve}. Waiting for capture to begin...")
            time.sleep(args.interval)
            continue
            
        print(f"\n[*] Failsafe Parsing Suricata Logs at {time.strftime('%Y-%m-%d %H:%M:%S')}...")
        tls_df, flow_df = parse_eve(args.eve)
        print(f"[*] Tracked Elements: {len(tls_df)} TLS records, {len(flow_df)} flow records.")
        
        if not flow_df.empty:
            print("[*] Engaging ML Architecture (Isolation Forest)...")
            flow_df = detect_anomalies(flow_df, tls_df, args.contamination)
            if 'anomaly' in flow_df.columns:
                num_anomalies = len(flow_df[flow_df['anomaly'] == -1])
                print(f"[*] Extracted {num_anomalies} anomalies from {len(flow_df)} flows.")
                
                if args.block and num_anomalies > 0:
                    apply_firewall_blocks(flow_df)
        else:
            print("[!] No flow records acquired. Skipping ML phase safely.")
            
        print("[*] Generating Final Analytics Report...")
        generate_report(tls_df, flow_df, args.outdir)
        write_summary_json(tls_df, flow_df, args.outdir)
        
        print(f"[*] Cycle complete. Sleeping for {args.interval} seconds before next real-time cycle...")
        time.sleep(args.interval)

if __name__ == "__main__":
    main()
