"""
Offline Analysis Module
Performs TLS metadata analysis based on controller input
"""

import json
import pandas as pd
import matplotlib.pyplot as plt
import os
import sys

EVE = "project_output/suricata_logs/eve.json"
OUTDIR = "project_output/analysis"
os.makedirs(OUTDIR, exist_ok=True)

if len(sys.argv) < 2:
    print("[!] No analysis option provided")
    sys.exit(1)

analysis_option = sys.argv[1]

if not os.path.exists(EVE):
    print("[!] Suricata log file not found")
    sys.exit(1)

# -------- Parse Suricata TLS Logs --------
records = []

with open(EVE) as f:
    for line in f:
        try:
            data = json.loads(line)
            if data.get("event_type") == "tls":
                tls = data.get("tls", {})
                records.append({
                    "tls_version": tls.get("version"),
                    "sni": tls.get("sni"),
                    "issuer": tls.get("issuerdn"),
                    "subject": tls.get("subject")
                })
        except json.JSONDecodeError:
            continue

if not records:
    print("[!] No TLS records found in Suricata logs")
    sys.exit(0)

df = pd.DataFrame(records)

# Safe column handling
for col in ["tls_version", "sni", "issuer", "subject"]:
    if col not in df.columns:
        df[col] = None

df["missing_sni"] = df["sni"].isna()
df["self_signed"] = df["issuer"] == df["subject"]

# -------- Analysis Options --------
if analysis_option == "1":
    print("\n=== TLS VERSION DISTRIBUTION ===\n")
    print(df["tls_version"].value_counts())

elif analysis_option == "2":
    print("\n=== ANOMALY SUMMARY ===\n")
    print("Missing SNI:", int(df["missing_sni"].sum()))
    print("Self-signed certificates:", int(df["self_signed"].sum()))

elif analysis_option == "3":
    df["tls_version"].value_counts().plot(kind="bar")
    plt.title("TLS Version Distribution")
    plt.tight_layout()
    plt.savefig(f"{OUTDIR}/tls_versions.png")
    plt.show()
    print(f"[✓] Graph saved to {OUTDIR}/tls_versions.png")

else:
    print("[!] Invalid analysis option")
