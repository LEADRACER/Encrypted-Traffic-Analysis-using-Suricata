"""
Offline Analysis Module
Safely analyzes TLS metadata from Suricata logs
"""

import json
import pandas as pd
import matplotlib.pyplot as plt
import os
import sys

EVE = "project_output/suricata_logs/eve.json"
OUTDIR = "project_output/analysis"
os.makedirs(OUTDIR, exist_ok=True)

if not os.path.exists(EVE):
    print("[!] Suricata log file not found")
    sys.exit(1)

print("\n=== ANALYSIS MODULE ===")
print("1. Show TLS versions")
print("2. Show anomaly counts")
print("3. Generate TLS version graph")

choice = input("Select option: ").strip()

# ---------------- PARSE SURICATA LOG ----------------
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

# ---------------- SAFE COLUMN HANDLING ----------------
for col in ["sni", "issuer", "subject", "tls_version"]:
    if col not in df.columns:
        df[col] = None

df["missing_sni"] = df["sni"].isna()
df["self_signed"] = df["issuer"] == df["subject"]

# ---------------- USER OPTIONS ----------------
if choice == "1":
    print("\nTLS Version Distribution:\n")
    print(df["tls_version"].value_counts())

elif choice == "2":
    print("\nAnomaly Summary:\n")
    print("Missing SNI:", int(df["missing_sni"].sum()))
    print("Self-signed certificates:", int(df["self_signed"].sum()))

elif choice == "3":
    df["tls_version"].value_counts().plot(kind="bar")
    plt.title("TLS Version Distribution")
    plt.tight_layout()
    plt.savefig(f"{OUTDIR}/tls_versions.png")
    plt.show()
    print(f"[✓] Graph saved in {OUTDIR}")

else:
    print("Invalid option selected")

