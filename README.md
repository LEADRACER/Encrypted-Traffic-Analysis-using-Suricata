# Encrypted-Traffic-Analysis-using-Suricata

## Overview
This project provides an advanced **Intrusion Prevention System (IPS)** and **Dynamic Firewall Automation** toolkit for analyzing and mitigating anomalous encrypted network traffic. Since deep packet inspection is impossible on encrypted payloads, this project heavily relies on **flow behavior, TLS handshake metadata, JA3 fingerprints, and Unsupervised Machine Learning** to reliably detect and neutralize threats.

The pipeline executes a definitive **Track, Prevent, Block** methodology:
1. **TRACK (ML Engine):** Captures traffic and analyzes network flows using Scikit-Learn's Isolation Forest to track anomalies in volume/duration ratios.
2. **PREVENT (Inline IPS):** Runs Suricata natively in inline NFQUEUE mode to intercept packets and immediately drop malicious handshakes matching specific rules.
3. **BLOCK (Dynamic Firewall):** Extracts hostile IPs from the ML anomaly detector and automatically injects strict `iptables DROP` rules to permanently sever the connections.

---

## 🚀 Features
- **Track, Prevent, Block Methodology**
- **Suricata Inline IPS Support** (NFQUEUE manipulation)
- **Machine Learning Flow Analysis** using Isolation Forest (`scikit-learn`)
- **JA3 & JA3s Fingerprinting** for identifying unique malicious clients
- **Interactive HTML Reporting** powered by Plotly for live dashboarding
- **Completely automated CLI Controller** built with `argparse`

---

## 🛠 Tech Stack
- **Python 3.8+** (CLI, Orchestration, Analysis)
- **Suricata** (IDS/IPS Engine)
- **Wireshark (tshark)** (Packet Capture)
- **Scikit-Learn & Pandas** (Machine Learning & Data Processing)
- **Plotly** (Interactive Web Reports)
- **IPTables / NFQUEUE** (Active Firewall Blocking)

---

## 📂 Project Structure
```text
Encrypted-Traffic-Analysis-using-Suricata/
│
├── controller.py          # Master CLI Orchestrator
├── wireshark_capture.py   # Traffic Tracking module
├── suricata_run.py        # Suricata execution & IPS Prevention module
├── analysis.py            # ML Anomaly Detection & IPTables Blocking module
│
├── requirements.txt       # Python dependencies
├── README.md              # Documentation
│
├── suricata/
│   └── rules/             # Dynamically generated Suricata Drop/Alert rules
│
└── project_output/        # Auto-generated outputs
    ├── captures/          # Saved .pcap files
    ├── suricata_logs/     # Suricata eve.json output
    └── analysis/          # Interactive HTML Reports
```

---

## ⚙️ Installation & Setup

### Prerequisites
- Linux Environment (Ubuntu / Debian / Kali recommended)
- `sudo` privileges (required for `iptables` and NFQUEUE manipulation)
- Suricata & TShark installed:
  ```bash
  sudo apt-get update
  sudo apt-get install suricata tshark python3-pip -y
  ```

### Install Python Dependencies
```bash
pip3 install -r requirements.txt
```

---

## 🚦 How to Use (The Controller)

The entire project has been consolidated into a master controller script. You can run individual modules or execute the entire Track, Prevent, Block pipeline automatically.

### Run the Full Active Pipeline
To capture traffic, run Suricata inline (IPS mode), perform ML analysis, actively block anomalous IPs, and generate an HTML report:
```bash
python3 controller.py --all --interface eth0 --duration 60
```
> **Note:** Generate HTTPS traffic (e.g. browsing or `curl`) during the capture phase!

### CLI Options
```text
options:
  -h, --help            show this help message and exit
  --capture             Run Wireshark capture (Track)
  --interface INTERFACE Network interface (Default: eth0)
  --duration DURATION   Capture/Suricata duration in seconds (Default: 30)
  --suricata            Run Suricata engine
  --ips                 Run Suricata directly in Inline IPS Mode (Prevent)
  --analyze             Run ML Analysis and generate HTML report (Track)
  --block               Dynamically isolate anomalous IPs via Firewall (Block)
  --all                 Run full Track, Prevent, Block pipeline
```

---

## 📊 The Interactive Report
After the pipeline finishes, an interactive HTML dashboard is compiled at:
`project_output/analysis/report.html`

The dashboard displays:
- Total connections and identified Machine Learning anomalies.
- Plotly interactive graphs mapping Server vs Client byte exchanges for Anomalous connections.
- TLS version distributions.
- Top JA3 and JA3s fingerprints.
- A table documenting which specific IP Addresses were targeted by automated `iptables DROP` firewall rules.

---

## ⚠️ Disclaimer
Running the `--all` or `--ips` flags will intentionally disrupt ongoing network flows by altering `iptables` rules and hooking traffic into `NFQUEUE`. This engine is designed for active disruption of network traffic. Run in a controlled testing environment, as the Machine Learning engine may permanently block legitimate IP addresses if they exhibit extreme flow anomalies.
