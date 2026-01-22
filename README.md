# Encrypted-Traffic-Analysis-using-Suricata

## Overview
This project focuses on analyzing **encrypted network traffic** using **Suricata IDS** integrated with **Python-based scripts**. Since payload inspection is not possible for encrypted traffic, this project relies on **metadata, flow behavior, TLS handshake features, and statistical patterns** to identify suspicious or malicious activity.

The goal is to demonstrate how effective security monitoring can still be performed even when traffic is encrypted.

---

## Features
- Encrypted traffic monitoring using Suricata
- Custom Suricata rules for TLS/SSL traffic
- Python scripts for log parsing and analysis
- Detection based on flow behavior and metadata
- Automated extraction of indicators from Suricata logs
- Modular and extensible architecture

---

## Tech Stack
- **Suricata** – Intrusion Detection System
- **Python 3** – Log parsing, analysis, and automation
- **TLS/SSL Analysis** – JA3 fingerprints, SNI, certificate metadata
- **Linux** – Deployment and testing environment

---

## Project Structure
Encrypted-Traffic-Analysis-using-Suricata/
│
├── suricata/
│ ├── rules/ # Custom Suricata rules
│ └── suricata.yaml # Suricata configuration
│
├── scripts/
│ ├── parser.py # Parses Suricata eve.json logs
│ ├── analyzer.py # Traffic behavior analysis
│ └── utils.py # Helper functions
│
├── logs/
│ └── eve.json # Suricata output logs
│
├── requirements.txt
└── README.md


---

## How It Works
1. Suricata monitors live or captured network traffic.
2. TLS/SSL metadata is extracted (SNI, JA3, certificate info).
3. Python scripts parse Suricata `eve.json` logs.
4. Traffic patterns are analyzed to detect anomalies.
5. Alerts and insights are generated based on behavioral analysis.

---

## Installation & Setup

### Prerequisites
- Linux (Ubuntu/Kali recommended)
- Suricata installed and configured
- Python 3.8+
- Network traffic source (pcap or live interface)

### Install Dependencies
```bash
pip install -r requirements.txt
