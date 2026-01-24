# Encrypted-Traffic-Analysis-using-Suricata

## Overview
This project implements a **fully automated encrypted traffic analysis pipeline** using **Python scripts**, **TShark**, and **Suricata IDS**.

All major tasks are handled programmatically:
1. Network traffic is captured using TShark via Python.
2. The captured PCAP is analyzed using Suricata, triggered by Python.
3. Suricata logs are parsed and analyzed using Python scripts.
4. A central controller script manages and coordinates the entire workflow.

Since encrypted traffic does not allow payload inspection, the analysis is based on **metadata, flow behavior, TLS handshake features, and statistical patterns**.

---

## Key Features
- Fully automated traffic capture using TShark (via Python)
- Programmatic execution of Suricata on captured traffic
- Encrypted traffic analysis without decryption
- Python-based parsing and behavioral analysis of Suricata logs
- Central controller script for end-to-end orchestration
- Modular and extensible script-based design

---

## Tech Stack
- **Python 3** – Automation, orchestration, and analysis
- **TShark** – Network traffic capture
- **Suricata** – Intrusion Detection System
- **TLS/SSL Metadata Analysis** – JA3, SNI, certificate information
- **Linux** – Execution and testing environment

---

## Project Structure

---

## Automated Workflow
1. **Traffic Capture**  
   `wireshark_capture.py` uses TShark to capture live encrypted network traffic and saves it as a PCAP file.

2. **Suricata Execution**  
   `suricata_run.py` automatically feeds the captured PCAP file into Suricata using the configured ruleset.

3. **Log Analysis**  
   `analysis.py` parses Suricata’s `eve.json` logs and extracts TLS metadata and flow-based indicators.

4. **Central Orchestration**  
   `controller.py` manages the entire pipeline — executing capture, detection, and analysis sequentially.

---

## How to Run the Project

### Install Dependencies
```bash
pip install -r requirements.txt
```
### Run the Complete Pipeline
```bash
python3 scripts/controller.py
```
---

## This single command:

- Captures encrypted traffic
- Runs Suricata on the captured data
- Analyzes the results automatically

## Use Cases

- Encrypted traffic inspection without decryption
- Malware command-and-control pattern detection
- Blue team and SOC automation practice
- Academic and cybersecurity research projects

## Limitations

- Payload inspection is not possible due to encryption
- Detection accuracy depends on metadata quality and rule tuning
- Requires appropriate permissions for packet capture

## Future Enhancements

- Machine learning–based encrypted traffic classification
- Real-time monitoring mode
- Visualization dashboard for analysis results
- Integration with SIEM platforms

## Disclaimer

- This project is intended for educational and research purposes only.
- Do not run packet capture or IDS tools on networks without proper authorization.

# Workflow Structure

## Overview
The workflow of this project is designed as a **script-driven automated pipeline**, where a dedicated Python script handles each stage. The entire process—from traffic capture to analysis—is coordinated by a central controller, ensuring consistency, repeatability, and minimal manual intervention.

---

## Workflow Architecture

Controller Script (controller.py)  
↓  
Traffic Capture Script (wireshark_capture.py)  
↓  
Suricata Execution Script (suricata_run.py)  
↓  
Log Analysis Script (analysis.py)

---

## Step-by-Step Workflow

### 1. Traffic Capture
The workflow begins with `wireshark_capture.py`.  
This script uses **TShark** to capture live network traffic from a specified interface. The captured data is saved as a **PCAP file**, which serves as the input for the detection stage.

Key Responsibilities:
- Start and stop packet capture programmatically
- Capture encrypted traffic
- Store traffic in PCAP format

---

### 2. Suricata Processing
Once traffic capture is complete, the controller triggers `suricata_run.py`.  
This script runs **Suricata** on the captured PCAP file using predefined configuration and rules.

Key Responsibilities:
- Execute Suricata via Python
- Apply custom IDS rules
- Generate structured logs (eve.json)

---

### 3. Log Analysis
The `analysis.py` script processes Suricata’s output logs.  
Since payloads are encrypted, the analysis focuses on **metadata, flow behavior, and TLS attributes**.

Key Responsibilities:
- Parse eve.json logs
- Extract TLS handshake information
- Analyze flow statistics and traffic patterns
- Identify anomalies or suspicious behavior

---

### 4. Central Orchestration
The entire workflow is controlled by `controller.py`.  
This script ensures that each stage runs in the correct order and handles dependencies between tasks.

Key Responsibilities:
- Orchestrate all scripts
- Maintain execution sequence
- Enable one-command execution of the full pipeline

---

## Workflow Benefits
- Fully automated execution
- Modular and maintainable design
- Easy debugging and testing of individual stages
- Scalable for future enhancements
- Suitable for academic, research, and SOC automation use cases

---

## Execution Flow Summary
1. Controller initiates the workflow  
2. Traffic is captured using TShark  
3. Captured traffic is analyzed by Suricata  
4. Logs are parsed and analyzed using Python  
5. Results are generated for further investigation  

---

## Extensibility
The workflow is designed to be easily extendable. Additional stages, such as real-time monitoring, machine learning-based classification, or visualization, can be integrated without disrupting the existing pipeline.
