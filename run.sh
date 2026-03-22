#!/bin/bash

# 🛡️ Simple One-Click Automation Script for Track, Prevent, Block Pipeline

echo "=========================================================="
echo "🛡️  Encrypted Traffic Analysis - Automated Pipeline Runner"
echo "=========================================================="

if [ "$EUID" -ne 0 ]; then
  echo "[!] Please run this script as root (sudo ./run.sh)."
  exit 1
fi

echo "[*] 1. Ensuring Python dependencies are installed..."
pip3 install -r requirements.txt -q

# Auto-detect active internet-facing network interface
DEFAULT_IFACE=$(ip route get 8.8.8.8 2>/dev/null | awk '{print $5; exit}')
if [ -z "$DEFAULT_IFACE" ]; then
    DEFAULT_IFACE="eth0"
fi

# Allow user to pass duration as bash argument (default 60 seconds)
DURATION=${1:-60}

echo "[*] 2. Auto-Detected Targeted Network Interface: $DEFAULT_IFACE"
echo "[*] 3. Scheduled IPS Capture Duration: $DURATION seconds"
echo "[*] 4. Initializing Master Python Controller pipeline..."
echo "----------------------------------------------------------"

python3 controller.py --all --interface "$DEFAULT_IFACE" --duration "$DURATION"

echo "----------------------------------------------------------"
echo "[✓] Complete Pipeline execution finished!"
echo "[*] Open your interactive HTML dashboard locally at:"
echo "    $(pwd)/project_output/analysis/report.html"
echo "=========================================================="
