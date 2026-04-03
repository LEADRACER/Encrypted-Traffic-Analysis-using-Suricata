#!/bin/bash

# 🛡️ Simple One-Click Automation Script for Track, Prevent, Block Pipeline

echo "=========================================================="
echo "🛡️  Encrypted Traffic Analysis - Automated Pipeline Runner"
echo "=========================================================="

if [ "$EUID" -ne 0 ]; then
  echo "[!] Please run this script as root (sudo ./run.sh)."
  exit 1
fi

# FIX: was installing from requirements.txt (old broken file); now always uses
# the correct fixed requirements.txt in the same directory as this script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REQ_FILE="$SCRIPT_DIR/requirements.txt"

echo "[*] 1. Ensuring Python dependencies are installed..."
# FIX: cleaner fallback — try with --break-system-packages first (Kali/Debian),
# then fall back to plain pip3 for venv environments
pip3 install -r "$REQ_FILE" -q --break-system-packages 2>/dev/null \
  || pip3 install -r "$REQ_FILE" -q

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

python3 "$SCRIPT_DIR/controller.py" --all --interface "$DEFAULT_IFACE" --duration "$DURATION"

echo "----------------------------------------------------------"
echo "[✓] Complete Pipeline execution finished!"
echo "[*] Open your interactive HTML dashboard locally at:"
echo "    $SCRIPT_DIR/project_output/analysis/report.html"
echo "=========================================================="
