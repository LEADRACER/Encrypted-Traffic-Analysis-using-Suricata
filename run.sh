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
echo "[*] 4. Starting enhanced real-time dashboard with auto-capture..."
echo "----------------------------------------------------------"

# Start enhanced dashboard server in background (starts Wireshark & Suricata automatically)
cd "$SCRIPT_DIR/dashboard"
python3 server.py > dashboard.log 2>&1 &
DASHBOARD_PID=$!
cd "$SCRIPT_DIR"

# Give the dashboard a moment to start
sleep 3

echo "[*] 5. Starting ML analysis and reporting pipeline..."
echo "----------------------------------------------------------"

# Start the analysis pipeline in background for continuous ML analysis and reporting
python3 "$SCRIPT_DIR/controller.py" --realtime --interface "$DEFAULT_IFACE" --block > analysis.log 2>&1 &
ANALYSIS_PID=$!

echo "[*] 6. Pipeline components running:"
echo "    - Dashboard Server: http://localhost:8080"
echo "    - Wireshark Capture: Real-time packet analysis"
echo "    - Suricata Engine: Security event monitoring"
echo "    - ML Analysis: Anomaly detection & reporting"
echo "----------------------------------------------------------"

# Wait for user to stop
echo "[*] Press Ctrl+C to stop all components..."
wait

# Cleanup on exit
echo "[*] Stopping all components..."
kill $DASHBOARD_PID 2>/dev/null || true
kill $ANALYSIS_PID 2>/dev/null || true

echo "[*] Components stopped."
echo "----------------------------------------------------------"
echo "[✓] Pipeline execution finished!"
echo "[*] Open your interactive HTML dashboard locally at:"
echo "    http://localhost:8080"
echo "[*] Check logs in:"
echo "    - $SCRIPT_DIR/dashboard/dashboard.log"
echo "    - $SCRIPT_DIR/analysis.log"
echo "=========================================================="