"""
Master Controller Script
Controls full project workflow
"""

import subprocess
import sys

def run(script):
    try:
        subprocess.run(["python3", script], check=True)
    except subprocess.CalledProcessError:
        print(f"[!] Error running {script}")
        sys.exit(1)

while True:
    print("\n===== PROJECT CONTROLLER =====")
    print("1. Run Wireshark Capture")
    print("2. Run Suricata IDS")
    print("3. Run Analysis")
    print("4. Run FULL PIPELINE")
    print("0. Exit")

    choice = input("Select option: ").strip()

    if choice == "1":
        run("wireshark_capture.py")
    elif choice == "2":
        run("suricata_run.py")
    elif choice == "3":
        run("analysis.py")
    elif choice == "4":
        run("wireshark_capture.py")
        run("suricata_run.py")
        run("analysis.py")
        print("[✓] Pipeline completed successfully")
    elif choice == "0":
        break
    else:
        print("Invalid choice")
