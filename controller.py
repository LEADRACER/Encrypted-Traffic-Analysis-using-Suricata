"""
Master Controller Script
Enforces capture → analysis pipeline
"""

import subprocess
import sys

wireshark_done = False
suricata_done = False


def run(script, args=None):
    cmd = ["python3", script]
    if args:
        cmd.extend(args)
    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError:
        print(f"[!] Error running {script}")
        sys.exit(1)


while True:
    print("\n===== PROJECT CONTROLLER =====")

    # -------- CAPTURE PHASE --------
    if not (wireshark_done and suricata_done):
        print("1. Run Wireshark Capture")
        print("2. Run Suricata IDS")
        print("3. Run FULL PIPELINE")
        print("0. Exit")

        choice = input("Select option: ").strip()

        if choice == "1":
            run("wireshark_capture.py")
            wireshark_done = True

        elif choice == "2":
            if not wireshark_done:
                print("[!] Run Wireshark first")
            else:
                run("suricata_run.py")
                suricata_done = True

        elif choice == "3":
            run("wireshark_capture.py")
            run("suricata_run.py")
            wireshark_done = True
            suricata_done = True
            print("[✓] Capture pipeline completed")

        elif choice == "0":
            break

        else:
            print("Invalid option")

    # -------- ANALYSIS PHASE --------
    else:
        print("\n=== ANALYSIS MODE ===")
        print("1. Show TLS versions")
        print("2. Show anomaly counts")
        print("3. Generate TLS version graph")
        print("0. Exit")

        choice = input("Select option: ").strip()

        if choice in {"1", "2", "3"}:
            run("analysis.py", [choice])

        elif choice == "0":
            break

        else:
            print("Invalid option")

