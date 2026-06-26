# -*- coding: utf-8 -*-
"""
Member 4 SBOM CLI Pipeline Menu
-------------------------------
Provides an interactive menu for:
  1) Set target source path
  2) Run scanning and verification pipeline (Syft + Grype + Enrich + Validate)
  3) Export to Excel format
  4) Exit
"""

import os
import sys
import subprocess

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SCANNER_PY = os.path.join(SCRIPT_DIR, "sbom_scanner.py")
REPORTER_PY = os.path.join(SCRIPT_DIR, "excel_reporter.py")
FINAL_SBOM = os.path.join(SCRIPT_DIR, "sbom_final.json")
EXCEL_OUT = os.path.join(SCRIPT_DIR, "sbom_report.xlsx")

def banner():
    print("")
    print("=" * 66)
    print("      Syft-Grype SBOM Compliance Pipeline - Member 4 CLI Menu")
    print("=" * 66)

def print_menu(target_path):
    display_path = target_path if target_path else "(not set)"
    print("")
    print("+---------------------------------------------------+")
    print("|                   MEMBER 4 MENU                   |")
    print("+---------------------------------------------------+")
    print("|  Current Target Path: {}".format(display_path))
    print("+---------------------------------------------------+")
    print("|  1  >>  Set Path / Set Target                     |")
    print("|  2  >>  Start Scanning & Compliance Mapping      |")
    print("|  3  >>  Export Excel Report                       |")
    print("|  4  >>  End / Stop                                |")
    print("+---------------------------------------------------+")
    print("")

def action_set_target():
    print("")
    print("  Enter the path to the source code folder to scan:")
    path = input("  > ").strip().strip('"').strip("'")
    if not path:
        print("  [!] Error: Empty path. No changes made.")
        return None

    path = os.path.abspath(path)
    if not os.path.exists(path):
        print("  [!] Error: Path does not exist -> {}".format(path))
        return None
    if not os.path.isdir(path):
        print("  [!] Error: Path is not a directory -> {}".format(path))
        return None

    print("  [+] Target path successfully set to: {}".format(path))
    return path

def action_scan(target_path):
    if not target_path:
        print("  [!] Error: Target path is not set! Please use Option 1 first.")
        return False

    print("\n  >> Launching Syft-Grype Scanning Pipeline...")
    cmd = [sys.executable, SCANNER_PY, "--src", target_path, "--output", FINAL_SBOM]
    try:
        # Run subprocess
        res = subprocess.run(cmd, check=True)
        print("\n  [+] Scanning and compliance validation completed successfully!")
        return True
    except subprocess.CalledProcessError as e:
        print("\n  [!] Error: Pipeline failed.")
        return False

def action_export_excel():
    if not os.path.exists(FINAL_SBOM):
        print("  [!] Error: Enriched SBOM not found at: {}".format(FINAL_SBOM))
        print("      Please run Option 2 (Start Scanning) first.")
        return False

    print("\n  >> Compiling Styled Excel Report...")
    cmd = [sys.executable, REPORTER_PY, FINAL_SBOM, EXCEL_OUT]
    try:
        subprocess.run(cmd, check=True)
        print("  [+] Excel report exported successfully!")
        print("      Saved to: {}".format(EXCEL_OUT))
        return True
    except subprocess.CalledProcessError as e:
        print("  [!] Error: Excel generation failed.")
        return False

def main():
    target_path = None
    # Auto-detect mock_project if available in parent
    parent_dir = os.path.dirname(SCRIPT_DIR)
    mock_proj_path = os.path.join(parent_dir, "mock_project")
    if os.path.exists(mock_proj_path) and os.path.isdir(mock_proj_path):
        target_path = mock_proj_path

    banner()
    while True:
        print_menu(target_path)
        choice = input("  Select an option (1-4): ").strip()
        if choice == "1":
            new_path = action_set_target()
            if new_path:
                target_path = new_path
        elif choice == "2":
            action_scan(target_path)
        elif choice == "3":
            action_export_excel()
        elif choice == "4":
            print("\n  Goodbye! Pipeline CLI closed.\n")
            break
        else:
            print("  [!] Invalid choice. Please enter 1, 2, 3, or 4.")
        
        input("\n  Press Enter to continue...")

if __name__ == "__main__":
    main()
