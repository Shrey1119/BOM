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
import time
import threading
import json

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SCANNER_PY = os.path.join(SCRIPT_DIR, "sbom_scanner.py")
REPORTER_PY = os.path.join(SCRIPT_DIR, "excel_reporter.py")
ENRICHER_PY = os.path.join(SCRIPT_DIR, "enricher.py")
VALIDATOR_PY = os.path.join(SCRIPT_DIR, "validator.py")
CONFIG_JSON = os.path.join(SCRIPT_DIR, "config.json")
FINAL_SBOM = os.path.join(SCRIPT_DIR, "sbom_final.json")
EXCEL_OUT = os.path.join(SCRIPT_DIR, "sbom_report.xlsx")
BIN_DIR = os.path.join(SCRIPT_DIR, "bin")
SYFT_EXE = os.path.join(BIN_DIR, "syft.exe")
GRYPE_EXE = os.path.join(BIN_DIR, "grype.exe")

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

def get_bar_chars():
    try:
        # Check if stdout can encode block characters
        "█".encode(sys.stdout.encoding or 'ascii')
        return "█", "░"
    except Exception:
        return "#", "-"

class ScanStepProgress:
    def __init__(self, step_name, start_percent, end_percent):
        self.step_name = step_name
        self.start_percent = start_percent
        self.end_percent = end_percent
        self.start_time = time.time()
        
    def update(self, current_progress, total_progress, component_count=None):
        fraction = current_progress / max(total_progress, 1)
        actual_percent = self.start_percent + fraction * (self.end_percent - self.start_percent)
        
        bar_len = 20
        filled = int(round(bar_len * current_progress / max(total_progress, 1)))
        b_char, e_char = get_bar_chars()
        bar = b_char * filled + e_char * (bar_len - filled)
        
        elapsed = time.time() - self.start_time
        comp_str = f" | Detected: {component_count}" if component_count is not None else ""
        sys.stdout.write(f"\r           [{bar}] {actual_percent:.1f}% | Elapsed: {elapsed:.1f}s{comp_str}")
        sys.stdout.flush()
        
    def complete(self, component_count=None):
        self.update(1, 1, component_count)
        sys.stdout.write("\n")
        sys.stdout.flush()

def run_process_with_progress(cmd, step_progress, env=None, component_count_cb=None):
    proc_data = {'process': None, 'error': None, 'success': False}
    
    def run_proc():
        try:
            proc_data['process'] = subprocess.Popen(
                cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                env=env,
                text=True
            )
            stdout, stderr = proc_data['process'].communicate()
            if proc_data['process'].returncode == 0:
                proc_data['success'] = True
            else:
                proc_data['error'] = stderr or stdout
        except Exception as e:
            proc_data['error'] = str(e)
            
    t = threading.Thread(target=run_proc)
    t.daemon = True
    t.start()
    
    start_time = time.time()
    spinners = ['|', '/', '-', '\\']
    idx = 0
    while t.is_alive():
        elapsed = time.time() - start_time
        fake_progress = min(elapsed / 15.0, 0.95)
        
        comp_count = None
        if component_count_cb:
            comp_count = component_count_cb()
            
        bar_len = 20
        filled = int(round(bar_len * fake_progress))
        b_char, e_char = get_bar_chars()
        bar = b_char * filled + e_char * (bar_len - filled)
        
        actual_percent = step_progress.start_percent + fake_progress * (step_progress.end_percent - step_progress.start_percent)
        
        comp_str = f" | Detected: {comp_count}" if comp_count is not None else ""
        sys.stdout.write(f"\r           [{bar}] {actual_percent:.1f}% | Elapsed: {elapsed:.1f}s {spinners[idx % 4]}{comp_str}")
        sys.stdout.flush()
        
        idx += 1
        time.sleep(0.2)
        
    t.join()
    
    if not proc_data['success']:
        print(f"\n  [!] Process execution error: {proc_data['error']}")
        raise subprocess.CalledProcessError(1, cmd)
        
    comp_count = None
    if component_count_cb:
        comp_count = component_count_cb()
    step_progress.complete(comp_count)

def get_raw_components_count():
    try:
        raw_sbom = os.path.join(SCRIPT_DIR, "sbom_raw.json")
        if os.path.exists(raw_sbom):
            with open(raw_sbom, 'r', encoding='utf-8') as f:
                data = json.load(f)
                return len(data.get('components', []))
    except Exception:
        pass
    return 0

def action_scan(target_path):
    if not target_path:
        print("  [!] Error: Target path is not set! Please use Option 1 first.")
        return False

    print("\n==========================================================")
    print("             READY TO LAUNCH COMPLIANCE SCAN              ")
    print("==========================================================")
    print("  Target Directory: {}".format(target_path))
    print("  Output SBOM File: {}".format(FINAL_SBOM))
    print("  Config File:      {}".format(CONFIG_JSON))
    print("==========================================================")
    confirm = input("  Do you want to start the scan now? (Y/n): ").strip().lower()
    if confirm not in ['', 'y', 'yes']:
        print("  [!] Scan cancelled by user.")
        return False

    raw_sbom = os.path.join(SCRIPT_DIR, "sbom_raw.json")
    vulnerable_sbom = os.path.join(SCRIPT_DIR, "sbom_vulnerable.json")
    
    # Check pre-requisites
    if not os.path.exists(SYFT_EXE) or not os.path.exists(GRYPE_EXE):
        print("\n  [!] Error: Portable Syft or Grype binaries not found in 'Member 4/bin/'.")
        print("      Please run setup_tools.py to install them.")
        return False

    print("\n  >> Starting compliance pipeline scan...\n")

    # Step 1: Init check (0% - 10%)
    step1 = ScanStepProgress("[Phase 1/5] Initializing scan environment & target sanity checks", 0, 10)
    print(f"  [+] {step1.step_name}")
    time.sleep(0.8)
    step1.complete(0)

    # Step 2: Syft Scan (10% - 40%)
    step2 = ScanStepProgress("[Phase 2/5] Running Syft deep dependency cataloging", 10, 40)
    print(f"  [+] {step2.step_name}")
    
    syft_cmd = [
        SYFT_EXE,
        f"dir:{os.path.abspath(target_path)}",
        "-o", f"cyclonedx-json={raw_sbom}"
    ]
    try:
        run_process_with_progress(syft_cmd, step2)
    except Exception:
        print("\n  [!] Syft cataloging phase failed.")
        return False

    raw_count = get_raw_components_count()

    # Step 3: Grype Vulnerability Scan (40% - 70%)
    step3 = ScanStepProgress("[Phase 3/5] Running Grype vulnerability mapper", 40, 70)
    print(f"  [+] {step3.step_name}")
    
    grype_cmd = [
        GRYPE_EXE,
        f"sbom:{raw_sbom}",
        "-o", "cyclonedx-json",
        "--file", vulnerable_sbom
    ]
    
    # Configure env to ignore database age checks
    grype_env = os.environ.copy()
    grype_env["GRYPE_DB_MAX_ALLOWED_BUILT_AGE"] = "87600h"
    
    try:
        run_process_with_progress(grype_cmd, step3, env=grype_env, component_count_cb=lambda: raw_count)
    except Exception:
        print("\n  [!] Grype vulnerability mapping phase failed.")
        return False

    # Step 4: Enrich SBOM (70% - 90%)
    step4 = ScanStepProgress("[Phase 4/5] Enriching metadata & calculating risk metrics", 70, 90)
    print(f"  [+] {step4.step_name}")
    
    enrich_cmd = [
        sys.executable,
        ENRICHER_PY,
        vulnerable_sbom,
        FINAL_SBOM,
        CONFIG_JSON
    ]
    try:
        run_process_with_progress(enrich_cmd, step4, component_count_cb=lambda: raw_count)
    except Exception:
        print("\n  [!] Metadata enrichment phase failed.")
        return False

    # Step 5: Validate SBOM (90% - 100%)
    step5 = ScanStepProgress("[Phase 5/5] Performing compliance validation checks", 90, 100)
    print(f"  [+] {step5.step_name}")
    
    validate_cmd = [
        sys.executable,
        VALIDATOR_PY,
        FINAL_SBOM
    ]
    try:
        run_process_with_progress(validate_cmd, step5, component_count_cb=lambda: raw_count)
        print("\n  [+] Scanning and compliance validation completed successfully!")
        return True
    except Exception:
        print("\n  [!] Compliance validation phase failed.")
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
