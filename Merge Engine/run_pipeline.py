# -*- coding: utf-8 -*-
"""
Enterprise SBOM Correlation & Merge Engine - CLI Pipeline Menu
Provides an interactive menu to set a target directory, scan it using 
both Syft and Trivy, and automatically merge and enrich the output.
"""

import os
import sys
import subprocess
import time
import threading
import json
import shutil

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(SCRIPT_DIR)

# Binaries & Scripts
SYFT_EXE = os.path.join(PARENT_DIR, "Member 4", "bin", "syft.exe")
TRIVY_EXE = os.path.join(PARENT_DIR, "Trivy", "trivy_cli.exe")

MERGE_PY = os.path.join(SCRIPT_DIR, "merge_engine.py")
ENRICHER_PY = os.path.join(SCRIPT_DIR, "enricher.py")
VALIDATOR_PY = os.path.join(SCRIPT_DIR, "validator.py")
REPORTER_PY = os.path.join(SCRIPT_DIR, "excel_reporter.py")
CONFIG_JSON = os.path.join(SCRIPT_DIR, "config.json")

SYFT_RAW = os.path.join(SCRIPT_DIR, "syft_raw.json")
TRIVY_RAW = os.path.join(SCRIPT_DIR, "trivy_raw.json")
VULN_SBOM = os.path.join(SCRIPT_DIR, "sbom_vulnerable.json")
FINAL_SBOM = os.path.join(SCRIPT_DIR, "sbom_final.json")
EXCEL_OUT = os.path.join(SCRIPT_DIR, "sbom_report.xlsx")

def banner():
    print("")
    print("=" * 66)
    print("    Enterprise SBOM Correlation & Merge Engine - CLI Menu")
    print("=" * 66)

def print_menu(target_path):
    display_path = target_path if target_path else "(not set)"
    print("")
    print("+---------------------------------------------------+")
    print("|                  MERGE ENGINE MENU                |")
    print("+---------------------------------------------------+")
    print("|  Current Target Path: {}".format(display_path))
    print("+---------------------------------------------------+")
    print("|  1  >>  Set Path / Set Target                     |")
    print("|  2  >>  Start Scanning & Correlation Pipeline     |")
    print("|  3  >>  Export Styled 7-Sheet Excel Report        |")
    print("|  4  >>  Exit / Close                              |")
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
        comp_str = f" | Unified: {component_count}" if component_count is not None else ""
        sys.stdout.write(f"\r           [{bar}] {actual_percent:.1f}% | Elapsed: {elapsed:.1f}s{comp_str}")
        sys.stdout.flush()
        
    def complete(self, component_count=None):
        self.update(1, 1, component_count)
        sys.stdout.write("\n")
        sys.stdout.flush()

def run_process_with_progress(cmd, step_progress, cwd=None, env=None, component_count_cb=None, shell=False, stdout_file=None):
    proc_data = {'process': None, 'error': None, 'success': False}
    
    def run_proc():
        try:
            proc_data['process'] = subprocess.Popen(
                cmd, 
                stdout=stdout_file or subprocess.PIPE, 
                stderr=subprocess.PIPE,
                cwd=cwd,
                env=env,
                text=True,
                shell=shell
            )
            stdout, stderr = proc_data['process'].communicate()
            if proc_data['process'].returncode == 0:
                proc_data['success'] = True
            else:
                proc_data['error'] = stderr or f"Process exited with non-zero code {proc_data['process'].returncode}"
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
        fake_progress = min(elapsed / 15.0, 0.95) # Assume 15s typical scan block time
        
        comp_count = None
        if component_count_cb:
            comp_count = component_count_cb()
            
        bar_len = 20
        filled = int(round(bar_len * fake_progress))
        b_char, e_char = get_bar_chars()
        bar = b_char * filled + e_char * (bar_len - filled)
        
        actual_percent = step_progress.start_percent + fake_progress * (step_progress.end_percent - step_progress.start_percent)
        
        comp_str = f" | Unified: {comp_count}" if comp_count is not None else ""
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

def get_final_components_count():
    try:
        if os.path.exists(FINAL_SBOM):
            with open(FINAL_SBOM, 'r', encoding='utf-8') as f:
                data = json.load(f)
                return len(data.get('components', []))
    except Exception:
        pass
    return 0

def action_scan(target_path):
    if not target_path:
        print("  [!] Error: Target path is not set! Please use Option 1 first.")
        return False
        
    # Check pre-requisites
    if not os.path.exists(SYFT_EXE):
        print("\n  [!] Error: Syft executable not found at: {}".format(SYFT_EXE))
        return False
        
    if not os.path.exists(TRIVY_EXE):
        print("\n  [!] Error: Trivy executable not found at: {}".format(TRIVY_EXE))
        return False

    print("\n==========================================================")
    print("             READY TO LAUNCH COMBINED SCAN & MERGE        ")
    print("==========================================================")
    print("  Target Directory: {}".format(target_path))
    print("  Output SBOM File: {}".format(FINAL_SBOM))
    print("  Config File:      {}".format(CONFIG_JSON))
    print("==========================================================")
    confirm = input("  Do you want to start the scan now? (Y/n): ").strip().lower()
    if confirm not in ['', 'y', 'yes']:
        print("  [!] Scan cancelled by user.")
        return False
        
    print("\n  >> Starting combined Syft + Trivy compliance scan...\n")
    
    # Step 1: Initial checks (0% - 5%)
    step1 = ScanStepProgress("[Phase 1/5] Initializing scan environment & binaries verification", 0, 5)
    print(f"  [+] {step1.step_name}")
    time.sleep(0.5)
    step1.complete(0)
    
    # Step 2: Syft scan (5% - 40%)
    step2 = ScanStepProgress("[Phase 2/5] Running Syft filesystem package cataloger", 5, 40)
    print(f"  [+] {step2.step_name}")
    
    syft_cmd = [
        SYFT_EXE,
        "scan",
        f"dir:{os.path.abspath(target_path)}",
        "-o", "cyclonedx-json"
    ]
    
    try:
        with open(SYFT_RAW, 'w', encoding='utf-8') as f_out:
            run_process_with_progress(syft_cmd, step2, stdout_file=f_out)
    except Exception:
        print("\n  [!] Syft scanning phase failed.")
        return False
        
    # Step 3: Trivy scan (40% - 75%)
    step3 = ScanStepProgress("[Phase 3/5] Running Trivy vulnerability dependency scanner", 40, 75)
    print(f"  [+] {step3.step_name}")
    
    trivy_cmd = [
        TRIVY_EXE,
        "fs",
        "--format", "cyclonedx",
        "--scanners", "vuln",
        os.path.abspath(target_path)
    ]
    
    try:
        with open(TRIVY_RAW, 'w', encoding='utf-8') as f_out:
            run_process_with_progress(trivy_cmd, step3, stdout_file=f_out)
    except Exception:
        print("\n  [!] Trivy scanning phase failed.")
        return False
        
    # Step 4: Correlation & Merge (75% - 90%)
    step4 = ScanStepProgress("[Phase 4/5] Merging SBOM component catalogs & resolving loop edges", 75, 90)
    print(f"  [+] {step4.step_name}")
    
    merge_cmd = [
        sys.executable,
        MERGE_PY,
        "--syft", SYFT_RAW,
        "--trivy", TRIVY_RAW,
        "--config", CONFIG_JSON,
        "--output", VULN_SBOM
    ]
    
    try:
        run_process_with_progress(merge_cmd, step4)
    except Exception:
        print("\n  [!] Correlation merge phase failed.")
        return False
        
    # Step 5: Enrichment & Validation (90% - 100%)
    step5 = ScanStepProgress("[Phase 5/5] Performing advanced attribute enrichment & validation checks", 90, 100)
    print(f"  [+] {step5.step_name}")
    
    enrich_cmd = [
        sys.executable,
        ENRICHER_PY,
        VULN_SBOM,
        FINAL_SBOM,
        CONFIG_JSON
    ]
    
    validate_cmd = [
        sys.executable,
        VALIDATOR_PY,
        FINAL_SBOM
    ]
    
    try:
        run_process_with_progress(enrich_cmd, step5)
        subprocess.run(validate_cmd, check=True)
        final_count = get_final_components_count()
        step5.complete(final_count)
        print("\n  [+] Combined scan and merge pipeline completed successfully!")
        return True
    except Exception:
        print("\n  [!] Enrichment / Validation phase failed.")
        return False

def action_export_excel():
    if not os.path.exists(FINAL_SBOM):
        print("  [!] Error: Final merged SBOM not found at: {}".format(FINAL_SBOM))
        print("      Please run Option 2 (Start Scanning) first.")
        return False
        
    print("\n  >> Constructing Styled 7-Sheet Excel Compliance Report...")
    cmd = [sys.executable, REPORTER_PY, FINAL_SBOM, EXCEL_OUT]
    try:
        subprocess.run(cmd, check=True)
        print("  [+] Excel report exported successfully!")
        print("      Saved to: {}".format(EXCEL_OUT))
        return True
    except subprocess.CalledProcessError:
        print("  [!] Error: Excel exporter compilation failed.")
        return False

def main():
    target_path = None
    # Auto-detect mock_project in parent
    mock_proj_path = os.path.join(PARENT_DIR, "mock_project")
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
            print("\n  Goodbye! Merge Engine CLI closed.\n")
            break
        else:
            print("  [!] Invalid selection. Please enter 1, 2, 3, or 4.")
            
        input("\n  Press Enter to continue...")

if __name__ == "__main__":
    main()
