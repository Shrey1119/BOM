# -*- coding: utf-8 -*-
"""
SBOM Automation Pipeline - Interactive CLI
-------------------------------------------
Provides a looping menu to:
  1) Set the source-code path to scan
  2) Export Excel compliance report (21 attributes, colourful & tabular)
  3) Export CycloneDX SBOM (raw JSON format)
  4) Exit
"""

import os
import sys
import shutil
import subprocess
import datetime
import json
import argparse


# ------------------------------------------------------------------
# Constants
# ------------------------------------------------------------------
if getattr(sys, 'frozen', False):
    exe_dir = os.path.dirname(sys.executable)
else:
    exe_dir = os.path.dirname(os.path.abspath(__file__))

if os.path.basename(exe_dir) in ("Member 2", "sbom_toolsuite"):
    SCRIPT_DIR = os.path.dirname(exe_dir)
else:
    SCRIPT_DIR = exe_dir

TRIVY_EXE     = os.path.join(SCRIPT_DIR, "Member 2", "trivy_cli.exe")
RAW_SBOM      = os.path.join(SCRIPT_DIR, "sbom_raw.json")
ENRICHED      = os.path.join(SCRIPT_DIR, "sbom_enriched.json")
OUTPUT_DIR    = os.path.join(SCRIPT_DIR, "sbom_output")
EXCEL_OUT     = os.path.join(OUTPUT_DIR, "public", "sbom_report.xlsx")
CYCLONEDX_OUT = os.path.join(OUTPUT_DIR, "public", "sbom_cyclonedx.json")


# ------------------------------------------------------------------
# Pretty Printing (ASCII-safe)
# ------------------------------------------------------------------
def banner():
    print("")
    print("=" * 66)
    print("          SBOM Automation Pipeline  v2.0")
    print("     Software Bill of Materials - Compliance Toolkit")
    print("=" * 66)
    print("")


def print_menu(scan_path):
    display_path = scan_path if scan_path else "(not set)"
    print("")
    print("+---------------------------------------------------+")
    print("|                   MAIN MENU                       |")
    print("+---------------------------------------------------+")
    print("|  Current Scan Path: {}".format(display_path))
    print("+---------------------------------------------------+")
    print("|  1  >>  Full Scan                                 |")
    print("|  2  >>  Quick Scan                                |")
    print("|  3  >>  Export Report in Excel Format             |")
    print("|  4  >>  Cyclone DX Format Export                  |")
    print("|  5  >>  Exit                                      |")
    print("+---------------------------------------------------+")
    print("")


def print_step(num, desc):
    print("")
    print("-" * 60)
    print("  Step {}: {}".format(num, desc))
    print("-" * 60)


def print_success(msg):
    print("  [+] {}".format(msg))


def print_error(msg):
    print("  [!] ERROR: {}".format(msg))


def print_info(msg):
    print("      {}".format(msg))


# ------------------------------------------------------------------
# Command Runner
# ------------------------------------------------------------------
def run_cmd(cmd, desc):
    """Run a shell command; return True on success."""
    print("  [*] Running: {}...".format(desc))
    try:
        result = subprocess.run(
            cmd, shell=True, check=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        if result.stdout:
            for line in result.stdout.strip().split("\n")[:15]:
                print("      {}".format(line))
        return True
    except subprocess.CalledProcessError as e:
        print_error("{} failed (exit code {})".format(desc, e.returncode))
        if e.stderr:
            for line in e.stderr.strip().split("\n")[:5]:
                print("      {}".format(line))
        return False
    except Exception as e:
        print_error("Unexpected error: {}".format(e))
        return False


# ------------------------------------------------------------------
# Core Pipeline Steps
# ------------------------------------------------------------------
def ensure_directories():
    os.makedirs(os.path.join(OUTPUT_DIR, "restricted"), exist_ok=True)
    os.makedirs(os.path.join(OUTPUT_DIR, "internal"), exist_ok=True)
    os.makedirs(os.path.join(OUTPUT_DIR, "public"), exist_ok=True)


def resolve_trivy():
    """Find or download the Trivy binary."""
    if os.path.exists(TRIVY_EXE):
        return TRIVY_EXE
    # Fallback to PATH
    try:
        subprocess.run(["where", "trivy"], stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL, check=True)
        return "trivy"
    except Exception:
        pass
    print_error("Trivy executable not found. Place trivy.exe in 'Member 2/' or install globally.")
    return None


def step_scan(scan_path):
    """Step 1: Trivy Scan -> sbom_raw.json"""
    print_step(1, "Trivy Filesystem Scan -> CycloneDX JSON")
    trivy = resolve_trivy()
    if not trivy:
        return False

    scanner = os.path.join(SCRIPT_DIR, "Member 2", "sbom_scanner.py")
    cmd = 'python "{}" --src "{}" --output "{}" --trivy-path "{}"'.format(
        scanner, scan_path, RAW_SBOM, trivy)
    if not run_cmd(cmd, "Trivy Scanner"):
        return False

    if os.path.exists(RAW_SBOM):
        size_kb = os.path.getsize(RAW_SBOM) / 1024
        print_success("Raw SBOM generated: {} ({:.1f} KB)".format(RAW_SBOM, size_kb))
    return True


def step_enrich():
    """Step 2: Enrich SBOM with 21 attributes."""
    print_step(2, "Enriching SBOM (21 Client Attributes)")
    enricher = os.path.join(SCRIPT_DIR, "Member 3", "enricher.py")
    cmd = 'python "{}" "{}" "{}"'.format(enricher, RAW_SBOM, ENRICHED)
    if not run_cmd(cmd, "SBOM Enricher"):
        return False

    if os.path.exists(ENRICHED):
        with open(ENRICHED, "r", encoding="utf-8") as f:
            data = json.load(f)
        comp_count = len(data.get("components", []))
        print_success("Enriched SBOM: {} components with full attribute coverage".format(comp_count))
    return True


def step_validate():
    """Step 3: Validate enriched SBOM."""
    print_step(3, "Validating Enriched SBOM Against 21-Attribute Schema")
    validator = os.path.join(SCRIPT_DIR, "Member 3", "validator.py")
    cmd = 'python "{}" "{}"'.format(validator, ENRICHED)
    return run_cmd(cmd, "SBOM Validator")


def step_distribute():
    """Step 4: Split & Sign SBOM into tiers."""
    print_step(4, "Splitting & Signing SBOM into Compliance Tiers")
    distributor = os.path.join(SCRIPT_DIR, "Member 2", "sbom_distributor.py")
    keys_dir = os.path.join(SCRIPT_DIR, "Member 2", "keys")
    cmd = 'python "{}" --sbom "{}" --keys-dir "{}" --output-dir "{}"'.format(
        distributor, ENRICHED, keys_dir, OUTPUT_DIR)
    return run_cmd(cmd, "SBOM Distributor")


def step_vex_csaf():
    """Step 5: Generate VEX & CSAF advisories."""
    print_step(5, "Generating VEX and CSAF Advisories")
    gen = os.path.join(SCRIPT_DIR, "sbom_toolsuite", "vex_csaf_generator.py")
    return run_cmd('python "{}"'.format(gen), "VEX & CSAF Generator")


def step_internal_map():
    """Step 6: Build internal governance map."""
    print_step(6, "Building Internal Governance Map")
    mapper = os.path.join(SCRIPT_DIR, "sbom_toolsuite", "build_internal_map.py")
    return run_cmd('python "{}"'.format(mapper), "Internal Component Mapper")


def step_html_report(scan_path):
    """Step 6.5: Generate HTML vulnerability report."""
    print_step("H", "Generating Human-Readable HTML Scan Report")
    trivy = resolve_trivy()
    if not trivy:
        return False
    
    html_tpl = os.path.join(SCRIPT_DIR, "Member 2", "contrib", "html.tpl")
    if not os.path.exists(html_tpl):
        print_error("HTML template not found: {}".format(html_tpl))
        return False
        
    out_path = os.path.join(OUTPUT_DIR, "report.html")
    cmd = '"{}" fs --format template --template "@{}" --output "{}" "{}"'.format(
        trivy, html_tpl, out_path, scan_path
    )
    return run_cmd(cmd, "Trivy HTML Report Generator")


def step_organize():
    """Step 7: Organize outputs into tiered folders."""
    print_step(7, "Organizing Outputs into Tiered Storage")

    moves = {
        os.path.join(OUTPUT_DIR, "sbom_private.json"):
            os.path.join(OUTPUT_DIR, "restricted", "sbom_private.json"),
        os.path.join(OUTPUT_DIR, "sbom_private.json.sig"):
            os.path.join(OUTPUT_DIR, "restricted", "sbom_private.json.sig"),
        os.path.join(OUTPUT_DIR, "vex.json"):
            os.path.join(OUTPUT_DIR, "restricted", "vex.json"),
        ENRICHED:
            os.path.join(OUTPUT_DIR, "restricted", "sbom_enriched.json"),
        os.path.join(OUTPUT_DIR, "internal_map.json"):
            os.path.join(OUTPUT_DIR, "internal", "internal_map.json"),
        os.path.join(OUTPUT_DIR, "csaf.json"):
            os.path.join(OUTPUT_DIR, "internal", "csaf.json"),
        os.path.join(OUTPUT_DIR, "sbom_public.json"):
            os.path.join(OUTPUT_DIR, "public", "sbom_public.json"),
        os.path.join(OUTPUT_DIR, "sbom_public.json.sig"):
            os.path.join(OUTPUT_DIR, "public", "sbom_public.json.sig"),
        os.path.join(OUTPUT_DIR, "report.html"):
            os.path.join(OUTPUT_DIR, "public", "report.html"),
    }

    copies = {
        os.path.join(SCRIPT_DIR, "Member 2", "keys", "private_key.pem"):
            os.path.join(OUTPUT_DIR, "restricted", "private_key.pem"),
        os.path.join(SCRIPT_DIR, "Member 2", "keys", "public_key.pem"):
            os.path.join(OUTPUT_DIR, "public", "public_key.pem"),
        os.path.join(SCRIPT_DIR, "sbom_toolsuite", "triage.json"):
            os.path.join(OUTPUT_DIR, "internal", "triage.json"),
    }

    moved = 0
    for src, dst in moves.items():
        if os.path.exists(src):
            if os.path.exists(dst):
                os.remove(dst)
            shutil.move(src, dst)
            print_info("Moved: {} -> {}".format(os.path.basename(src), os.path.basename(dst)))
            moved += 1

    for src, dst in copies.items():
        if os.path.exists(src):
            shutil.copy2(src, dst)
            print_info("Copied: {} -> {}".format(os.path.basename(src), os.path.basename(dst)))
            moved += 1

    print_success("Organized {} files into compliance tiers".format(moved))
    return True


# ------------------------------------------------------------------
# Full Scan Pipeline (used by all export options)
# ------------------------------------------------------------------
def run_full_scan_pipeline(scan_path):
    """Run the complete scan -> enrich -> validate -> distribute pipeline."""
    ensure_directories()

    steps = [
        lambda: step_scan(scan_path),
        step_enrich,
        step_validate,
        step_distribute,
        step_vex_csaf,
        step_internal_map,
        lambda: step_html_report(scan_path),
        step_organize,
    ]

    for i, step_fn in enumerate(steps, 1):
        if not step_fn():
            print_error("Pipeline halted at step {}. Fix the issue above and retry.".format(i))
            return False

    print_success("Full scan pipeline completed successfully!")
    return True


def find_enriched_sbom():
    """Locate the enriched SBOM file (could be in multiple places)."""
    candidates = [
        ENRICHED,
        os.path.join(OUTPUT_DIR, "restricted", "sbom_enriched.json"),
    ]
    for path in candidates:
        if os.path.exists(path):
            return path
    return None


# ------------------------------------------------------------------
# Menu Action Handlers
# ------------------------------------------------------------------
def action_set_path():
    """Prompt user for the source-code directory to scan."""
    print("")
    print("  Enter the full path to the source code folder to scan:")
    path = input("  > ").strip().strip('"').strip("'")

    if not path:
        print_error("Empty path. No changes made.")
        return None

    path = os.path.abspath(path)

    if not os.path.exists(path):
        print_error("Path does not exist: {}".format(path))
        return None

    if not os.path.isdir(path):
        print_error("Path is not a directory: {}".format(path))
        return None

    print_success("Scan path set to: {}".format(path))
    return path


def ensure_scan_path(scan_path):
    """Ensure scan path is set, prompting the user if not."""
    if not scan_path:
        print("\n  Scan path is not set yet.")
        scan_path = action_set_path()
    return scan_path


def action_full_scan(scan_path):
    """Run full scan pipeline and generate all reports (Excel & CycloneDX)."""
    scan_path = ensure_scan_path(scan_path)
    if not scan_path:
        return None

    print("")
    print("  >> Starting Full Scan Pipeline...")
    
    # Run full pipeline
    if not run_full_scan_pipeline(scan_path):
        return scan_path

    enriched_path = find_enriched_sbom()
    if not enriched_path:
        print_error("Enriched SBOM not found after pipeline.")
        return scan_path

    # 1. Export Excel Report
    print_step("E", "Generating Styled Excel Compliance Report")
    reporter = os.path.join(SCRIPT_DIR, "sbom_toolsuite", "excel_reporter.py")
    cmd = 'python "{}" "{}" "{}"'.format(reporter, enriched_path, EXCEL_OUT)
    if run_cmd(cmd, "Excel Report Generator"):
        print_success("Excel Report exported -> {}".format(EXCEL_OUT))
    else:
        print_error("Excel report generation failed.")

    # 2. Export CycloneDX JSON
    print_step("C", "Exporting CycloneDX JSON")
    os.makedirs(os.path.dirname(CYCLONEDX_OUT), exist_ok=True)
    shutil.copy2(enriched_path, CYCLONEDX_OUT)
    
    raw_out = os.path.join(OUTPUT_DIR, "public", "sbom_raw_cyclonedx.json")
    if os.path.exists(RAW_SBOM):
        shutil.copy2(RAW_SBOM, raw_out)

    if os.path.exists(CYCLONEDX_OUT):
        print_success("CycloneDX JSON exported -> {}".format(CYCLONEDX_OUT))
    else:
        print_error("Failed to export CycloneDX JSON.")
        
    return scan_path


def action_quick_scan(scan_path):
    """Run quick filesystem scan and export raw CycloneDX."""
    scan_path = ensure_scan_path(scan_path)
    if not scan_path:
        return None

    print("")
    print("  >> Starting Quick Scan...")
    ensure_directories()
    
    # 1. Scan filesystem
    if not step_scan(scan_path):
        return scan_path

    # 2. HTML Report
    step_html_report(scan_path)

    # 3. Export raw CycloneDX
    print_step("Q", "Exporting Quick CycloneDX JSON")
    os.makedirs(os.path.dirname(CYCLONEDX_OUT), exist_ok=True)
    shutil.copy2(RAW_SBOM, CYCLONEDX_OUT)
    
    if os.path.exists(CYCLONEDX_OUT):
        size_kb = os.path.getsize(CYCLONEDX_OUT) / 1024
        print_success("CycloneDX JSON exported -> {}".format(CYCLONEDX_OUT))
        print_info("File size: {:.1f} KB".format(size_kb))
        print_info("Format: CycloneDX v1.6 (raw scan)")
    else:
        print_error("Failed to export CycloneDX JSON.")
        
    return scan_path


def action_export_excel(scan_path):
    """Run full pipeline then generate Excel report."""
    scan_path = ensure_scan_path(scan_path)
    if not scan_path:
        return None

    print("")
    print("  >> Starting Full Pipeline + Excel Export...")

    # Check if enriched SBOM already exists (skip re-scan if user wants)
    existing = find_enriched_sbom()
    if existing:
        print("")
        print("  An enriched SBOM already exists at:")
        print("    {}".format(existing))
        choice = input("  Re-scan from scratch? (y/N): ").strip().lower()
        if choice in ("y", "yes"):
            if not run_full_scan_pipeline(scan_path):
                return scan_path
        else:
            print_info("Using existing enriched SBOM. Skipping scan.")
    else:
        if not run_full_scan_pipeline(scan_path):
            return scan_path

    # Find the enriched file
    enriched_path = find_enriched_sbom()
    if not enriched_path:
        print_error("Enriched SBOM not found after pipeline. Cannot generate Excel report.")
        return scan_path

    # Generate Excel report
    print_step("E", "Generating Styled Excel Compliance Report")
    reporter = os.path.join(SCRIPT_DIR, "sbom_toolsuite", "excel_reporter.py")
    cmd = 'python "{}" "{}" "{}"'.format(reporter, enriched_path, EXCEL_OUT)
    if run_cmd(cmd, "Excel Report Generator"):
        print_success("Excel Report exported -> {}".format(EXCEL_OUT))
        size_kb = os.path.getsize(EXCEL_OUT) / 1024 if os.path.exists(EXCEL_OUT) else 0
        print_info("File size: {:.1f} KB".format(size_kb))
        print_info("Sheets: Dashboard | Component Data (21 Attr) | Vulnerability Matrix | Legend & Info")
    else:
        print_error("Excel report generation failed.")
    return scan_path


def action_export_cyclonedx(scan_path):
    """Run full pipeline then export a clean CycloneDX JSON."""
    scan_path = ensure_scan_path(scan_path)
    if not scan_path:
        return None

    print("")
    print("  >> Starting Full Pipeline + CycloneDX Export...")

    # Check if enriched SBOM already exists
    existing = find_enriched_sbom()
    if existing:
        print("")
        print("  An enriched SBOM already exists at:")
        print("    {}".format(existing))
        choice = input("  Re-scan from scratch? (y/N): ").strip().lower()
        if choice in ("y", "yes"):
            if not run_full_scan_pipeline(scan_path):
                return scan_path
        else:
            print_info("Using existing enriched SBOM. Skipping scan.")
    else:
        if not run_full_scan_pipeline(scan_path):
            return scan_path

    # Find the enriched file
    enriched_path = find_enriched_sbom()
    if not enriched_path:
        print_error("Enriched SBOM not found. Cannot export CycloneDX.")
        return scan_path

    # Copy the enriched SBOM as the CycloneDX deliverable
    print_step("C", "Exporting CycloneDX JSON")
    ensure_directories()

    shutil.copy2(enriched_path, CYCLONEDX_OUT)

    # Also keep the raw CycloneDX
    raw_out = os.path.join(OUTPUT_DIR, "public", "sbom_raw_cyclonedx.json")
    if os.path.exists(RAW_SBOM):
        shutil.copy2(RAW_SBOM, raw_out)
        print_info("Raw CycloneDX (pre-enrichment) -> {}".format(raw_out))

    if os.path.exists(CYCLONEDX_OUT):
        size_kb = os.path.getsize(CYCLONEDX_OUT) / 1024
        print_success("CycloneDX JSON exported -> {}".format(CYCLONEDX_OUT))
        print_info("File size: {:.1f} KB".format(size_kb))
        print_info("Format: CycloneDX v1.6 (enriched with 21 attributes)")

        # Print quick summary
        with open(CYCLONEDX_OUT, "r", encoding="utf-8") as f:
            data = json.load(f)
        comp_count = len(data.get("components", []))
        vuln_count = len(data.get("vulnerabilities", []))
        print_info("Components: {}  |  Vulnerabilities: {}".format(comp_count, vuln_count))
    else:
        print_error("Failed to export CycloneDX JSON.")
    return scan_path


# ------------------------------------------------------------------
# Main Loop
# ------------------------------------------------------------------
def run_cli_mode(args):
    """Run the pipeline in non-interactive CLI mode."""
    scan_path = args.src
    if not scan_path:
        print_error("Scan path (--src / -s) is required in CLI mode.")
        sys.exit(1)

    scan_path = os.path.abspath(scan_path)
    if not os.path.exists(scan_path) or not os.path.isdir(scan_path):
        print_error("Scan path is not a valid directory: {}".format(scan_path))
        sys.exit(1)

    print_info("CLI mode started. Target: {}".format(scan_path))

    # Run full pipeline
    if not run_full_scan_pipeline(scan_path):
        print_error("Pipeline execution failed.")
        sys.exit(1)

    enriched_path = find_enriched_sbom()
    if not enriched_path:
        print_error("Enriched SBOM not found after pipeline. Cannot export reports.")
        sys.exit(1)

    # 1. Excel Generation
    if args.all or args.excel:
        excel_path = args.excel if isinstance(args.excel, str) else EXCEL_OUT
        excel_path = os.path.abspath(excel_path)
        
        print_step("E", "Generating Styled Excel Compliance Report")
        reporter = os.path.join(SCRIPT_DIR, "sbom_toolsuite", "excel_reporter.py")
        cmd = 'python "{}" "{}" "{}"'.format(reporter, enriched_path, excel_path)
        if run_cmd(cmd, "Excel Report Generator"):
            print_success("Excel Report exported -> {}".format(excel_path))
        else:
            print_error("Excel report generation failed.")

    # 2. CycloneDX Generation
    if args.all or args.cyclonedx:
        json_path = args.cyclonedx if isinstance(args.cyclonedx, str) else CYCLONEDX_OUT
        json_path = os.path.abspath(json_path)
        
        print_step("C", "Exporting CycloneDX JSON")
        ensure_directories()
        
        # Ensure output directory for json_path exists
        os.makedirs(os.path.dirname(json_path), exist_ok=True)
        shutil.copy2(enriched_path, json_path)
        
        # Also copy the raw CycloneDX if it exists
        raw_out = os.path.join(os.path.dirname(json_path), "sbom_raw_cyclonedx.json")
        if os.path.exists(RAW_SBOM):
            shutil.copy2(RAW_SBOM, raw_out)
            print_info("Raw CycloneDX (pre-enrichment) -> {}".format(raw_out))

        if os.path.exists(json_path):
            print_success("CycloneDX JSON exported -> {}".format(json_path))
        else:
            print_error("Failed to export CycloneDX JSON.")


# ------------------------------------------------------------------
# Main Loop
# ------------------------------------------------------------------
def main():
    if len(sys.argv) > 1:
        parser = argparse.ArgumentParser(description="SBOM Automation Pipeline - CLI Mode")
        parser.add_argument("--src", "-s", required=True, help="Path to the source code folder to scan")
        parser.add_argument("--excel", "-e", help="Output path for Excel compliance report (default: sbom_output/public/sbom_report.xlsx)", nargs='?', const=True)
        parser.add_argument("--cyclonedx", "--json", "-j", help="Output path for CycloneDX JSON format (default: sbom_output/public/sbom_cyclonedx.json)", nargs='?', const=True)
        parser.add_argument("--all", "-a", action="store_true", help="Run scan and generate all reports (Excel and CycloneDX)")
        
        args = parser.parse_args()
        run_cli_mode(args)
    else:
        banner()
        scan_path = None

        while True:
            print_menu(scan_path)
            choice = input("  Select an option (1-5): ").strip()

            if choice == "1":
                result = action_full_scan(scan_path)
                if result:
                    scan_path = result

            elif choice == "2":
                result = action_quick_scan(scan_path)
                if result:
                    scan_path = result

            elif choice == "3":
                result = action_export_excel(scan_path)
                if result:
                    scan_path = result

            elif choice == "4":
                result = action_export_cyclonedx(scan_path)
                if result:
                    scan_path = result

            elif choice == "5":
                print("")
                print("  Goodbye! SBOM Pipeline terminated.")
                print("")
                # Keep the window open when double clicked
                input("  Press Enter to close this window...")
                break

            else:
                print_error("Invalid option. Please enter a number between 1 and 5.")

            # Pause before showing menu again
            input("\n  Press Enter to continue...")


if __name__ == "__main__":
    main()
