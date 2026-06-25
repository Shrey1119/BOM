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


# ------------------------------------------------------------------
# Constants
# ------------------------------------------------------------------
SCRIPT_DIR    = os.path.dirname(os.path.abspath(__file__))
TRIVY_EXE     = os.path.join(SCRIPT_DIR, "Member 2", "trivy.exe")
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
    print("|  1  >>  Set Path to Scan                          |")
    print("|  2  >>  Export Excel Report (Colourful & Tabular) |")
    print("|  3  >>  Export CycloneDX JSON Format              |")
    print("|  4  >>  Exit                                      |")
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


def action_export_excel(scan_path):
    """Run full pipeline then generate Excel report."""
    if not scan_path:
        print_error("Scan path is not set! Please use option 1 first.")
        return

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
                return
        else:
            print_info("Using existing enriched SBOM. Skipping scan.")
    else:
        if not run_full_scan_pipeline(scan_path):
            return

    # Find the enriched file
    enriched_path = find_enriched_sbom()
    if not enriched_path:
        print_error("Enriched SBOM not found after pipeline. Cannot generate Excel report.")
        return

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


def action_export_cyclonedx(scan_path):
    """Run full pipeline then export a clean CycloneDX JSON."""
    if not scan_path:
        print_error("Scan path is not set! Please use option 1 first.")
        return

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
                return
        else:
            print_info("Using existing enriched SBOM. Skipping scan.")
    else:
        if not run_full_scan_pipeline(scan_path):
            return

    # Find the enriched file
    enriched_path = find_enriched_sbom()
    if not enriched_path:
        print_error("Enriched SBOM not found. Cannot export CycloneDX.")
        return

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


# ------------------------------------------------------------------
# Main Loop
# ------------------------------------------------------------------
def main():
    banner()

    scan_path = None

    while True:
        print_menu(scan_path)
        choice = input("  Select an option (1-4): ").strip()

        if choice == "1":
            result = action_set_path()
            if result:
                scan_path = result

        elif choice == "2":
            action_export_excel(scan_path)

        elif choice == "3":
            action_export_cyclonedx(scan_path)

        elif choice == "4":
            print("")
            print("  Goodbye! SBOM Pipeline terminated.")
            print("")
            break

        else:
            print_error("Invalid option. Please enter 1, 2, 3, or 4.")

        # Pause before showing menu again
        input("\n  Press Enter to continue...")


if __name__ == "__main__":
    main()
