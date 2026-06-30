# -*- coding: utf-8 -*-
"""
SBOM Automation Pipeline - Interactive CLI
-------------------------------------------
Provides a seamless, fault-tolerant workflow to:
  1) Scan a project directory (or reuse an existing scan)
  2) Produce a comprehensive summary
  3) Export Excel compliance reports or CycloneDX SBOMs
"""

import os
import sys
import shutil
import subprocess
import datetime
import json
import argparse
import time
import threading
import itertools


# ------------------------------------------------------------------
# Constants
# ------------------------------------------------------------------
if getattr(sys, 'frozen', False):
    exe_dir = os.path.dirname(sys.executable)
else:
    exe_dir = os.path.dirname(os.path.abspath(__file__))

if os.path.basename(exe_dir) in ("Member 2", "Trivy", "sbom_toolsuite"):
    SCRIPT_DIR = os.path.dirname(exe_dir)
else:
    SCRIPT_DIR = exe_dir

MEMBER_2_DIR = "Trivy" if os.path.exists(os.path.join(SCRIPT_DIR, "Trivy")) else "Member 2"

TRIVY_EXE     = os.path.join(SCRIPT_DIR, MEMBER_2_DIR, "trivy_cli.exe")
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
    print("          SBOM Automation Pipeline  v3.0")
    print("     Software Bill of Materials - Compliance Toolkit")
    print("=" * 66)
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


def print_warning(msg):
    print("  [!] WARNING: {}".format(msg))


def print_info(msg):
    print("      {}".format(msg))


# ------------------------------------------------------------------
# Command Runner (Fault Tolerant)
# ------------------------------------------------------------------
def run_cmd(cmd, desc):
    """Run a shell command directly on the terminal for real-time progress and interactive output."""
    print(f"\n  [*] Executing: {desc}")
    print(f"      Command: {cmd}")
    try:
        # Run subprocess allowing it to inherit parent stdout/stderr for real-time console rendering
        subprocess.run(
            cmd, shell=True, check=True
        )
        print(f"  [+] {desc} completed successfully.")
        return True
    except subprocess.CalledProcessError as e:
        print_error(f"{desc} failed (exit code {e.returncode})")
        return False
    except Exception as e:
        print_error(f"Unexpected error running {desc}: {e}")
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
    try:
        subprocess.run(["where", "trivy"], stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL, check=True)
        return "trivy"
    except Exception:
        pass
    print_error("Trivy executable not found. Place trivy.exe in '{}/' or install globally.".format(MEMBER_2_DIR))
    return None


def step_scan(scan_path):
    print_step(1, "Multi-Scanner Scan (Syft+Grype, Trivy fs, cdxgen deep)")
    trivy = resolve_trivy()
    if not trivy:
        return False
    scanner = os.path.join(SCRIPT_DIR, "sbom_toolsuite", "sbom_scanner.py")
    syft_grype = os.path.join(SCRIPT_DIR, "sbom_toolsuite", "syft_grype.json")
    trivy_out = os.path.join(SCRIPT_DIR, "sbom_toolsuite", "trivy_raw.json")
    cdxgen = os.path.join(SCRIPT_DIR, "sbom_toolsuite", "cdxgen_raw.json")
    
    cmd = 'python "{}" --src "{}" --syft-grype "{}" --trivy "{}" --cdxgen "{}" --trivy-path "{}"'.format(
        scanner, scan_path, syft_grype, trivy_out, cdxgen, trivy)
    
    return run_cmd(cmd, "Multi-Scanner orchestration")


def step_merge():
    print_step("1.5", "Merging SBOMs (manifest-cli logic)")
    merger = os.path.join(SCRIPT_DIR, "sbom_toolsuite", "manifest_cli_merger.py")
    syft_grype = os.path.join(SCRIPT_DIR, "sbom_toolsuite", "syft_grype.json")
    trivy_out = os.path.join(SCRIPT_DIR, "sbom_toolsuite", "trivy_raw.json")
    cdxgen = os.path.join(SCRIPT_DIR, "sbom_toolsuite", "cdxgen_raw.json")
    
    cmd = 'python "{}" --syft-grype "{}" --trivy "{}" --cdxgen "{}" --output "{}"'.format(
        merger, syft_grype, trivy_out, cdxgen, RAW_SBOM)
    
    success = run_cmd(cmd, "SBOM Merger")
    if os.path.exists(RAW_SBOM):
        size_kb = os.path.getsize(RAW_SBOM) / 1024
        print_success("Merged Master SBOM generated: {:.1f} KB".format(size_kb))
    return success


def step_enrich():
    print_step(2, "Enriching SBOM (21 Client Attributes)")
    enricher = os.path.join(SCRIPT_DIR, "sbom_toolsuite", "sbom_enricher.py")
    cmd = 'python "{}" "{}" "{}"'.format(enricher, RAW_SBOM, ENRICHED)
    success = run_cmd(cmd, "SBOM Enricher")
    if success and os.path.exists(ENRICHED):
        try:
            with open(ENRICHED, "r", encoding="utf-8") as f:
                data = json.load(f)
            comp_count = len(data.get("components", []))
            print_success("Enriched {} components with full attribute coverage".format(comp_count))
        except Exception:
            pass
    return success


def step_validate():
    print_step(3, "Validating Enriched SBOM Against 21-Attribute Schema")
    validator = os.path.join(SCRIPT_DIR, "sbom_toolsuite", "validate_sbom.py")
    cmd = 'python "{}" "{}"'.format(validator, ENRICHED)
    return run_cmd(cmd, "SBOM Validator")


def step_distribute():
    print_step(4, "Splitting & Signing SBOM into Compliance Tiers")
    distributor = os.path.join(SCRIPT_DIR, "sbom_toolsuite", "sbom_distributor.py")
    keys_dir = os.path.join(SCRIPT_DIR, "sbom_toolsuite", "keys")
    cmd = 'python "{}" --sbom "{}" --keys-dir "{}" --output-dir "{}"'.format(
        distributor, ENRICHED, keys_dir, OUTPUT_DIR)
    return run_cmd(cmd, "SBOM Distributor")


def step_vex_csaf():
    print_step(5, "Generating VEX and CSAF Advisories (Reachability Evaluation)")
    gen = os.path.join(SCRIPT_DIR, "sbom_toolsuite", "vex_csaf_generator.py")
    cmd = 'python "{}" --sbom "{}" --vex "{}" --csaf "{}"'.format(
        gen, ENRICHED, os.path.join(OUTPUT_DIR, "vex.json"), os.path.join(OUTPUT_DIR, "csaf.json"))
    return run_cmd(cmd, "VEX & CSAF Generator")


def step_internal_map():
    print_step(6, "Building Internal Governance Map")
    mapper = os.path.join(SCRIPT_DIR, "sbom_toolsuite", "build_internal_map.py")
    return run_cmd('python "{}"'.format(mapper), "Internal Component Mapper")


def step_html_report(scan_path):
    print_step("H", "Generating Human-Readable HTML Scan Report")
    trivy = resolve_trivy()
    if not trivy:
        return False
    html_tpl = os.path.join(SCRIPT_DIR, MEMBER_2_DIR, "contrib", "html.tpl")
    if not os.path.exists(html_tpl):
        print_warning("HTML template not found: {}. Skipping HTML report.".format(html_tpl))
        return True
    out_path = os.path.join(OUTPUT_DIR, "public", "report.html")
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    cmd = '"{}" fs --format template --template "@{}" --output "{}" "{}"'.format(
        trivy, html_tpl, out_path, scan_path
    )
    return run_cmd(cmd, "Trivy HTML Report Generator")


def step_organize():
    print_step(7, "Organizing Outputs into Tiered Storage")
    moves = {
        os.path.join(OUTPUT_DIR, "sbom_private.json"): os.path.join(OUTPUT_DIR, "restricted", "sbom_private.json"),
        os.path.join(OUTPUT_DIR, "sbom_private.json.sig"): os.path.join(OUTPUT_DIR, "restricted", "sbom_private.json.sig"),
        os.path.join(OUTPUT_DIR, "vex.json"): os.path.join(OUTPUT_DIR, "restricted", "vex.json"),
        ENRICHED: os.path.join(OUTPUT_DIR, "restricted", "sbom_enriched.json"),
        os.path.join(OUTPUT_DIR, "internal_map.json"): os.path.join(OUTPUT_DIR, "internal", "internal_map.json"),
        os.path.join(OUTPUT_DIR, "csaf.json"): os.path.join(OUTPUT_DIR, "internal", "csaf.json"),
        os.path.join(OUTPUT_DIR, "sbom_public.json"): os.path.join(OUTPUT_DIR, "public", "sbom_public.json"),
        os.path.join(OUTPUT_DIR, "sbom_public.json.sig"): os.path.join(OUTPUT_DIR, "public", "sbom_public.json.sig"),
    }
    moved = 0
    for src, dst in moves.items():
        if os.path.exists(src):
            try:
                if os.path.exists(dst): os.remove(dst)
                shutil.move(src, dst)
                moved += 1
            except Exception as e:
                print_warning(f"Could not move {src} to {dst}: {e}")

    # Don't fail the pipeline if organization partially fails
    print_success(f"Organized {moved} files into compliance tiers")
    return True


# ------------------------------------------------------------------
# Display Comprehensive Scan Summary
# ------------------------------------------------------------------
def display_summary():
    target_sbom = ENRICHED
    if not os.path.exists(target_sbom):
        target_sbom = os.path.join(OUTPUT_DIR, "restricted", "sbom_enriched.json")
    
    if not os.path.exists(target_sbom):
        print_error("Could not locate enriched SBOM for summary.")
        return False

    try:
        with open(target_sbom, "r", encoding="utf-8") as f:
            data = json.load(f)
            
        components = data.get("components", [])
        vulns = data.get("vulnerabilities", [])
        
        # Calculate statistics
        languages = set()
        ecosystems = set()
        ai_components = 0
        direct_deps = 0
        
        for c in components:
            purl = c.get("purl", "")
            if purl.startswith("pkg:npm"):
                ecosystems.add("npm (JavaScript/TypeScript)")
                languages.add("JavaScript")
            elif purl.startswith("pkg:pypi"):
                ecosystems.add("PyPI (Python)")
                languages.add("Python")
            elif purl.startswith("pkg:golang"):
                ecosystems.add("Go modules")
                languages.add("Go")
            
            # Check properties
            for p in c.get("properties", []):
                if "ai" in p.get("value", "").lower() or "ml" in p.get("value", "").lower():
                    ai_components += 1
                if p.get("name") == "dependency_type" and p.get("value") == "direct":
                    direct_deps += 1

        transitive_deps = len(components) - direct_deps

        print("")
        if sys.stdout.isatty():
            print("  ┌──────────────────────────────────────────────────┐")
            print("  │  COMPREHENSIVE SCAN SUMMARY                      │")
            print("  ├──────────────────────────────────────────────────┤")
            print("  │  Total Components Detected : {:<19} │".format(len(components)))
            print("  │  Direct Dependencies       : {:<19} │".format(direct_deps))
            print("  │  Transitive Dependencies   : {:<19} │".format(transitive_deps))
            print("  │  AI Components Detected    : {:<19} │".format(ai_components))
            print("  │  Vulnerabilities Detected  : {:<19} │".format(len(vulns)))
            print("  │  Languages Detected        : {:<19} │".format(len(languages)))
            print("  │  Ecosystems Detected       : {:<19} │".format(len(ecosystems)))
            print("  ├──────────────────────────────────────────────────┤")
            print("  │  Overall Status: SUCCESS                         │")
            print("  └──────────────────────────────────────────────────┘")
        else:
            print("  +--------------------------------------------------+")
            print("  |  COMPREHENSIVE SCAN SUMMARY                      |")
            print("  +--------------------------------------------------+")
            print("  |  Total Components Detected : {:<19} |".format(len(components)))
            print("  |  Direct Dependencies       : {:<19} |".format(direct_deps))
            print("  |  Transitive Dependencies   : {:<19} |".format(transitive_deps))
            print("  |  AI Components Detected    : {:<19} |".format(ai_components))
            print("  |  Vulnerabilities Detected  : {:<19} |".format(len(vulns)))
            print("  |  Languages Detected        : {:<19} |".format(len(languages)))
            print("  |  Ecosystems Detected       : {:<19} |".format(len(ecosystems)))
            print("  +--------------------------------------------------+")
            print("  |  Overall Status: SUCCESS                         |")
            print("  +--------------------------------------------------+")
        print("")
        return True
    except Exception as e:
        print_error(f"Failed to generate summary: {e}")
        return False


# ------------------------------------------------------------------
# Workflow Actions
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
    if not os.path.exists(path) or not os.path.isdir(path):
        print_error("Path is not a valid directory: {}".format(path))
        return None
    return path


def run_full_pipeline(scan_path):
    ensure_directories()
    
    steps = [
        lambda: step_scan(scan_path),
        step_merge,
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
            # In a fault-tolerant pipeline, if a critical step fails we might still want to halt.
            # But the steps themselves catch errors and only return False if unrecoverable.
            print_error(f"Pipeline halted at step {i} due to unrecoverable error.")
            return False
            
    print_success("Pipeline execution complete.")
    return True


def export_excel():
    print_step("E", "Generating Styled Excel Compliance Report")
    
    target_sbom = ENRICHED
    if not os.path.exists(target_sbom):
        target_sbom = os.path.join(OUTPUT_DIR, "restricted", "sbom_enriched.json")
        
    reporter = os.path.join(SCRIPT_DIR, "sbom_toolsuite", "excel_reporter.py")
    cmd = 'python "{}" "{}" "{}"'.format(reporter, target_sbom, EXCEL_OUT)
    if run_cmd(cmd, "Excel Report Generator"):
        print_success("Excel Report exported -> {}".format(EXCEL_OUT))
    else:
        print_error("Excel report generation failed.")


def export_cyclonedx():
    print_step("C", "Exporting CycloneDX JSON")
    ensure_directories()
    
    target_sbom = ENRICHED
    if not os.path.exists(target_sbom):
        target_sbom = os.path.join(OUTPUT_DIR, "restricted", "sbom_enriched.json")

    shutil.copy2(target_sbom, CYCLONEDX_OUT)
    if os.path.exists(CYCLONEDX_OUT):
        print_success("CycloneDX JSON exported -> {}".format(CYCLONEDX_OUT))
    else:
        print_error("Failed to export CycloneDX JSON.")


# ------------------------------------------------------------------
# Main Loop (New Linear Workflow)
# ------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="SBOM Automation Pipeline")
    parser.add_argument("--src", "-s", help="Path to the source code folder to scan")
    parser.add_argument("--excel", "-e", help="Output path for Excel report", action="store_true")
    parser.add_argument("--cyclonedx", "-c", help="Output path for CycloneDX format", action="store_true")
    args = parser.parse_args()

    banner()

    # CLI Mode Execution
    if args.src:
        scan_path = os.path.abspath(args.src)
        run_full_pipeline(scan_path)
        display_summary()
        # Automatically generate compliance exports
        export_excel()
        export_cyclonedx()
        sys.exit(0)

    # Interactive Mode Execution
    print("+---------------------------------------------------+")
    print("|                   MAIN MENU                       |")
    print("+---------------------------------------------------+")
    print("|  1  >>  Start SBOM Scan Pipeline                  |")
    print("|  2  >>  Exit                                      |")
    print("+---------------------------------------------------+")
    
    choice = input("\n  Select an option (1-2): ").strip()
    if choice != "1":
        print("  Exiting...")
        sys.exit(0)

    # 1. Get Target Path
    scan_path = action_set_path()
    if not scan_path:
        sys.exit(1)
        
    # 2. Check for existing SBOM
    target_sbom = ENRICHED
    if not os.path.exists(target_sbom):
        target_sbom = os.path.join(OUTPUT_DIR, "restricted", "sbom_enriched.json")
        
    run_scan = True
    if os.path.exists(target_sbom):
        print("\n  Existing enriched SBOM detected.")
        print("  1. Reuse Existing Scan")
        print("  2. Perform Fresh Scan")
        reuse_choice = input("\n  Selection: ").strip()
        if reuse_choice == "1":
            print_success("Reusing existing scan results. Skipping pipeline execution.")
            run_scan = False
            
    # 3. Run Pipeline (if required)
    if run_scan:
        if not run_full_pipeline(scan_path):
            sys.exit(1)
            
    # 4. Display Summary
    if not display_summary():
        sys.exit(1)
        
    # 5. Export
    print("---------------------------------------")
    print("Scan completed successfully.\n")
    print("Auto-generating compliance exports...")
    print("---------------------------------------")
    
    export_excel()
    export_cyclonedx()
        
    print("\n  Workflow complete.\n")


if __name__ == "__main__":
    main()
