import os
import sys
import subprocess
import argparse
import shutil
from merge_engine import merge_sboms

# Paths
MERGE_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(MERGE_DIR)

# Scanner Binaries
SYFT_EXE = os.path.join(PARENT_DIR, "Member 4", "bin", "syft.exe")
TRIVY_EXE = os.path.join(PARENT_DIR, "Trivy", "trivy_cli.exe")

ENRICHER_PY = os.path.join(MERGE_DIR, "enricher.py")
VALIDATOR_PY = os.path.join(MERGE_DIR, "validator.py")
CONFIG_JSON = os.path.join(MERGE_DIR, "config.json")

def check_binaries():
    if not os.path.exists(SYFT_EXE):
        print(f"Error: Syft executable not found at {SYFT_EXE}")
        return False
    if not os.path.exists(TRIVY_EXE):
        print(f"Error: Trivy executable not found at {TRIVY_EXE}")
        return False
    return True

def run_scanner(src_dir, output_path):
    if not check_binaries():
        return False
        
    src_dir_abs = os.path.abspath(src_dir)
    output_path_abs = os.path.abspath(output_path)
    
    syft_raw = os.path.join(MERGE_DIR, "syft_raw.json")
    trivy_raw = os.path.join(MERGE_DIR, "trivy_raw.json")
    vulnerable_sbom = os.path.join(MERGE_DIR, "sbom_vulnerable.json")
    
    # 1. Run Syft Scan
    print(f"\n[Step 1] Running Syft filesystem scan on {src_dir_abs}...")
    syft_cmd = [
        SYFT_EXE,
        "scan",
        f"dir:{src_dir_abs}",
        "-o", "cyclonedx-json"
    ]
    print(f"Executing: {' '.join(syft_cmd)}")
    try:
        # Redirect stdout directly to syft_raw.json
        with open(syft_raw, 'w', encoding='utf-8') as f_out:
            subprocess.run(syft_cmd, stdout=f_out, stderr=subprocess.PIPE, text=True, check=True)
        size_kb = os.path.getsize(syft_raw) / 1024
        print(f"Syft scan completed successfully. Raw SBOM generated: {syft_raw} ({size_kb:.1f} KB)")
    except subprocess.CalledProcessError as e:
        print(f"Error running Syft: {e.stderr or e}")
        return False
        
    # 2. Run Trivy Scan
    print(f"\n[Step 2] Running Trivy filesystem scan on {src_dir_abs}...")
    trivy_cmd = [
        TRIVY_EXE,
        "fs",
        "--format", "cyclonedx",
        "--scanners", "vuln",
        src_dir_abs
    ]
    print(f"Executing: {' '.join(trivy_cmd)}")
    try:
        with open(trivy_raw, 'w', encoding='utf-8') as f_out:
            subprocess.run(trivy_cmd, stdout=f_out, stderr=subprocess.PIPE, text=True, check=True)
        size_kb = os.path.getsize(trivy_raw) / 1024
        print(f"Trivy scan completed successfully. Raw SBOM generated: {trivy_raw} ({size_kb:.1f} KB)")
    except subprocess.CalledProcessError as e:
        print(f"Error running Trivy: {e.stderr or e}")
        return False
        
    # 3. Correlate and Merge
    print("\n[Step 3] Correlating and deduplicating component catalogs...")
    try:
        merge_sboms(syft_raw, trivy_raw, CONFIG_JSON, vulnerable_sbom)
    except Exception as e:
        print(f"Error merging SBOMs: {e}")
        return False
        
    # 4. Enrich SBOM
    print(f"\n[Step 4] Running Attribute Enricher...")
    enrich_cmd = [
        sys.executable,
        ENRICHER_PY,
        vulnerable_sbom,
        output_path_abs,
        CONFIG_JSON
    ]
    print(f"Executing: {' '.join(enrich_cmd)}")
    try:
        subprocess.run(enrich_cmd, capture_output=True, text=True, check=True)
        print(f"Enrichment completed successfully. Final SBOM: {output_path_abs}")
    except subprocess.CalledProcessError as e:
        print(f"Error running Enricher: {e.stderr or e}")
        return False

    # 5. Validate Compliance
    print(f"\n[Step 5] Running Compliance Validation...")
    validate_cmd = [
        sys.executable,
        VALIDATOR_PY,
        output_path_abs
    ]
    print(f"Executing: {' '.join(validate_cmd)}")
    try:
        subprocess.run(validate_cmd, check=True)
        print("Validation completed successfully. Merged SBOM is fully compliant!")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error running Validator: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Standalone Syft & Trivy SBOM Correlation Scanner")
    parser.add_argument("--src", required=True, help="Directory path to scan")
    parser.add_argument("--output", required=True, help="Output path for enriched compliance SBOM")
    
    args = parser.parse_args()
    
    success = run_scanner(args.src, args.output)
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
