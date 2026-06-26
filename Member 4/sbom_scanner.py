import os
import sys
import subprocess
import argparse

# Paths
MEMBER_4_DIR = os.path.dirname(os.path.abspath(__file__))
BIN_DIR = os.path.join(MEMBER_4_DIR, "bin")
SYFT_EXE = os.path.join(BIN_DIR, "syft.exe")
GRYPE_EXE = os.path.join(BIN_DIR, "grype.exe")

ENRICHER_PY = os.path.join(MEMBER_4_DIR, "enricher.py")
VALIDATOR_PY = os.path.join(MEMBER_4_DIR, "validator.py")
CONFIG_JSON = os.path.join(MEMBER_4_DIR, "config.json")

def check_tools():
    if not os.path.exists(SYFT_EXE):
        print(f"Error: {SYFT_EXE} is not found. Please run setup_tools.py first.")
        return False
    if not os.path.exists(GRYPE_EXE):
        print(f"Error: {GRYPE_EXE} is not found. Please run setup_tools.py first.")
        return False
    return True

def run_pipeline(src_dir, output_path):
    if not check_tools():
        return False

    raw_sbom = os.path.join(MEMBER_4_DIR, "sbom_raw.json")
    vulnerable_sbom = os.path.join(MEMBER_4_DIR, "sbom_vulnerable.json")
    
    # Absolute paths
    src_dir_abs = os.path.abspath(src_dir)
    output_path_abs = os.path.abspath(output_path)
    
    # 1. Run Syft Scan
    print(f"\n[Step 1] Running Syft Scan on {src_dir_abs}...")
    syft_cmd = [
        SYFT_EXE,
        f"dir:{src_dir_abs}",
        "-o", f"cyclonedx-json={raw_sbom}"
    ]
    print(f"Executing: {' '.join(syft_cmd)}")
    try:
        res = subprocess.run(syft_cmd, capture_output=True, text=True, check=True)
        print("Syft scan completed successfully.")
        if os.path.exists(raw_sbom):
            size_kb = os.path.getsize(raw_sbom) / 1024
            print(f"Raw SBOM generated: {raw_sbom} ({size_kb:.1f} KB)")
        else:
            print("Error: Syft finished but raw SBOM file was not created.")
            return False
    except subprocess.CalledProcessError as e:
        print(f"Error running Syft: {e.stderr or e.output}")
        return False

    # 2. Run Grype Scan
    print(f"\n[Step 2] Running Grype Vulnerability Scanner...")
    grype_cmd = [
        GRYPE_EXE,
        f"sbom:{raw_sbom}",
        "-o", "cyclonedx-json",
        "--file", vulnerable_sbom
    ]
    print(f"Executing: {' '.join(grype_cmd)}")
    
    # Configure environment variables to bypass Grype DB age constraints (since we run offline/cached)
    grype_env = os.environ.copy()
    grype_env["GRYPE_DB_MAX_ALLOWED_BUILT_AGE"] = "87600h"  # Bypass 5-day db limit (10 years)
    
    try:
        res = subprocess.run(grype_cmd, capture_output=True, text=True, check=True, env=grype_env)
        print("Grype vulnerability injection completed successfully.")
        if os.path.exists(vulnerable_sbom):
            size_kb = os.path.getsize(vulnerable_sbom) / 1024
            print(f"Vulnerable SBOM generated: {vulnerable_sbom} ({size_kb:.1f} KB)")
        else:
            print("Error: Grype finished but vulnerable SBOM file was not created.")
            return False
    except subprocess.CalledProcessError as e:
        print(f"Error running Grype: {e.stderr or e.output}")
        return False

    # 3. Enrich SBOM
    print(f"\n[Step 3] Running Attribute Enricher...")
    enrich_cmd = [
        sys.executable,
        ENRICHER_PY,
        vulnerable_sbom,
        output_path_abs,
        CONFIG_JSON
    ]
    print(f"Executing: {' '.join(enrich_cmd)}")
    try:
        res = subprocess.run(enrich_cmd, capture_output=True, text=True, check=True)
        print(f"Enrichment completed successfully. Enriched file: {output_path_abs}")
    except subprocess.CalledProcessError as e:
        print(f"Error running Enricher: {e.stderr or e.output}")
        return False

    # 4. Validate Enriched SBOM
    print(f"\n[Step 4] Running Compliance Validation...")
    validate_cmd = [
        sys.executable,
        VALIDATOR_PY,
        output_path_abs
    ]
    print(f"Executing: {' '.join(validate_cmd)}")
    try:
        res = subprocess.run(validate_cmd, check=True)
        print("Validation completed successfully. SBOM is fully compliant!")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error running Validator: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Syft & Grype SBOM Compliance Pipeline (Team Member 4)")
    parser.add_argument("--src", required=True, help="Directory path to scan")
    parser.add_argument("--output", required=True, help="Output path for enriched compliance SBOM")
    
    args = parser.parse_args()
    
    success = run_pipeline(args.src, args.output)
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
