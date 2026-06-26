import os
import sys
import subprocess
import argparse
import shutil

# Paths
CDXGEN_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(CDXGEN_DIR)

# Reuse portable grype from Member 4/bin
MEMBER_4_BIN = os.path.join(PARENT_DIR, "Member 4", "bin")
GRYPE_EXE = os.path.join(MEMBER_4_BIN, "grype.exe")

ENRICHER_PY = os.path.join(CDXGEN_DIR, "enricher.py")
VALIDATOR_PY = os.path.join(CDXGEN_DIR, "validator.py")
CONFIG_JSON = os.path.join(CDXGEN_DIR, "config.json")

def check_tools():
    # Verify node/npx is installed
    try:
        subprocess.run(["node", "-v"], capture_output=True, check=True)
    except Exception:
        print("Error: Node.js is not found. Please install Node.js first.")
        return False
        
    if not os.path.exists(GRYPE_EXE):
        print(f"Error: {GRYPE_EXE} is not found. Please run setup_tools.py in Member 4 folder first.")
        return False
    return True

def run_pipeline(src_dir, output_path):
    if not check_tools():
        return False

    raw_sbom = os.path.join(CDXGEN_DIR, "sbom_raw.json")
    vulnerable_sbom = os.path.join(CDXGEN_DIR, "sbom_vulnerable.json")
    
    src_dir_abs = os.path.abspath(src_dir)
    output_path_abs = os.path.abspath(output_path)
    
    # Define temporary file in target src_dir to prevent spaces in cdxgen CLI arguments
    temp_raw_filename = "sbom_raw_temp.json"
    temp_raw_path = os.path.join(src_dir_abs, temp_raw_filename)
    
    # 1. Run cdxgen
    print(f"\n[Step 1] Running cdxgen on {src_dir_abs}...")
    # Run cdxgen via npx inside target directory to bypass space-in-path bugs
    cdxgen_cmd = [
        "npx",
        "@cyclonedx/cdxgen",
        "-r", # Recursive scan
        "--spec-version", "1.5",
        "-o", temp_raw_filename
    ]
    print(f"Executing: {' '.join(cdxgen_cmd)} (inside {src_dir_abs})")
    
    try:
        # Run process inside target directory
        subprocess.run(cdxgen_cmd, cwd=src_dir_abs, capture_output=True, text=True, check=True, shell=True)
        
        # Move temp raw file to cdxgen/sbom_raw.json
        if os.path.exists(temp_raw_path):
            shutil.move(temp_raw_path, raw_sbom)
            print("cdxgen scan completed successfully.")
            size_kb = os.path.getsize(raw_sbom) / 1024
            print(f"Raw SBOM generated: {raw_sbom} ({size_kb:.1f} KB)")
        else:
            print("Error: cdxgen finished but raw SBOM file was not created.")
            return False
    except subprocess.CalledProcessError as e:
        print(f"Error running cdxgen: {e.stderr or e.output}")
        # Clean up if temp file created
        if os.path.exists(temp_raw_path):
            os.remove(temp_raw_path)
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
    
    grype_env = os.environ.copy()
    grype_env["GRYPE_DB_MAX_ALLOWED_BUILT_AGE"] = "87600h"  # Bypass 5-day db limit
    
    try:
        subprocess.run(grype_cmd, capture_output=True, text=True, check=True, env=grype_env)
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
        subprocess.run(enrich_cmd, capture_output=True, text=True, check=True)
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
        subprocess.run(validate_cmd, check=True)
        print("Validation completed successfully. SBOM is fully compliant!")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error running Validator: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description="cdxgen SBOM Compliance Pipeline")
    parser.add_argument("--src", required=True, help="Directory path to scan")
    parser.add_argument("--output", required=True, help="Output path for enriched compliance SBOM")
    
    args = parser.parse_args()
    
    success = run_pipeline(args.src, args.output)
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
