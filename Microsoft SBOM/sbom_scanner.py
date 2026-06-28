import os
import sys
import subprocess
import argparse
import shutil

# Paths
MS_SBOM_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(MS_SBOM_DIR)

BIN_DIR = os.path.join(MS_SBOM_DIR, "bin")
SBOM_TOOL_EXE = os.path.join(BIN_DIR, "sbom-tool.exe")
GRYPE_EXE = os.path.join(BIN_DIR, "grype.exe")

ENRICHER_PY = os.path.join(MS_SBOM_DIR, "enricher.py")
VALIDATOR_PY = os.path.join(MS_SBOM_DIR, "validator.py")
CONFIG_JSON = os.path.join(MS_SBOM_DIR, "config.json")

def check_tools():
    if not os.path.exists(SBOM_TOOL_EXE) or not os.path.exists(GRYPE_EXE):
        print("Error: Required tools are missing in bin directory. Please run setup_tools.py first.")
        return False
    return True

def run_pipeline(src_dir, output_path):
    if not check_tools():
        return False

    raw_sbom = os.path.join(MS_SBOM_DIR, "sbom_raw.json")
    vulnerable_sbom = os.path.join(MS_SBOM_DIR, "sbom_vulnerable.json")
    
    src_dir_abs = os.path.abspath(src_dir)
    output_path_abs = os.path.abspath(output_path)
    
    # 1. Run Microsoft SBOM tool
    print(f"\n[Step 1] Running Microsoft SBOM tool on {src_dir_abs}...")
    
    # Run the generate subcommand. We point build drop path (-b) and build components path (-bc) to src_dir
    # We pass -D true to auto-delete previous manifest directory
    # Package details are passed with unique namespace
    sbom_cmd = [
        SBOM_TOOL_EXE,
        "generate",
        "-b", src_dir_abs,
        "-bc", src_dir_abs,
        "-pn", "Microsoft_SBOM_Output",
        "-pv", "1.0.0",
        "-ps", "Internal_Dev",
        "-nsb", "https://company.internal/sbom",
        "-D", "true"
    ]
    print(f"Executing: {' '.join(sbom_cmd)}")
    
    try:
        res = subprocess.run(sbom_cmd, capture_output=True, text=True, check=True)
        print("Microsoft SBOM generation run completed.")
        
        # The tool generates manifest in <src_dir>/_manifest/spdx_2.2/manifest.spdx.json
        expected_manifest = os.path.join(src_dir_abs, "_manifest", "spdx_2.2", "manifest.spdx.json")
        
        if os.path.exists(expected_manifest):
            # Copy to raw_sbom
            shutil.copy2(expected_manifest, raw_sbom)
            print("Successfully retrieved raw SPDX SBOM.")
            
            # Clean up the generated _manifest folder in target directory
            manifest_dir = os.path.join(src_dir_abs, "_manifest")
            try:
                shutil.rmtree(manifest_dir)
                print("Cleaned up temporary _manifest folder from scan target.")
            except Exception as e:
                print(f"Warning: Could not remove temporary _manifest folder: {e}")
                
            size_kb = os.path.getsize(raw_sbom) / 1024
            print(f"Raw SPDX SBOM generated: {raw_sbom} ({size_kb:.1f} KB)")
        else:
            print(f"Error: Raw SPDX SBOM file was not created at {expected_manifest}")
            print(f"Stdout:\n{res.stdout}\nStderr:\n{res.stderr}")
            return False
            
    except subprocess.CalledProcessError as e:
        print(f"Error running Microsoft SBOM tool: {e.stderr or e.output or e}")
        return False

    # 2. Run Grype Scan (Takes SPDX SBOM input, outputs CycloneDX JSON)
    print(f"\n[Step 2] Running Grype Vulnerability Scanner...")
    grype_cmd = [
        GRYPE_EXE,
        f"sbom:{raw_sbom}",
        "-o", "cyclonedx-json",
        "--file", vulnerable_sbom
    ]
    print(f"Executing: {' '.join(grype_cmd)}")
    
    grype_env = os.environ.copy()
    grype_env["GRYPE_DB_MAX_ALLOWED_BUILT_AGE"] = "87600h"  # Bypass database limit
    
    try:
        subprocess.run(grype_cmd, capture_output=True, text=True, check=True, env=grype_env)
        print("Grype vulnerability scan completed successfully.")
        if os.path.exists(vulnerable_sbom):
            size_kb = os.path.getsize(vulnerable_sbom) / 1024
            print(f"Vulnerable SBOM (CycloneDX format) generated: {vulnerable_sbom} ({size_kb:.1f} KB)")
        else:
            print("Error: Grype finished but vulnerable SBOM file was not created.")
            return False
    except subprocess.CalledProcessError as e:
        print(f"Error running Grype: {e.stderr or e.output or e}")
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
        print(f"Error running Enricher: {e.stderr or e.output or e}")
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
    parser = argparse.ArgumentParser(description="Microsoft SBOM Compliance Pipeline")
    parser.add_argument("--src", required=True, help="Directory path to scan")
    parser.add_argument("--output", required=True, help="Output path for enriched compliance SBOM")
    
    args = parser.parse_args()
    
    success = run_pipeline(args.src, args.output)
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
