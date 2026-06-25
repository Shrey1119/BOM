import os
import sys
import argparse
import subprocess

def find_trivy(specified_path=None):
    """Finds the trivy executable."""
    if specified_path:
        if os.path.exists(specified_path):
            return specified_path
        else:
            print(f"Error: Specified Trivy path '{specified_path}' does not exist.")
            sys.exit(1)
            
    # Check current directory / script directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    local_path = os.path.join(script_dir, "trivy.exe")
    if os.path.exists(local_path):
        return local_path
        
    # Check PATH
    try:
        # On Windows, 'where' is used; on Linux/Mac, 'which'
        cmd = "where" if os.name == "nt" else "which"
        subprocess.run([cmd, "trivy"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        return "trivy"
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
        
    print("Error: Trivy executable not found locally or in PATH.")
    print("Please install Trivy or specify its path using --trivy-path.")
    sys.exit(1)

def run_scan(src_dir, output_path, trivy_path):
    """Runs the Trivy scan and outputs CycloneDX JSON."""
    if not os.path.exists(src_dir):
        print(f"Error: Source directory '{src_dir}' does not exist.")
        sys.exit(1)
        
    abs_src = os.path.abspath(src_dir)
    abs_output = os.path.abspath(output_path)
    
    # Ensure output parent directory exists
    output_dir = os.path.dirname(abs_output)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)
        
    print(f"Targeting source code folder: {abs_src}")
    print(f"Using Trivy executable: {trivy_path}")
    print("Executing Trivy vulnerability and dependency scan...")
    
    # Construct Trivy command
    # fs: Scan filesystem
    # --format cyclonedx: Output CycloneDX JSON format
    # --scanners vuln: Explicitly enable vulnerability scanning in the CycloneDX report
    cmd = [
        trivy_path,
        "fs",
        "--format", "cyclonedx",
        "--scanners", "vuln",
        "--output", abs_output,
        abs_src
    ]
    
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        print(f"Scan completed successfully. CycloneDX SBOM saved to: {abs_output}")
        if result.stdout:
            print("Trivy Output:\n", result.stdout)
    except subprocess.CalledProcessError as e:
        print("Error: Trivy execution failed.")
        print("Exit code:", e.returncode)
        print("Standard Output:\n", e.stdout)
        print("Standard Error:\n", e.stderr)
        sys.exit(1)
    except Exception as e:
        print("An unexpected error occurred during scan execution:", e)
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Trivy SBOM Scan Automation Wrapper (Team Member 2)")
    parser.add_argument("--src", required=True, help="Path to the source directory to scan")
    parser.add_argument("--output", default="raw_sbom.json", help="Path to save the generated CycloneDX JSON SBOM (default: raw_sbom.json)")
    parser.add_argument("--trivy-path", help="Path to the Trivy executable (if not in PATH or local directory)")
    
    args = parser.parse_args()
    
    trivy_exe = find_trivy(args.trivy_path)
    run_scan(args.src, args.output, trivy_exe)

if __name__ == "__main__":
    main()
