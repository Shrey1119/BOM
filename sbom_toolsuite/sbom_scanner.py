import os
import sys
import argparse
import subprocess
import urllib.request
import zipfile
import io

def download_trivy(download_dir):
    """Downloads and extracts Trivy CLI v0.71.2 for Windows."""
    url = "https://github.com/aquasecurity/trivy/releases/download/v0.71.2/trivy_0.71.2_Windows-64bit.zip"
    print(f"\n[INFO] Downloading Trivy binary from GitHub releases:\n  {url}")
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=60) as response:
            zip_bytes = response.read()
        
        print("[INFO] Extracting Trivy binary...")
        os.makedirs(download_dir, exist_ok=True)
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
            z.extract("trivy.exe", path=download_dir)
        print("[INFO] Trivy binary downloaded and extracted successfully.\n")
        return os.path.join(download_dir, "trivy.exe")
    except Exception as e:
        print(f"[ERROR] Failed to download or extract Trivy automatically: {e}")
        return None

def is_lfs_pointer(file_path):
    """Checks if a file is a Git LFS pointer instead of a real binary."""
    try:
        with open(file_path, "rb") as f:
            header = f.read(100)
            return header.startswith(b"version https://git-lfs")
    except Exception:
        return False

def find_trivy(specified_path=None):
    """Finds the trivy executable, with automatic LFS fix and download fallback."""
    if specified_path:
        if os.path.exists(specified_path):
            if is_lfs_pointer(specified_path):
                print(f"[WARN] Specified Trivy '{specified_path}' is an LFS pointer.")
                # Fallback to local download in the same directory
                parent_dir = os.path.dirname(os.path.abspath(specified_path))
                fixed_path = download_trivy(parent_dir)
                if fixed_path:
                    return fixed_path
            else:
                return specified_path
        else:
            print(f"Error: Specified Trivy path '{specified_path}' does not exist.")
            sys.exit(1)
            
    # Check script directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    local_path = os.path.join(script_dir, "trivy.exe")
    if os.path.exists(local_path) and not is_lfs_pointer(local_path):
        return local_path
        
    # Check Member 2 directory
    member2_path = os.path.abspath(os.path.join(script_dir, "..", "Member 2", "trivy.exe"))
    if os.path.exists(member2_path) and not is_lfs_pointer(member2_path):
        return member2_path
        
    # If the file exists in Member 2 but is an LFS pointer, download/overwrite it there
    if os.path.exists(member2_path) and is_lfs_pointer(member2_path):
        print("[WARN] Member 2/trivy.exe is a Git LFS pointer (not fully downloaded). Fixing...")
        fixed_path = download_trivy(os.path.dirname(member2_path))
        if fixed_path:
            return fixed_path
            
    # If file exists in script dir but is an LFS pointer, download/overwrite it there
    if os.path.exists(local_path) and is_lfs_pointer(local_path):
        print("[WARN] Local trivy.exe is a Git LFS pointer (not fully downloaded). Fixing...")
        fixed_path = download_trivy(script_dir)
        if fixed_path:
            return fixed_path
            
    # Check PATH
    try:
        cmd = "where" if os.name == "nt" else "which"
        subprocess.run([cmd, "trivy"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        return "trivy"
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
        
    # As a final fallback, download Trivy directly into the Member 2 directory
    print("[WARN] Trivy not found or not working. Downloading a clean copy...")
    fallback_dir = os.path.abspath(os.path.join(script_dir, "..", "Member 2"))
    fixed_path = download_trivy(fallback_dir)
    if fixed_path:
        return fixed_path
        
    print("Error: Trivy executable not found locally, and download failed.")
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
    parser = argparse.ArgumentParser(description="Trivy SBOM Scan Automation Wrapper")
    parser.add_argument("--src", required=True, help="Path to the source directory to scan")
    parser.add_argument("--output", default="sbom_raw.json", help="Path to save the generated CycloneDX JSON SBOM (default: sbom_raw.json)")
    parser.add_argument("--trivy-path", help="Path to the Trivy executable")
    
    args = parser.parse_args()
    
    trivy_exe = find_trivy(args.trivy_path)
    run_scan(args.src, args.output, trivy_exe)

if __name__ == "__main__":
    main()
