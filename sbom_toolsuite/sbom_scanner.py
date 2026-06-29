import os
import sys
import argparse
import subprocess
import urllib.request
import zipfile
import io
import shutil

# Root directories relative to script
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(SCRIPT_DIR)

# Default path constants
SYFT_EXE_DEFAULT = os.path.join(PARENT_DIR, "Member 4", "bin", "syft.exe")
GRYPE_EXE_DEFAULT = os.path.join(PARENT_DIR, "Member 4", "bin", "grype.exe")
TRIVY_EXE_DEFAULT = os.path.join(PARENT_DIR, "Trivy", "trivy_cli.exe")

def is_lfs_pointer(file_path):
    """Checks if a file is a Git LFS pointer instead of a real binary."""
    if not os.path.exists(file_path):
        return False
    try:
        with open(file_path, "rb") as f:
            header = f.read(100)
            return header.startswith(b"version https://git-lfs")
    except Exception:
        return False

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
            extracted_path = os.path.join(download_dir, "trivy.exe")
            target_path = os.path.join(download_dir, "trivy_cli.exe")
            if os.path.exists(target_path):
                os.remove(target_path)
            os.rename(extracted_path, target_path)
        print("[INFO] Trivy binary downloaded and extracted successfully.\n")
        return target_path
    except Exception as e:
        print(f"[ERROR] Failed to download or extract Trivy automatically: {e}")
        return None

def find_trivy(specified_path=None):
    """Finds the trivy executable, with automatic LFS fix and download fallback."""
    if specified_path:
        if os.path.exists(specified_path):
            if is_lfs_pointer(specified_path):
                print(f"[WARN] Specified Trivy '{specified_path}' is an LFS pointer. Fixing...")
                fixed_path = download_trivy(os.path.dirname(os.path.abspath(specified_path)))
                if fixed_path:
                    return fixed_path
            else:
                return specified_path
        else:
            print(f"Error: Specified Trivy path '{specified_path}' does not exist.")
            sys.exit(1)

    if os.path.exists(TRIVY_EXE_DEFAULT) and not is_lfs_pointer(TRIVY_EXE_DEFAULT):
        return TRIVY_EXE_DEFAULT

    if os.path.exists(TRIVY_EXE_DEFAULT) and is_lfs_pointer(TRIVY_EXE_DEFAULT):
        fixed_path = download_trivy(os.path.dirname(TRIVY_EXE_DEFAULT))
        if fixed_path:
            return fixed_path

    # Check PATH
    try:
        cmd = "where" if os.name == "nt" else "which"
        subprocess.run([cmd, "trivy"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        return "trivy"
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass

    print("[WARN] Trivy not found. Downloading a clean copy...")
    fixed_path = download_trivy(os.path.join(PARENT_DIR, "Trivy"))
    if fixed_path:
        return fixed_path

    print("Error: Trivy executable not found locally, and download failed.")
    sys.exit(1)

def find_binary(path_default, name):
    """Generic lookup helper for Syft/Grype binaries."""
    if os.path.exists(path_default) and not is_lfs_pointer(path_default):
        return path_default
    
    # Try system PATH
    try:
        cmd = "where" if os.name == "nt" else "which"
        subprocess.run([cmd, name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        return name
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass

    print(f"Error: Required binary '{name}' not found at default path '{path_default}' or in PATH.")
    sys.exit(1)

def run_scans(src_dir, syft_grype_out, trivy_out, cdxgen_out, trivy_path):
    """Runs the 3 scans (Syft+Grype, Trivy fs, and cdxgen with reachability)."""
    abs_src = os.path.abspath(src_dir)
    abs_syft_grype = os.path.abspath(syft_grype_out)
    abs_trivy = os.path.abspath(trivy_out)
    abs_cdxgen = os.path.abspath(cdxgen_out)

    syft_exe = find_binary(SYFT_EXE_DEFAULT, "syft")
    grype_exe = find_binary(GRYPE_EXE_DEFAULT, "grype")

    # Ensure parent output directory exists
    os.makedirs(os.path.dirname(abs_syft_grype), exist_ok=True)

    print(f"\nTargeting source folder: {abs_src}")

    # ==========================================================
    # Step 1: Deep Binary Parsing with Syft + Grype
    # ==========================================================
    temp_syft_raw = os.path.join(SCRIPT_DIR, "syft_raw_temp.json")
    print(f"\n[Step 1/3] Running Syft scan on {abs_src}...")
    syft_cmd = [
        syft_exe,
        "scan",
        f"dir:{abs_src}",
        "-o", "cyclonedx-json"
    ]
    try:
        with open(temp_syft_raw, 'w', encoding='utf-8') as f_out:
            subprocess.run(syft_cmd, stdout=f_out, stderr=subprocess.PIPE, text=True, check=True)
        print("Syft scan completed. Injecting vulnerabilities with Grype...")
        
        grype_cmd = [
            grype_exe,
            f"sbom:{temp_syft_raw}",
            "-o", "cyclonedx-json",
            "--file", abs_syft_grype
        ]
        grype_env = os.environ.copy()
        grype_env["GRYPE_DB_MAX_ALLOWED_BUILT_AGE"] = "87600h"  # Bypass age limit
        subprocess.run(grype_cmd, capture_output=True, text=True, check=True, env=grype_env)
        print(f"Syft + Grype output generated: {abs_syft_grype}")
    except subprocess.CalledProcessError as e:
        print(f"Error during Syft + Grype phase: {e.stderr or e}")
        return False
    finally:
        if os.path.exists(temp_syft_raw):
            os.remove(temp_syft_raw)

    # ==========================================================
    # Step 2: Unified Security Triage with Trivy
    # ==========================================================
    print(f"\n[Step 2/3] Running Trivy vulnerability, config & secret scan on {abs_src}...")
    trivy_cmd = [
        trivy_path,
        "fs",
        "--format", "cyclonedx",
        "--scanners", "vuln,config,secret",
        "--output", abs_trivy,
        abs_src
    ]
    try:
        subprocess.run(trivy_cmd, capture_output=True, text=True, check=True)
        print(f"Trivy scan completed. Output generated: {abs_trivy}")
    except subprocess.CalledProcessError as e:
        print(f"Error during Trivy phase: {e.stderr or e}")
        return False

    # ==========================================================
    # Step 3: Reachability Analysis with cdxgen
    # ==========================================================
    print(f"\n[Step 3/3] Running cdxgen in deep mode (with reachables) on {abs_src}...")
    # Executing outside target directory (no cwd=abs_src) to bypass EBADDEVENGINES package manager version errors
    cdxgen_cmd = 'npx @cyclonedx/cdxgen -r --spec-version 1.5 --with-reachables -o "{}" "{}"'.format(abs_cdxgen, abs_src)
    try:
        subprocess.run(cdxgen_cmd, capture_output=True, text=True, check=True, shell=True)
        if os.path.exists(abs_cdxgen):
            print(f"cdxgen scan completed. Output generated: {abs_cdxgen}")
        else:
            print("Error: cdxgen completed but output file was not created.")
            return False
    except subprocess.CalledProcessError as e:
        print(f"Error during cdxgen phase: {e.stderr or e.output}")
        return False

    return True

def main():
    parser = argparse.ArgumentParser(description="Multi-Scanner SBOM Orchestration Wrapper")
    parser.add_argument("--src", required=True, help="Path to the source directory to scan")
    parser.add_argument("--syft-grype", default="syft_grype.json", help="Output path for Syft+Grype CycloneDX")
    parser.add_argument("--trivy", default="trivy_raw.json", help="Output path for Trivy CycloneDX")
    parser.add_argument("--cdxgen", default="cdxgen_raw.json", help="Output path for cdxgen CycloneDX")
    parser.add_argument("--trivy-path", help="Path to the Trivy executable")
    
    args = parser.parse_args()
    
    trivy_exe = find_trivy(args.trivy_path)
    success = run_scans(args.src, args.syft_grype, args.trivy, args.cdxgen, trivy_exe)
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
