import os
import sys
import urllib.request
import zipfile
import subprocess
import shutil

# Config
SBOM_TOOL_URL = "https://github.com/microsoft/sbom-tool/releases/latest/download/sbom-tool-win-x64.exe"
GRYPE_VERSION = "0.79.0"
GRYPE_URL = f"https://github.com/anchore/grype/releases/download/v{GRYPE_VERSION}/grype_{GRYPE_VERSION}_windows_amd64.zip"

MS_SBOM_DIR = os.path.dirname(os.path.abspath(__file__))
BIN_DIR = os.path.join(MS_SBOM_DIR, "bin")

def setup_directories():
    os.makedirs(BIN_DIR, exist_ok=True)

def download_file(url, target_path, name):
    print(f"Downloading {name} from {url}...")
    try:
        req = urllib.request.Request(
            url,
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        )
        with urllib.request.urlopen(req) as response, open(target_path, 'wb') as out_file:
            shutil.copyfileobj(response, out_file)
        print(f"Successfully downloaded {name} to {target_path}")
        return True
    except Exception as e:
        print(f"Error downloading {name}: {e}")
        return False

def copy_or_download_grype():
    target_grype = os.path.join(BIN_DIR, "grype.exe")
    
    # Try to copy from Member 4/bin/grype.exe first
    parent_dir = os.path.dirname(MS_SBOM_DIR)
    member4_grype = os.path.join(parent_dir, "Member 4", "bin", "grype.exe")
    
    if os.path.exists(member4_grype):
        print(f"Found existing Grype at {member4_grype}. Copying...")
        try:
            shutil.copy2(member4_grype, target_grype)
            print("Successfully copied Grype binary.")
            return True
        except Exception as e:
            print(f"Failed to copy Grype: {e}. Will attempt downloading.")
            
    # Fallback to downloading
    zip_path = os.path.join(BIN_DIR, "grype.zip")
    if download_file(GRYPE_URL, zip_path, "Grype Zip Package"):
        print("Extracting Grype...")
        try:
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                found = False
                for file_info in zip_ref.infolist():
                    filename = os.path.basename(file_info.filename)
                    if filename.lower() == "grype.exe":
                        with zip_ref.open(file_info) as source, open(target_grype, "wb") as target:
                            shutil.copyfileobj(source, target)
                        found = True
                        break
                if found:
                    print("Successfully extracted grype.exe")
                    os.remove(zip_path)
                    return True
                else:
                    print("Could not find grype.exe in the zip archive.")
        except Exception as e:
            print(f"Error extracting Grype: {e}")
            if os.path.exists(zip_path):
                os.remove(zip_path)
    return False

def verify_tool(exe_path, args, name):
    if not os.path.exists(exe_path):
        print(f"Error: {name} executable not found at {exe_path}")
        return False
    try:
        res = subprocess.run([exe_path] + args, capture_output=True, text=True, check=True)
        # Handle cases where stdout is empty but stderr contains the version, or just print success
        output = res.stdout.strip() or res.stderr.strip()
        first_line = output.split('\n')[0] if output else "Executed successfully"
        print(f"Verification success: {name} -> {first_line}")
        return True
    except Exception as e:
        print(f"Verification failed for {name}: {e}")
        return False

def main():
    print("Setting up Microsoft SBOM Tool and Grype...")
    setup_directories()
    
    # 1. Download Microsoft SBOM Tool
    sbom_tool_exe = os.path.join(BIN_DIR, "sbom-tool.exe")
    sbom_ok = True
    if not os.path.exists(sbom_tool_exe):
        sbom_ok = download_file(SBOM_TOOL_URL, sbom_tool_exe, "Microsoft SBOM Tool")
    else:
        print("Microsoft SBOM Tool already exists, skipping download.")
        
    # 2. Setup Grype
    grype_ok = True
    grype_exe = os.path.join(BIN_DIR, "grype.exe")
    if not os.path.exists(grype_exe):
        grype_ok = copy_or_download_grype()
    else:
        print("Grype already exists, skipping setup.")
        
    if sbom_ok and grype_ok:
        print("\nVerifying tools...")
        # Microsoft SBOM tool supports 'version' command
        sbom_verify = verify_tool(sbom_tool_exe, ["version"], "Microsoft SBOM Tool")
        grype_verify = verify_tool(grype_exe, ["version"], "Grype")
        
        if sbom_verify and grype_verify:
            print("\nTool setup completed successfully!")
            sys.exit(0)
            
    print("\nSetup failed!")
    sys.exit(1)

if __name__ == "__main__":
    main()
