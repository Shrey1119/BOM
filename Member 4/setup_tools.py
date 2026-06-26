import os
import sys
import urllib.request
import zipfile
import subprocess
import shutil

# Config
SYFT_VERSION = "1.3.0"
GRYPE_VERSION = "0.79.0"

SYFT_URL = f"https://github.com/anchore/syft/releases/download/v{SYFT_VERSION}/syft_{SYFT_VERSION}_windows_amd64.zip"
GRYPE_URL = f"https://github.com/anchore/grype/releases/download/v{GRYPE_VERSION}/grype_{GRYPE_VERSION}_windows_amd64.zip"

MEMBER_4_DIR = os.path.dirname(os.path.abspath(__file__))
BIN_DIR = os.path.join(MEMBER_4_DIR, "bin")

def download_and_extract(url, name, exe_name):
    os.makedirs(BIN_DIR, exist_ok=True)
    zip_path = os.path.join(BIN_DIR, f"{name}.zip")
    
    print(f"Downloading {name} from {url}...")
    try:
        req = urllib.request.Request(
            url, 
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        )
        with urllib.request.urlopen(req) as response, open(zip_path, 'wb') as out_file:
            shutil.copyfileobj(response, out_file)
        print(f"Successfully downloaded {name} to {zip_path}")
    except Exception as e:
        print(f"Error downloading {name}: {e}")
        return False
        
    print(f"Extracting {name}...")
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            found = False
            for file_info in zip_ref.infolist():
                filename = os.path.basename(file_info.filename)
                if filename.lower() == exe_name.lower():
                    # Extract to BIN_DIR
                    with zip_ref.open(file_info) as source, open(os.path.join(BIN_DIR, exe_name), "wb") as target:
                        shutil.copyfileobj(source, target)
                    found = True
                    break
            
            if not found:
                print(f"Could not find {exe_name} in Zip package.")
                return False
        
        # Clean up zip
        os.remove(zip_path)
        
        exe_path = os.path.join(BIN_DIR, exe_name)
        if os.path.exists(exe_path):
            print(f"Successfully extracted {exe_name} to {exe_path}")
            return True
        else:
            print(f"Could not find {exe_name} after extraction.")
            return False
    except Exception as e:
        print(f"Error extracting {name}: {e}")
        return False

def verify_tool(exe_name):
    exe_path = os.path.join(BIN_DIR, exe_name)
    if not os.path.exists(exe_path):
        print(f"{exe_name} is missing.")
        return False
        
    try:
        res = subprocess.run([exe_path, "--version"], capture_output=True, text=True, check=True)
        print(f"Verification success: {exe_name} -> {res.stdout.strip()}")
        return True
    except Exception as e:
        print(f"Verification failed for {exe_name}: {e}")
        return False

def main():
    print("Setting up compliance tools...")
    syft_ok = download_and_extract(SYFT_URL, "syft", "syft.exe")
    grype_ok = download_and_extract(GRYPE_URL, "grype", "grype.exe")
    
    if syft_ok and grype_ok:
        print("\nVerifying tools...")
        syft_verify = verify_tool("syft.exe")
        grype_verify = verify_tool("grype.exe")
        if syft_verify and grype_verify:
            print("\nSetup completed successfully!")
            sys.exit(0)
    
    print("\nSetup failed!")
    sys.exit(1)

if __name__ == "__main__":
    main()
