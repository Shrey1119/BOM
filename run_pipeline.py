import os
import sys
import shutil
import subprocess
import datetime
import json
import hashlib

def print_header(title):
    print("\n" + "=" * 80)
    print(f" {title.upper()} ".center(80, "="))
    print("=" * 80 + "\n")

def run_command(cmd, desc):
    print(f"[*] Running: {desc}...")
    try:
        result = subprocess.run(cmd, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.stdout:
            print(result.stdout.strip())
        return True
    except subprocess.CalledProcessError as e:
        print(f"\n[!] Error: {desc} failed.")
        print(f"Command: {e.cmd}")
        print(f"Exit Code: {e.returncode}")
        print(f"Output: {e.stdout}")
        print(f"Error Output: {e.stderr}")
        return False
    except Exception as e:
        print(f"\n[!] Unexpected error executing {desc}: {e}")
        return False

def setup_directories():
    print("[*] Creating output directory tiers (restricted, internal, public)...")
    os.makedirs('sbom_output/restricted', exist_ok=True)
    os.makedirs('sbom_output/internal', exist_ok=True)
    os.makedirs('sbom_output/public', exist_ok=True)

def encrypt_tier1_files(passphrase_bytes):
    print("\n[*] Encrypting Tier 1 (restricted) files with AES-256-GCM...")
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        key = passphrase_bytes[:32].ljust(32, b'0')  # 256-bit key
        aesgcm = AESGCM(key)
        
        target_files = [
            'sbom_output/restricted/sbom_private.json',
            'sbom_output/restricted/vex.json',
            'sbom_output/restricted/sbom_enriched.json'
        ]
        
        for fname in target_files:
            if os.path.exists(fname):
                nonce = os.urandom(12)
                with open(fname, 'rb') as f:
                    data = f.read()
                ct = aesgcm.encrypt(nonce, data, None)
                with open(fname + '.enc', 'wb') as f:
                    f.write(nonce + ct)
                os.remove(fname)
                print(f"  [encrypted] {fname} -> {fname}.enc")
            else:
                print(f"  [skipped] {fname} (not found)")
        print("[+] Tier 1 encryption completed successfully.")
    except ImportError:
        print("[!] Warning: 'cryptography' library is missing. Skipping encryption.")
    except Exception as e:
        print(f"[!] Error during encryption: {e}")

def organize_outputs():
    print("\n[*] Organizing files into compliance storage tiers...")
    
    # Mapping of source path to destination path
    moves = {
        'sbom_output/sbom_private.json':      'sbom_output/restricted/sbom_private.json',
        'sbom_output/sbom_private.json.sig':  'sbom_output/restricted/sbom_private.json.sig',
        'sbom_output/vex.json':               'sbom_output/restricted/vex.json',
        'sbom_enriched.json':                  'sbom_output/restricted/sbom_enriched.json',
        'sbom_output/internal_map.json':      'sbom_output/internal/internal_map.json',
        'sbom_output/csaf.json':              'sbom_output/internal/csaf.json',
        'sbom_output/sbom_public.json':       'sbom_output/public/sbom_public.json',
        'sbom_output/sbom_public.json.sig':   'sbom_output/public/sbom_public.json.sig',
        'sbom_output/report.html':            'sbom_output/public/report.html',
    }
    
    # Copies (non-destructive)
    copies = {
        'Member 2/keys/private_key.pem': 'sbom_output/restricted/private_key.pem',
        'Member 2/keys/public_key.pem':  'sbom_output/public/public_key.pem',
        'sbom_toolsuite/triage.json':    'sbom_output/internal/triage.json',
    }

    for src, dst in moves.items():
        if os.path.exists(src):
            if os.path.exists(dst):
                os.remove(dst)
            shutil.move(src, dst)
            print(f"  [moved]  {src} -> {dst}")
            
    for src, dst in copies.items():
        if os.path.exists(src):
            shutil.copy2(src, dst)
            print(f"  [copied] {src} -> {dst}")

def print_final_status():
    print_header("Pipeline Execution Status")
    
    print("Tier 1: Restricted Storage (Confidential / Core Security)")
    for f in os.listdir('sbom_output/restricted'):
        path = os.path.join('sbom_output/restricted', f)
        print(f"  [RESTRICTED] {path:<50} ({os.path.getsize(path)} bytes)")
        
    print("\nTier 2: Internal Governance Storage (Operations & Vulnerabilities)")
    for f in os.listdir('sbom_output/internal'):
        path = os.path.join('sbom_output/internal', f)
        print(f"  [INTERNAL]   {path:<50} ({os.path.getsize(path)} bytes)")
        
    print("\nTier 3: Public / Stakeholder Storage (Shared Assets)")
    for f in os.listdir('sbom_output/public'):
        path = os.path.join('sbom_output/public', f)
        print(f"  [PUBLIC]     {path:<50} ({os.path.getsize(path)} bytes)")
        
    print("\n[+] Final deliverables are compiled and verified successfully!")

def main():
    print_header("SBOM Automation Pipeline")
    
    # Step 1: Directory Setup
    setup_directories()
    
    # Step 2: Trivy Scanning
    trivy_exe = "Member 2/trivy.exe"
    if not os.path.exists(trivy_exe):
        trivy_exe = "trivy"
        
    print("\n--- Step 2: Running Trivy Scan ---")
    scan_cmd = f'python "Member 2/sbom_scanner.py" --src mock_project --output sbom_raw.json --trivy-path "{trivy_exe}"'
    if not run_command(scan_cmd, "Trivy Scanner"):
        sys.exit(1)
        
    # Step 3: Enrichment
    print("\n--- Step 3: Enriching SBOM (21 Attributes) ---")
    enrich_cmd = 'python "Member 3/enricher.py" sbom_raw.json sbom_enriched.json'
    if not run_command(enrich_cmd, "SBOM Enricher"):
        sys.exit(1)
        
    # Step 4: Validation
    print("\n--- Step 4: Validating Enriched SBOM ---")
    validate_cmd = 'python "Member 3/validator.py" sbom_enriched.json'
    if not run_command(validate_cmd, "SBOM Validator"):
        sys.exit(1)
        
    # Step 5: Split & Sign
    print("\n--- Step 5: Splitting & Cryptographically Signing SBOM ---")
    dist_cmd = 'python "Member 2/sbom_distributor.py" --sbom sbom_enriched.json --keys-dir "Member 2/keys" --output-dir sbom_output'
    if not run_command(dist_cmd, "SBOM Split & Sign"):
        sys.exit(1)
        
    # Step 6: VEX & CSAF Generation
    print("\n--- Step 6: Generating VEX and CSAF Advisory ---")
    vex_cmd = 'python sbom_toolsuite/vex_csaf_generator.py'
    if not run_command(vex_cmd, "VEX & CSAF Generator"):
        sys.exit(1)
        
    # Step 7: Internal Mapping
    print("\n--- Step 7: Generating Internal Governance Map ---")
    map_cmd = 'python sbom_toolsuite/build_internal_map.py'
    if not run_command(map_cmd, "Internal Component Mapper"):
        sys.exit(1)
        
    # Step 8: HTML Scan Report
    print("\n--- Step 8: Generating Human-Readable HTML Report ---")
    html_cmd = f'"{trivy_exe}" fs --format template --template "@Member 2/contrib/html.tpl" --output sbom_output/report.html mock_project'
    if not run_command(html_cmd, "Trivy HTML Report Generator"):
        sys.exit(1)
        
    # Step 9: Organize Tiers
    organize_outputs()
    
    # Step 10: Optional GCM Encryption for restricted files
    passphrase = os.environ.get('SBOM_ENC_KEY')
    if passphrase:
        encrypt_tier1_files(passphrase.encode('utf-8'))
    else:
        print("\n[i] SBOM_ENC_KEY env variable not set. Restricted files left decrypted.")
        
    # Step 11: Print report status
    print_final_status()

if __name__ == "__main__":
    main()
