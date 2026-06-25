# Team Member 2 Runbook: Tooling & Execution Engineer

This runbook describes the detailed execution steps, commands, and script usages for **Team Member 2 (Tooling & Execution Engineer)**.

## Core Responsibilities
1. **Tool Setup**: Deploy and configure the Trivy CLI in the target scanning environment.
2. **Vulnerability & Metadata Scanning**: Execute fs scans on target folders to generate raw CycloneDX JSON SBOMs.
3. **Split & Sign Distribution**: Segment the finalized SBOM into Public and Private versions, generate ECDSA cryptographic keys, and sign both documents to ensure data integrity.

---

## Step 1: Deploy Trivy CLI

We download and install Trivy CLI locally (stored in the same directory as the scripts) to prevent the need for administrator privileges.

### CLI Check
To verify that Trivy CLI is operational, run:
```powershell
.\trivy.exe --version
```
*Expected output:*
```text
Version: 0.71.2
```

---

## Step 2: Execute Dependency & Vulnerability Scan

Use the automated `sbom_scanner.py` wrapper to invoke Trivy. This scans the target folder, fetches the latest vulnerability database, and outputs a compliant CycloneDX JSON SBOM.

### Command Format
```powershell
python sbom_scanner.py --src <source_directory_path> --output <output_json_path> [--trivy-path <path_to_trivy_exe>]
```

### Running Against Mock Project
To test the scanner locally:
```powershell
python sbom_scanner.py --src .\mock_project --output .\raw_sbom.json
```

*What this command does:*
1. Resolves the path to the `trivy.exe` binary.
2. Invokes Trivy with structural metadata extraction and vulnerability scanners enabled (`trivy fs --format cyclonedx --scanners vuln ...`).
3. Saves the generated CycloneDX JSON SBOM containing 22 vulnerabilities to `raw_sbom.json`.

---

## Step 3: Splitting and Cryptographically Signing the SBOM

Use the automated `sbom_distributor.py` to securely distribute the SBOMs by separating public details from internal vulnerabilities and signing both documents using NIST P-256 ECDSA keys.

### Command Format
```powershell
python sbom_distributor.py --sbom <raw_or_enriched_sbom_path> --keys-dir <keys_output_directory> --output-dir <final_distribution_directory>
```

### Execution Example
```powershell
python sbom_distributor.py --sbom .\raw_sbom.json --keys-dir .\keys --output-dir .
```

*What this command does:*
1. Checks for existing keys in the `.\keys` directory. If not present, it generates a fresh ECDSA NIST P-256 key pair (`private_key.pem` and `public_key.pem`).
2. Splits the input SBOM into two new files:
   - **`sbom_public.json`**: All vulnerability details are completely stripped (removing the root `vulnerabilities` array and custom internal properties).
   - **`sbom_private.json`**: Retains all vulnerabilities and security metadata.
3. Canonicalizes both JSON files to ensure a stable representation.
4. Cryptographically signs the canonical bytes using the private key.
5. Embeds the base64-encoded signature directly within the JSON structures (under `metadata.properties` and the top-level `signature` block) for simple verification.
6. Writes detached signature files (`sbom_public.json.sig` and `sbom_private.json.sig`) for validation by external tools.

---

## Verification & Validation Checklist

Before passing the outputs to downstream members:
1. Verify that `keys/private_key.pem` is kept secure and not shared.
2. Verify that `keys/public_key.pem` is shared with the client or verifier.
3. Check that `sbom_public.json` has `Public vuln count: 0` using:
   ```powershell
   python -c "import json; d=json.load(open('sbom_public.json')); print('Vulns:', len(d.get('vulnerabilities', [])))"
   ```
4. Verify signature validity: The distributor automatically asserts signature matches right after signing.
