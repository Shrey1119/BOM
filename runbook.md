# SBOM Compliance Automation Runbook

This runbook contains step-by-step instructions and copy-pasteable commands for all three roles of the SBOM Compliance Automation Pipeline.

---

## Team Member 2: Tooling & Execution Engineer Runbook

### Role Description
The Tooling & Execution Engineer is responsible for running the initial filesystem scans using **Trivy**, generating the raw CycloneDX JSON metadata, and handling the final cryptographic signing and splitting of the public/private SBOMs.

### Step 1: Run filesystem vulnerability scanner
Execute the `sbom_scanner.py` script located in the `Trivy` directory. This script finds or downloads the local `trivy_cli.exe` binary, scans the target source code, and saves the CycloneDX JSON output.

```powershell
# Command:
python Trivy/sbom_scanner.py --src mock_project --output sbom_raw.json
```

### Step 2: Split and sign the SBOM
Once the SBOM is enriched, you must split it into two files (`sbom_public.json` and `sbom_private.json`) and cryptographically sign them using NIST P-256 ECDSA.

```powershell
# Command:
python Trivy/sbom_distributor.py --sbom sbom_output/restricted/sbom_enriched.json --keys-dir Trivy/keys --output-dir sbom_output
```
*Outputs generated:*
- `sbom_output/sbom_public.json` (Vulnerabilities stripped)
- `sbom_output/sbom_public.json.sig` (Detached public signature)
- `sbom_output/sbom_private.json` (Full vulnerabilities)
- `sbom_output/sbom_private.json.sig` (Detached private signature)

---

## Team Member 3: Compliance & Enrichment Specialist Runbook

### Role Description
The Compliance & Enrichment Specialist is responsible for post-processing the raw SBOM, querying external package registries (like PyPI) to resolve missing lifecycle attributes, and performing compliance checks.

### Step 1: Enrich the SBOM
Pass the raw scanner output through the enricher script. It resolves attributes such as release dates, licenses, end-of-life dates, and unique Package URLs (PURLs).

```powershell
# Command:
python Member 3/enricher.py sbom_raw.json sbom_enriched.json
```

### Step 2: Validate the Enriched SBOM
Perform the 21-attribute compliance check using the validator script.

```powershell
# Command:
python Member 3/validator.py sbom_enriched.json
```
If successful, you will see a validation table and a success message showing zero compliance errors.

---

## Team Member 1: Security & Governance Lead Runbook

### Role Description
The Security & Governance Lead is responsible for vulnerability management, generating VEX and CSAF advisory documents, building internal component records, and organizing the outputs into access-controlled storage directories.

### Step 1: Generate VEX & CSAF Documents
Compile the Vulnerability Exploitability eXchange (VEX) statuses and Common Security Advisory Framework (CSAF) advisories for the client.

```powershell
# Command:
python sbom_toolsuite/vex_csaf_generator.py
```
*Outputs generated:*
- `sbom_output/vex.json`
- `sbom_output/csaf.json`

### Step 2: Compile Internal Governance Mapping
Generate the internal governance component mapping tracking all active packages.

```powershell
# Command:
python sbom_toolsuite/build_internal_map.py
```
*Outputs generated:*
- `sbom_output/internal_map.json`

### Step 3: Render Vulnerability HTML Report
Generate the styled human-readable HTML vulnerability scan report.

```powershell
# Command:
Trivy/trivy_cli.exe fs --format template --template "@Trivy/contrib/html.tpl" --output sbom_output/report.html mock_project
```

### Step 4: Organize and Secure Storage
Structure the generated deliverables into their corresponding compliance folders:
- **`sbom_output/public`**: Safe for external sharing (public keys, public SBOM, excel report, html report).
- **`sbom_output/restricted`**: Confidential security assets (private keys, private SBOM, VEX JSON).
- **`sbom_output/internal`**: Internal governance tools (CSAF advisory, internal map, triage JSON).

---

## Unified Automation: Running the Pipeline in One Go

For convenience, you can run the entire multi-role pipeline from the root directory using the interactive CLI menu or by supplying command-line arguments:

```powershell
# Run the complete pipeline via CLI:
python run_pipeline.py -s mock_project -a
```
This single command triggers the scanner, enricher, validator, distributor, VEX/CSAF generator, internal governance mapper, and Excel/HTML exporters sequentially, depositing organized files directly into the `sbom_output/` compliance folder.
