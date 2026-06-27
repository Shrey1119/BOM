# SBOM Compliance Automation Tasks

## Phase 1: Setup and Mock Workspace
- [x] Create mock source code directory `mock_project/` with typical dependencies (some vulnerable, e.g., standard packages) to test the scanner.
- [x] Configure `sbom_toolsuite/config.json` with default values and enrichment schemas for the 21 client attributes.

## Phase 2: SBOM Generation & Enrichment (Tooling)
- [x] Implement `sbom_toolsuite/sbom_scanner.py` to run Trivy and generate baseline CycloneDX JSON.
- [x] Implement `sbom_toolsuite/sbom_enricher.py` to query external package databases and inject the 21 client attributes (licenses, EOL dates, release dates, purls, etc.).
- [x] Implement `sbom_toolsuite/validate_sbom.py` to verify the 21 attributes for all components.

## Phase 3: Vulnerability Management & Distribution
- [x] Implement `sbom_toolsuite/vex_csaf_generator.py` to compile VEX status and CSAF advisory.
- [x] Implement `sbom_toolsuite/sbom_distributor.py` to split the SBOM into Public and Private files and cryptographically sign them (ECDSA signature files).

## Phase 4: Runbook and Verification
- [x] Write `runbook.md` with step-by-step copy-paste instructions divided for the 3 Team Members.
- [x] Run the automated verification against `mock_project/`.
- [x] Create the final walkthrough.md artifact.
