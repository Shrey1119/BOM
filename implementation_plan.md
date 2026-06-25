# SBOM and CBOM Compliance Automation Plan

This implementation plan defines the structure, design, and steps to build a complete, automated tool suite (`sbom_toolsuite`) and a detailed, copy-pasteable execution runbook (`runbook.md`) for the Agent AI. The goal is to scan a client's source code, generate fully compliant SBOM and CBOM documents, manage vulnerabilities via VEX/CSAF, split files into Public/Private versions, sign them, and validate them against both the client's 21 attributes and CERT-In Technical Guidelines.

---

## Goal Description
Convert the high-level tasks in [phase.txt](file:///d:/College%20Work/Internship/BOM/phase.txt) into a production-grade, script-driven tool suite and a step-by-step execution guide. This will enable any Agent AI or developer to act as one of the three team members to execute their designated tasks:
1. Scan source code using **Trivy** for vulnerabilities and package metadata.
2. Analyze code for cryptographic components (algorithms, protocols, keys, certificates) to generate a **CBOM** compliant with CERT-In Chapter 8 guidelines.
3. Post-process the SBOM to enrich it with all **21 client attributes** (including release dates, EOL, suppliers, licenses, and PURLs).
4. Automate **VEX & CSAF** vulnerability assessment documents.
5. Implement secure distribution by splitting the SBOM into **Public** (no vulnerabilities, no private keys/secrets) and **Private** (detailed vulnerabilities and internal configurations) files, and **cryptographically sign** them.
6. Validate all generated documents for schema completeness and compliance.

---

## User Review Required

> [!IMPORTANT]
> **Team Division & Runbook Structure**
> The runbook will be split into **three distinct role-based modules**, each detailing the precise copy-pasteable commands and scripts required:
> 1. **Team Member 1 (Security & Governance Lead Runbook)**:
>    - Configuration of security policies and public/private keys.
>    - Internal mapping compilation.
>    - Generating VEX (Vulnerability Exploitability eXchange) and CSAF advisories.
>    - Secure storage integration guidelines.
> 2. **Team Member 2 (Tooling & Execution Engineer Runbook)**:
>    - Installation and configuration of Trivy CLI.
>    - Execution of source code scans for metadata and vulnerabilities.
>    - Cryptographic asset scanning (CBOM) to identify algorithms, protocols, keys, and certificates.
>    - Cryptographic signing of public/private SBOMs and CBOMs.
> 3. **Team Member 3 (Compliance & Enrichment Specialist Runbook)**:
>    - Configuration and utilization of enrichment tools (e.g. registry querying scripts).
>    - Data mapping to populate the 21 client attributes.
>    - Package URL (PURL) formatting for all dependencies.
>    - Execution of the final automated validation check to ensure zero missing attributes.

---

## Open Questions

> [!WARNING]
> Please review and clarify the following questions:
> 1. **Testing Environment**: Should we create a mock target source code folder (containing basic files with dependencies like Log4j and cryptographic library imports) to verify our scanning and signing scripts during the verification phase?
> 2. **Signing Protocol**: We propose using standard ECDSA P-256 signatures with SHA-256 for signing the SBOMs/CBOMs, embedding the signature in the document metadata or saving it as a detached signature (`.sig` file). Do you have other signature format requirements?
> 3. **Validation Threshold**: Should the validator fail if *any* of the 21 attributes are missing, or should it emit warnings for optional fields (like `Comments or Notes`)?

---

## Proposed Changes

We will introduce a new automated directory `sbom_toolsuite/` in the project workspace, and create the detailed markdown runbook.

### Automated Tool Suite

#### [NEW] [config.json](file:///d:/College%20Work/Internship/BOM/sbom_toolsuite/config.json)
- Contains component enrichment mapping rules (e.g., fallback licensing, EOL calculation rules, custom component details, default authors).
- Stores signing configurations (e.g., path to private key, public key, and output directory).

#### [NEW] [sbom_scanner.py](file:///d:/College%20Work/Internship/BOM/sbom_toolsuite/sbom_scanner.py)
- Programmatically calls Trivy CLI in CycloneDX JSON format against the target directory.
- Captures baseline components, versions, dependencies, hashes, and raw vulnerabilities (Attribute 1, 2, 7, 8, 14).

#### [NEW] [cbom_scanner.py](file:///d:/College%20Work/Internship/BOM/sbom_toolsuite/cbom_scanner.py)
- Statically scans the target source code for cryptographic indicators (libraries like `pycryptodome`, `openssl`, imports like `hashlib`, algorithms, TLS versions, cipher suites).
- Generates a CBOM (CycloneDX-compatible JSON format) containing the 4 required cryptographic assets: Algorithms, Keys, Protocols, and Certificates.

#### [NEW] [sbom_enricher.py](file:///d:/College%20Work/Internship/BOM/sbom_toolsuite/sbom_enricher.py)
- Merges Trivy's raw SBOM and queries external registries (e.g., PyPI, npm Registry) to fetch missing data like EOL date, release date, license details, and description.
- Populates the remaining 21 required client attributes using a combination of registry data and `config.json`.
- Formats Attribute 21 (Unique Identifier) strictly in PURL format: `pkg:<type>/<namespace>/<name>@<version>`.

#### [NEW] [vex_csaf_generator.py](file:///d:/College%20Work/Internship/BOM/sbom_toolsuite/vex_csaf_generator.py)
- Processes identified vulnerabilities and outputs:
  - A **VEX document** mapping each CVE to its status (`not_affected`, `affected`, `fixed`, `under_investigation`).
  - A **CSAF JSON advisory** detailing mitigations and CVSS scores.

#### [NEW] [sbom_distributor.py](file:///d:/College%20Work/Internship/BOM/sbom_toolsuite/sbom_distributor.py)
- Performs the splitting of enriched SBOM/CBOM:
  - **Public SBOM**: Strips vulnerability details (`vulnerabilities` array), private properties, and internal dependency configurations.
  - **Private SBOM**: Retains complete vulnerability history, VEX linkages, and internal configuration metadata.
- Generates a cryptographic signature (ECDSA) for both files using a generated private key, writing the signature to detached `.sig` files and embedding them in the metadata field.

#### [NEW] [validate_sbom.py](file:///d:/College%20Work/Internship/BOM/sbom_toolsuite/validate_sbom.py)
- Validates the output files for schema compliance and ensures all 21 client-required attributes are correctly populated and structured.

#### [NEW] [runbook.md](file:///d:/College%20Work/Internship/BOM/runbook.md)
- A highly detailed, copy-pasteable execution guide in markdown containing step-by-step instructions, run commands, and checklists for the Agent AI to follow when executing these tools on any client repository, separated into the 3 roles.

---

## Verification Plan

### Automated Tests
- We will execute python scripts to run mock checks:
  1. Generate a mock project folder (`mock_project/`) with known vulnerable libraries (e.g., old versions of python packages) and cryptographic usages (e.g. hashlib.sha256, cryptography).
  2. Run the entire tool suite: scanner, CBOM analyzer, enricher, VEX generator, and distributor/signer.
  3. Validate the output using `validate_sbom.py` to ensure zero errors and confirm the 21 attributes are populated.
  4. Verify the integrity of the cryptographic signatures.

### Manual Verification
- Review the generated output files (`sbom_public.json`, `sbom_private.json`, `cbom.json`, `vex.json`, `csaf.json`) against the spreadsheet requirements and the CERT-In Technical Guidelines PDF.
