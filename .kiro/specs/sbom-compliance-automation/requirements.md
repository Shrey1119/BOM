# Requirements Document

## Introduction

The SBOM Compliance Automation Suite is a Python-based tool suite (`sbom_toolsuite/`) that automates the end-to-end workflow for generating, enriching, validating, and securely distributing Software Bill of Materials (SBOM) documents. The suite scans client source code using Trivy, enriches the output with all 21 client-mandated attributes (aligned with CERT-In Technical Guidelines), generates VEX/CSAF vulnerability management documents, splits SBOMs into Public and Private variants, cryptographically signs all artifacts, and produces role-based execution runbooks for three team members.

---

## Glossary

- **SBOM**: Software Bill of Materials — a formal, machine-readable inventory of software components and their relationships.
- **CycloneDX**: An SBOM standard format (JSON) used for describing software components and vulnerabilities.
- **Trivy**: An open-source CLI vulnerability and dependency scanner that outputs CycloneDX JSON.
- **PURL**: Package URL — a standard identifier scheme in the format `pkg:<type>/<namespace>/<name>@<version>`.
- **VEX**: Vulnerability Exploitability eXchange — a document classifying each CVE's applicability to a given product.
- **CSAF**: Common Security Advisory Framework — a structured advisory format for describing vulnerabilities and mitigations.
- **ECDSA**: Elliptic Curve Digital Signature Algorithm — used to cryptographically sign SBOM artifacts.
- **CVE**: Common Vulnerabilities and Exposures identifier.
- **CVSS**: Common Vulnerability Scoring System — numeric severity score for a CVE.
- **EOL**: End-of-Life date for a software component.
- **CERT-In**: Computer Emergency Response Team – India, whose Technical Guidelines define mandatory SBOM attributes.
- **Scanner**: The `sbom_scanner.py` module responsible for executing Trivy and producing a baseline SBOM.
- **Enricher**: The `sbom_enricher.py` module responsible for injecting all 21 client attributes.
- **Validator**: The `validate_sbom.py` module responsible for verifying attribute completeness and schema compliance.
- **VEX_Generator**: The `vex_csaf_generator.py` module responsible for producing VEX and CSAF documents.
- **Distributor**: The `sbom_distributor.py` module responsible for splitting and signing SBOM artifacts.
- **Config**: The `sbom_toolsuite/config.json` configuration file supplying enrichment rules, overrides, and signing paths.
- **Public_SBOM**: The SBOM variant with vulnerability details removed, safe for external sharing.
- **Private_SBOM**: The SBOM variant retaining all vulnerability and internal configuration data.
- **Mock_Project**: The `mock_project/` directory containing known-vulnerable dependencies used for automated verification.
- **Runbook**: The `runbook.md` file containing role-specific, copy-pasteable execution instructions.

---

## Requirements

### Requirement 1: Baseline SBOM Generation via Trivy Scan

**User Story:** As a Tooling & Execution Engineer (Team Member 2), I want to programmatically invoke Trivy against a target source code directory, so that I can produce a baseline CycloneDX JSON SBOM containing structural component metadata.

#### Acceptance Criteria

1. WHEN the Scanner is invoked with a target directory path, THE Scanner SHALL execute the Trivy CLI in filesystem scan mode and capture its CycloneDX JSON output.
2. WHEN the Trivy scan completes successfully, THE Scanner SHALL write the raw CycloneDX JSON output to a configurable output file path.
3. WHEN the Trivy scan completes, THE Scanner SHALL populate at minimum the following attributes for each discovered component: Component Name (Attribute 1), Component Version (Attribute 2), Component Hash/Checksum (Attribute 3), Component Type (Attribute 6), Dependencies (Attribute 7), and File Name/Path (Attribute 14).
4. WHEN Trivy identifies a vulnerability for a component, THE Scanner SHALL include the CVE identifier and CVSS severity score in the raw SBOM output, satisfying Attribute 8 (Vulnerabilities).
5. IF the Trivy CLI is not found or returns a non-zero exit code, THEN THE Scanner SHALL raise a descriptive error and halt execution without writing partial output.
6. WHEN the Scanner is invoked, THE Scanner SHALL read the target directory path and output file path from Config or from command-line arguments.

---

### Requirement 2: 21-Attribute SBOM Enrichment

**User Story:** As a Compliance & Enrichment Specialist (Team Member 3), I want to enrich the raw Trivy SBOM with all 21 client-mandated attributes by querying external registries and applying configuration overrides, so that the final SBOM meets both client and CERT-In Technical Guideline requirements.

#### Acceptance Criteria

1. WHEN the Enricher is invoked with a raw CycloneDX JSON SBOM, THE Enricher SHALL query the PyPI JSON API or npm Registry API to fetch Release Date (Attribute 10), End-of-Life Date (Attribute 11), Supplier/Vendor Name (Attribute 4), and License Information (Attribute 5) for each component.
2. WHEN registry data is unavailable for a component, THE Enricher SHALL apply fallback values from Config (e.g., `default_eol_offset_years`, `default_usage_restrictions`, `default_origin`).
3. WHEN the Enricher processes each component, THE Enricher SHALL format the Unique Identifier (Attribute 21) strictly as a PURL in the format `pkg:<type>/<namespace>/<name>@<version>`.
4. WHEN the Enricher processes each component, THE Enricher SHALL populate the Criticality field (Attribute 12) using `criticality_overrides` from Config, falling back to `default_criticality` when no override exists.
5. WHEN the Enricher processes each component, THE Enricher SHALL populate the Component Origin field (Attribute 13) using `origin_overrides` from Config, falling back to `default_origin`.
6. WHEN the Enricher processes each component, THE Enricher SHALL populate the Usage Restrictions / Export Control flags (Attribute 15) using `usage_restrictions_overrides` from Config, falling back to `default_usage_restrictions`.
7. WHEN the Enricher processes each component, THE Enricher SHALL populate the Author of SBOM Data (Attribute 16) and Timestamp of SBOM Generation (Attribute 17) from Config and the current UTC system time respectively.
8. WHEN the Enricher processes each component, THE Enricher SHALL populate the Component Description (Attribute 9) from registry API responses where available.
9. WHEN the Enricher processes each component, THE Enricher SHALL populate the Executable Properties (Attribute 18), Archive Properties (Attribute 19), and Comments (Attribute 20) fields using values from Config or sensible defaults.
10. WHEN enrichment is complete, THE Enricher SHALL write the fully enriched CycloneDX JSON SBOM to a configurable output file path.
11. IF a registry API request fails due to a network error or HTTP error code, THEN THE Enricher SHALL log the failure, apply Config fallback values, and continue processing remaining components without halting.

---

### Requirement 3: SBOM Compliance Validation

**User Story:** As a Compliance & Enrichment Specialist (Team Member 3), I want to automatically validate the enriched SBOM against all 21 client-required attributes and CERT-In Technical Guidelines, so that I can confirm zero missing or malformed fields before distribution.

#### Acceptance Criteria

1. WHEN the Validator is invoked with an enriched SBOM file, THE Validator SHALL check each component for the presence and non-empty value of all 21 mandatory attributes.
2. WHEN the Validator detects a missing or empty attribute for any component, THE Validator SHALL report the component name, attribute number, and attribute name in a structured validation report.
3. WHEN the Validator checks Attribute 21 (Unique Identifier), THE Validator SHALL verify that the value conforms to the PURL format `pkg:<type>/<namespace>/<name>@<version>` using a regular expression.
4. WHEN the Validator checks Attribute 8 (Vulnerabilities), THE Validator SHALL verify that each vulnerability entry contains a CVE identifier and a CVSS numeric score.
5. WHEN the Validator checks Attribute 17 (Timestamp), THE Validator SHALL verify that the value is a valid ISO 8601 UTC datetime string.
6. WHEN validation completes with no errors, THE Validator SHALL output a structured success report with a total component count and a confirmation that all 21 attributes are compliant.
7. WHEN validation completes with errors, THE Validator SHALL output a structured error report listing all violations and exit with a non-zero status code.

---

### Requirement 4: VEX Document Generation

**User Story:** As a Security & Governance Lead (Team Member 1), I want to generate a Vulnerability Exploitability eXchange (VEX) document from the enriched SBOM's vulnerability data, so that the client receives a formal assessment of each CVE's exploitability status.

#### Acceptance Criteria

1. WHEN the VEX_Generator is invoked with an enriched SBOM, THE VEX_Generator SHALL produce a VEX document containing one entry per identified CVE.
2. WHEN producing a VEX entry, THE VEX_Generator SHALL assign each CVE one of four statuses: `not_affected`, `affected`, `fixed`, or `under_investigation`.
3. WHEN producing a VEX entry, THE VEX_Generator SHALL include the CVE identifier, CVSS score, affected component PURL, and exploitability status in each entry.
4. WHEN the VEX_Generator produces a VEX document, THE VEX_Generator SHALL write the output to a configurable file path in CycloneDX VEX JSON format.
5. IF the enriched SBOM contains no vulnerabilities, THEN THE VEX_Generator SHALL produce an empty VEX document with a metadata note indicating zero vulnerabilities were found.

---

### Requirement 5: CSAF Advisory Generation

**User Story:** As a Security & Governance Lead (Team Member 1), I want to generate a CSAF advisory document for all discovered vulnerabilities, so that the client receives structured remediation guidance aligned with industry standards.

#### Acceptance Criteria

1. WHEN the VEX_Generator is invoked with an enriched SBOM, THE VEX_Generator SHALL produce a CSAF JSON advisory document for all vulnerabilities with status `affected` or `under_investigation`.
2. WHEN producing a CSAF advisory, THE VEX_Generator SHALL include the CVE identifier, CVSS base score, affected component name and version, and a remediation or mitigation description for each entry.
3. WHEN producing a CSAF advisory, THE VEX_Generator SHALL set the document timestamp to the current UTC time and include the organization name from Config.
4. WHEN the VEX_Generator produces a CSAF advisory, THE VEX_Generator SHALL write the output to a configurable file path in valid CSAF 2.0 JSON format.

---

### Requirement 6: Public/Private SBOM Split

**User Story:** As a Tooling & Execution Engineer (Team Member 2), I want to split the enriched SBOM into a Public variant and a Private variant, so that sensitive vulnerability and internal configuration data is not exposed in the externally distributed document.

#### Acceptance Criteria

1. WHEN the Distributor is invoked with an enriched SBOM, THE Distributor SHALL produce a Public_SBOM by removing the `vulnerabilities` array, private property annotations, and internal dependency configuration metadata.
2. WHEN the Distributor is invoked with an enriched SBOM, THE Distributor SHALL produce a Private_SBOM retaining all vulnerability data, VEX linkages, CSAF references, internal configuration metadata, and comments.
3. WHEN producing the Public_SBOM, THE Distributor SHALL retain all 21 non-sensitive attributes including Component Name, Version, Hash, License, PURL, Type, Dependencies, Description, Release Date, EOL Date, Criticality, Origin, Author, Timestamp, and File Name/Path.
4. WHEN the Distributor produces both SBOM variants, THE Distributor SHALL write them to configurable output file paths (e.g., `sbom_public.json` and `sbom_private.json`).

---

### Requirement 7: Cryptographic Signing of SBOM Artifacts

**User Story:** As a Tooling & Execution Engineer (Team Member 2), I want to cryptographically sign all SBOM artifacts using ECDSA, so that recipients can verify the integrity and authenticity of the documents.

#### Acceptance Criteria

1. WHEN the Distributor signs an SBOM artifact, THE Distributor SHALL use the ECDSA private key located at the path specified in Config (`signing.private_key_path`) to generate a detached signature.
2. WHEN the Distributor generates a signature, THE Distributor SHALL write the detached signature to a `.sig` file with the same base name as the signed artifact (e.g., `sbom_public.json.sig`).
3. WHEN the Distributor generates a signature, THE Distributor SHALL embed the base64-encoded signature value in the SBOM's metadata field.
4. WHEN the Distributor generates a signature, THE Distributor SHALL also write the corresponding public key path to the SBOM's metadata so recipients know which key to use for verification.
5. IF the private key file is not found at the configured path, THEN THE Distributor SHALL raise a descriptive error and halt the signing process.
6. WHEN ECDSA key files do not exist, THE Distributor SHALL generate a new ECDSA key pair and write the private and public key PEM files to the paths specified in Config.

---

### Requirement 8: Configuration-Driven Behavior

**User Story:** As any team member, I want all tool behaviors to be governed by `sbom_toolsuite/config.json`, so that the suite can be adapted to different client projects without modifying source code.

#### Acceptance Criteria

1. THE Config SHALL define the author name, organization name, and SBOM format description used across all modules.
2. THE Config SHALL define `criticality_overrides` (a per-component map) and `default_criticality` used by the Enricher.
3. THE Config SHALL define `usage_restrictions_overrides` (a per-component map) and `default_usage_restrictions` used by the Enricher.
4. THE Config SHALL define `origin_overrides` (a per-component map) and `default_origin` used by the Enricher.
5. THE Config SHALL define `comments` (a per-component map) supplying internal notes for Attribute 20.
6. THE Config SHALL define `default_eol_offset_years` used by the Enricher to calculate EOL dates when registry data is unavailable.
7. THE Config SHALL define `signing.private_key_path` and `signing.public_key_path` consumed by the Distributor.

---

### Requirement 9: Mock Project for Automated Verification

**User Story:** As any team member, I want a `mock_project/` directory containing known-vulnerable Python packages, so that the entire tool suite can be verified end-to-end in a controlled environment.

#### Acceptance Criteria

1. THE Mock_Project SHALL contain a `requirements.txt` file listing at minimum five Python packages with known historical vulnerabilities (e.g., `requests==2.20.0`, `urllib3==1.24.2`, `jinja2==2.10`, `numpy==1.15.0`, `django==2.1`).
2. WHEN the full tool suite is executed against Mock_Project, THE Validator SHALL report zero missing attributes across all components.
3. WHEN the full tool suite is executed against Mock_Project, THE Distributor SHALL produce `sbom_public.json`, `sbom_private.json`, `sbom_public.json.sig`, and `sbom_private.json.sig` without errors.
4. WHEN the full tool suite is executed against Mock_Project, THE VEX_Generator SHALL produce at least one VEX entry corresponding to a known CVE in the listed packages.

---

### Requirement 10: Role-Based Runbook

**User Story:** As any team member, I want a comprehensive `runbook.md` document with role-specific, copy-pasteable instructions, so that each team member can execute their designated tasks independently without needing to read source code.

#### Acceptance Criteria

1. THE Runbook SHALL contain a dedicated section for Team Member 1 (Security & Governance Lead) covering: ECDSA key generation, VEX/CSAF generation commands, and secure storage guidance.
2. THE Runbook SHALL contain a dedicated section for Team Member 2 (Tooling & Execution Engineer) covering: Trivy installation, scanning commands, SBOM splitting commands, and signing commands.
3. THE Runbook SHALL contain a dedicated section for Team Member 3 (Compliance & Enrichment Specialist) covering: enrichment commands, PURL formatting guidance, and validation commands.
4. WHEN a team member follows their Runbook section, THE Runbook SHALL provide the exact shell commands required to execute each script with correct arguments and file paths.
5. THE Runbook SHALL include a prerequisite section listing required tools (Python 3.x, Trivy CLI) and their installation commands.

---

### Requirement 11: Walkthrough Artifact

**User Story:** As a project stakeholder, I want a `walkthrough.md` document summarizing the complete automated verification run, so that I can review the end-to-end flow and confirm compliance without executing the scripts myself.

#### Acceptance Criteria

1. THE Walkthrough SHALL document the complete sequence of tool executions performed against Mock_Project, including the commands run and the output artifacts produced.
2. THE Walkthrough SHALL include a table or structured summary confirming that all 21 attributes are populated for each component in the Mock_Project scan.
3. THE Walkthrough SHALL confirm the cryptographic integrity of the signed artifacts by documenting the signature verification steps and results.
