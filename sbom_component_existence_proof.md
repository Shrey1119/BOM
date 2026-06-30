# SBOM Auditor Report: Mathematical Verification Framework
## Proof of Component Existence in the Target System

This document outlines the mathematical statistics, formulas, and structural validation procedures used to verify and prove the existence of each software component recorded in the Software Bill of Materials (SBOM) for compliance audits.

Auditors can use this mathematical framework to verify that the components listed in the final compliance spreadsheet (`sbom_report.xlsx`) and CycloneDX JSON deliverables have been programmatically corroborated and are not arbitrary or synthetic entries.

---

## 1. The Mathematical Component Trust Score ($T_{c}$)

To quantitatively assess the level of proof for each component's existence, the Enrichment Engine computes an **Existence Trust Score** ($T_{c}$) ranging from $0\%$ to $100\%$. 

### The Scoring Formula
For any component $c$, the Trust Score is defined as the weighted sum of five verification coefficients:

$$T_{c} = \min \left( 100, S_{\text{purl}} + S_{\text{api}} + S_{\text{hash}} + S_{\text{license}} + S_{\text{override}} \right)$$

Where the scoring factors are defined as follows:

| Factor Symbol | Verification Weight | Activation Rule | Code Reference | Description |
| :--- | :---: | :--- | :--- | :--- |
| $S_{\text{purl}}$ | **20%** | $S_{\text{purl}} = 20$ if component has a valid, formatted Package URL (PURL); else $0$. | [enricher.py:L454-458](file:///c:/Users/ADMIN/OneDrive/Desktop/BOM/BOM/Merge%20Engine/enricher.py#L454-L458) | Proves standard identity nomenclature matching the package manager specifications. |
| $S_{\text{api}}$ | **30%** | $S_{\text{api}} = 30$ if version and PURL are verified against a public upstream package registry (e.g., PyPI); else $0$. | [enricher.py:L460-464](file:///c:/Users/ADMIN/OneDrive/Desktop/BOM/BOM/Merge%20Engine/enricher.py#L460-L464) | Proves the package exists in public registries under the exact version scanned. |
| $S_{\text{hash}}$ | **25%** | $S_{\text{hash}} = 25$ if a cryptographic integrity digest (SHA-256) is present for the package; else $0$. | [enricher.py:L466-472](file:///c:/Users/ADMIN/OneDrive/Desktop/BOM/BOM/Merge%20Engine/enricher.py#L466-L472) | Proves unique mathematical integrity and allows binary matching of local source. |
| $S_{\text{license}}$| **15%** | $S_{\text{license}} = 15$ if a non-empty, non-generic license is successfully mapped to the package; else $0$. | [enricher.py:L474-478](file:///c:/Users/ADMIN/OneDrive/Desktop/BOM/BOM/Merge%20Engine/enricher.py#L474-L478) | Corroborates package legitimacy and compliance metadata consistency. |
| $S_{\text{override}}$| **10%** | $S_{\text{override}} = 10$ if component attributes match explicit manual review entries in the `config.json` file; else $0$. | [enricher.py:L480-484](file:///c:/Users/ADMIN/OneDrive/Desktop/BOM/BOM/Merge%20Engine/enricher.py#L480-L484) | Reflects human-in-the-loop review and governance validation of existence. |

### Trust Classification Thresholds
The trust score maps to three audit confidence levels:

*   **High Confidence ($T_{c} \ge 80\%$)**: The component's existence is proven by multiple independent sources (local files, package managers, and upstream APIs). Recommended for immediate audit approval.
*   **Medium Confidence ($50\% \le T_{c} < 80\%$)**: The component is detected, but lacks certain attributes (e.g. missing SHA-256 hash in registry or offline fallback).
*   **Low Confidence ($T_{c} < 50\%$)**: Insufficient verification. Needs manual review or security overrides.

---

## 2. Scanner Correlation and Deduplication Statistics

The pipeline integrates results from two distinct scanner methodologies:
1.  **Syft** (Filesystem cataloger searching manifest locks).
2.  **Trivy** (Container and vulnerability scanner analyzing binary targets).

To prove integration consistency to auditors, the pipeline calculates mathematical metrics across the raw and final component sets.

### Variable Definitions
*   $N_{\text{Syft}}$: Total components detected in the raw Syft scan.
*   $N_{\text{Trivy}}$: Total components detected in the raw Trivy scan.
*   $N_{\text{Common}}$: Overlapping components detected by **both** scanners, matched via exact PURL alignment or fuzzy name-version correlation.
*   $N_{\text{Final}}$: Total unique components in the final merged inventory.

### Statistical Equations

#### 1. Deduplicated Inventory Size
$$N_{\text{Final}} = N_{\text{Syft}} + N_{\text{Trivy}} - N_{\text{Common}}$$

#### 2. Discarded Duplicate Records
$$N_{\text{Duplicates}} = (N_{\text{Syft}} + N_{\text{Trivy}}) - N_{\text{Final}} = N_{\text{Common}}$$

#### 3. Merge Success Rate (Synchronization Rate)
This represents the synchronization match percentage between the two tools relative to the total raw count:

$$R_{\text{Merge}} = \frac{N_{\text{Common}}}{N_{\text{Syft}} + N_{\text{Trivy}}} \times 100\%$$

#### 4. Matching Coverage Percentage
This represents the proportion of components in the final inventory that were verified by both scanners:

$$C_{\text{Coverage}} = \frac{N_{\text{Matched}}}{N_{\text{Final}}} \times 100\%$$

*(Where $N_{\text{Matched}}$ is the count of final components with `merge_status` set to `"Merged"` or `"Merged (Fuzzy Name/Version)"`)*.

---

## 3. Local Evidence Integrity and Path Corroboration

Auditors require proof that the scanned library actually resides on the system's disk. This is handled using the **Evidence Source** list, which traces the exact file path or configuration where the scanner discovered the component.

### Path Verification Strength
Let $P_e$ be the set of paths in the component's `evidence_sources` array. The physical proof strength of the paths is classified into three categories:

1.  **Primary Manifest Evidence (Strongest)**:
    If any path in $P_e$ matches lockfiles or package manifests (e.g. `poetry.lock`, `package-lock.json`, `Cargo.lock`, `requirements.txt`).
    $$\text{Manifest Match} \implies \text{Active project dependency verified.}$$
2.  **Installed Directory Evidence (Strong)**:
    If any path in $P_e$ matches active library files or interpreter paths (e.g. `/usr/local/lib/python3.10/site-packages/`).
    $$\text{Installed path verification} \implies \text{Component executable file present on target disk.}$$
3.  **Heuristic Scan Discovery (Secondary)**:
    If paths are labeled `"Syft Scan Discovery"` or `"Trivy Scan Discovery"`. This indicates scanner consensus on dependencies, but file paths were abstracted.

---

## 4. Concrete Example Calculation

### Case: Verification of `Django v2.1`

#### A. Input Verification States
1.  **PURL availability**: Component has purl `pkg:pypi/django@2.1` $\implies P(c) = 1$.
2.  **PURL confirmation**: Python PyPI API successfully fetched metadata for Django v2.1 $\implies A(c) = 1$.
3.  **Hash presence**: SHA-256 hash was generated or retrieved for Django v2.1 $\implies H(c) = 1$.
4.  **Identified license**: License property resolves to `BSD-3-Clause` $\implies L(c) = 1$.
5.  **Config override**: Django has no manual override entry in `config.json` $\implies R(c) = 0$.

#### B. Trust Score Computation
$$T_{\text{Django}} = S_{\text{purl}} + S_{\text{api}} + S_{\text{hash}} + S_{\text{license}} + S_{\text{override}}$$
$$T_{\text{Django}} = (20 \times 1) + (30 \times 1) + (25 \times 1) + (15 \times 1) + (10 \times 0)$$
$$T_{\text{Django}} = 20 + 30 + 25 + 15 + 0 = 90\%$$

$$\text{Since } 90\% \ge 80\%, \text{ Django is verified at HIGH CONFIDENCE.}$$

---

## 5. Auditor Verification Runbook (Step-by-Step)

Auditors can programmatically verify these calculations directly from the enriched SBOM JSON (`sbom_final.json` or `sbom_enriched.json`) by executing the following commands or scripts:

### Step 1: Count Raw vs Merged Totals
Run this Python command in the terminal to verify the inventory size calculations:
```powershell
python -c "
import json
with open('sbom_final.json') as f:
    sbom = json.load(f)
components = sbom.get('components', [])
syft_total = sum(1 for c in components if 'syft' in c.get('detected_by', []))
trivy_total = sum(1 for c in components if 'trivy' in c.get('detected_by', []))
common_total = sum(1 for c in components if len(c.get('detected_by', [])) > 1)
final_total = len(components)
print(f'Syft Total: {syft_total}')
print(f'Trivy Total: {trivy_total}')
print(f'Common Overlap: {common_total}')
print(f'Final Deduplicated: {final_total}')
print(f'Verification Equation: {syft_total} + {trivy_total} - {common_total} = {syft_total + trivy_total - common_total} (Final: {final_total})')
"
```

### Step 2: Validate Trust Score Compliance
Ensure that all components meet the audit thresholds by running this validation helper:
```powershell
python -c "
import json
with open('sbom_final.json') as f:
    components = json.load(f).get('components', [])
low_trust = []
for c in components:
    props = {p['name']: p['value'] for p in c.get('properties', []) if 'name' in p}
    score = int(props.get('trust_score', '0%').replace('%', ''))
    if score < 80:
        low_trust.append((c['name'], c['version'], score, props.get('trust_score_reason', 'N/A')))
if low_trust:
    print(f'Found {len(low_trust)} components requiring auditor check:')
    for item in low_trust:
        print(f' - {item[0]}@{item[1]} (Score: {item[2]}%) Reason: {item[3]}')
else:
    print('All components passed verification with High Confidence (>= 80%)!')
"
```
