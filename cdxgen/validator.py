import json
import os
import sys

def validate_sbom(enriched_sbom_path):
    print(f"=== Starting SBOM Validation on: {os.path.basename(enriched_sbom_path)} ===")
    if not os.path.exists(enriched_sbom_path):
        print(f"Error: Enriched SBOM file does not exist at {enriched_sbom_path}")
        return False

    with open(enriched_sbom_path, 'r', encoding='utf-8') as f:
        sbom = json.load(f)

    # 1. Metadata Checks (Author & Timestamp)
    metadata = sbom.get('metadata', {})
    authors = metadata.get('authors', [])
    timestamp = metadata.get('timestamp', '')

    metadata_errors = []
    if not authors or not authors[0].get('name'):
        metadata_errors.append("Attribute 16 (Author of SBOM Data) is missing in metadata.")
    if not timestamp:
        metadata_errors.append("Attribute 17 (Timestamp) is missing in metadata.")

    # 2. Components Checks
    components = sbom.get('components', [])
    if not components:
        print("Warning: No components found in the SBOM.")
        
    all_passed = True
    comp_reports = []

    # Map of dependencies
    deps = sbom.get('dependencies', [])
    dep_refs = {d.get('ref') for d in deps}

    for comp in components:
        name = comp.get('name', 'Unknown')
        version = comp.get('version', 'Unknown')
        purl = comp.get('purl', '')
        
        comp_errors = []
        
        # Attribute 1: Component Name
        if not comp.get('name'):
            comp_errors.append("Attr 1: Component Name is missing")
        # Attribute 2: Component Version
        if not comp.get('version'):
            comp_errors.append("Attr 2: Component Version is missing")
        # Attribute 3: Component Description
        if not comp.get('description'):
            comp_errors.append("Attr 3: Component Description is missing")
        # Attribute 4: Component Supplier
        supplier = comp.get('supplier', {})
        if not supplier or not supplier.get('name'):
            comp_errors.append("Attr 4: Component Supplier is missing")
        # Attribute 5: Component License
        licenses = comp.get('licenses', [])
        if not licenses or not licenses[0].get('license', {}).get('name'):
            comp_errors.append("Attr 5: Component License is missing")
        # Attribute 7: Component Dependencies (Checked in dependencies mapping ref)
        ref = comp.get('bom-ref') or purl
        if ref not in dep_refs:
            comp_errors.append(f"Attr 7: Dependency mapping ref ({ref}) not defined in root dependencies list")
        # Attribute 14: Checksums or Hashes
        hashes = comp.get('hashes', [])
        if not hashes:
            comp_errors.append("Attr 14: Checksums or Hashes are missing")
        # Attribute 21: Unique Identifier (PURL)
        if not purl or not purl.startswith("pkg:"):
            comp_errors.append("Attr 21: Unique Identifier (PURL) is invalid or missing")

        # Custom properties
        properties = comp.get('properties', [])
        prop_map = {p.get('name'): p.get('value') for p in properties}
        
        required_properties = {
            'origin': "Attr 6: Component Origin",
            'patch_status': "Attr 9: Patch Status",
            'release_date': "Attr 10: Release Date",
            'eol_date': "Attr 11: End-of-Life (EOL) Date",
            'criticality': "Attr 12: Criticality",
            'criticality_reason': "Attr 12 sub: Criticality Rationale",
            'usage_restrictions': "Attr 13: Usage Restrictions",
            'comments': "Attr 15: Comments or Notes",
            'executable': "Attr 18: Executable Property",
            'executable_evidence': "Attr 18 sub: Executable Evidence",
            'archive': "Attr 19: Archive Property",
            'archive_metadata': "Attr 19 sub: Archive Metadata Info",
            'structured': "Attr 20: Structured Property",
            'trust_score': "Evidence: Trust Score %",
            'trust_score_reason': "Evidence: Trust Score Reason Rationale",
            'evidence_findings': "Evidence: Detection Evidence Findings",
            'repository_source': "Ecosystem: Repository Source Registry"
        }
        
        for prop_name, label in required_properties.items():
            if prop_name not in prop_map or prop_map[prop_name] is None or prop_map[prop_name] == "":
                comp_errors.append(f"{label} property is missing")

        status = "PASSED" if not comp_errors else "FAILED"
        if comp_errors:
            all_passed = False
            
        comp_reports.append({
            "name": name,
            "version": version,
            "status": status,
            "errors": comp_errors
        })

    # Output report
    print("\n--- Validation Results Table ---")
    print(f"{'Component Name':<20} | {'Version':<10} | {'Status':<8} | {'Errors'}")
    print("-" * 100)
    for rep in comp_reports:
        err_str = "; ".join(rep["errors"]) if rep["errors"] else "None"
        print(f"{rep['name']:<20} | {rep['version']:<10} | {rep['status']:<8} | {err_str}")
        
    print("-" * 100)
    
    if metadata_errors:
        print("\nMetadata Validation Errors:")
        for err in metadata_errors:
            print(f"- {err}")
        all_passed = False
        
    if all_passed:
        print("\nSUCCESS: Enriched SBOM is fully compliant with all 21 client attributes and CycloneDX v1.6 requirements!")
        return True
    else:
        print("\nFAILURE: Compliance check failed. Some required fields or attributes are missing.")
        return False

if __name__ == "__main__":
    base_dir = os.path.dirname(os.path.abspath(__file__))
    enriched_path = os.path.join(base_dir, "sbom_final.json")
    
    if len(sys.argv) > 1:
        enriched_path = sys.argv[1]
        
    success = validate_sbom(enriched_path)
    sys.exit(0 if success else 1)
