import json
import os
import sys
import argparse
import uuid
import re

def normalize_purl(purl):
    """Normalize PURL format: lowercase namespace/name and strip package qualifiers."""
    if not purl:
        return ""
    # Strip any query parameters (e.g. ?package-id=...)
    purl_clean = purl.split('?')[0]
    
    # Parse purl parts
    # pkg:pypi/django@2.1 -> pkg, pypi/django@2.1
    if not purl_clean.startswith("pkg:"):
        return purl_clean.lower()
        
    parts = purl_clean.split('/', 1)
    if len(parts) > 1:
        scheme_type = parts[0].lower() # e.g. pkg:pypi
        rest = parts[1].lower() # e.g. django@2.1
        return f"{scheme_type}/{rest}"
    return purl_clean.lower()

def extract_ecosystem(purl):
    """Determine ecosystem based on PURL format."""
    if not purl:
        return "generic"
    if purl.startswith("pkg:pypi/"):
        return "pypi"
    elif purl.startswith("pkg:npm/"):
        return "npm"
    elif purl.startswith("pkg:maven/"):
        return "maven"
    elif purl.startswith("pkg:golang/") or purl.startswith("pkg:go/"):
        return "go"
    elif purl.startswith("pkg:cargo/") or purl.startswith("pkg:rust/"):
        return "cargo"
    return "generic"

def clean_name(name):
    """Normalize package name strings."""
    if not name:
        return ""
    # Lowercase and trim leading/trailing scopes or paths
    name_clean = name.strip().lower()
    if "/" in name_clean and not name_clean.startswith("@"):
        name_clean = name_clean.split("/")[-1]
    return name_clean

def load_config(config_path):
    if os.path.exists(config_path):
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"Warning: Failed to load config from {config_path} ({e})")
    return {}

def merge_sboms(syft_path, trivy_path, config_path, output_path):
    print(f"Merging SBOMs:\n - Syft: {syft_path}\n - Trivy: {trivy_path}")
    
    # Validate that both paths are actual files
    if not os.path.isfile(syft_path):
        print(f"Error: Syft path is not a file: {syft_path}")
        sys.exit(1)
    if not os.path.isfile(trivy_path):
        print(f"Error: Trivy path is not a file: {trivy_path}")
        sys.exit(1)
        
    # 1. Load inputs
    with open(syft_path, 'r', encoding='utf-8') as f:
        syft_data = json.load(f)
        
    with open(trivy_path, 'r', encoding='utf-8') as f:
        trivy_data = json.load(f)
        
    config = load_config(config_path)
    
    # 2. Correlate Components
    correlated_components = {}
    trivy_to_unified_ref = {}
    syft_to_unified_ref = {}
    
    # Track statistics
    syft_count = 0
    trivy_count = 0
    common_count = 0
    
    # --- STEP A: Ingest Syft Components ---
    syft_components = syft_data.get('components', [])
    for comp in syft_components:
        syft_count += 1
        name = comp.get('name')
        version = comp.get('version', 'unknown')
        purl = comp.get('purl', '')
        
        norm_purl = normalize_purl(purl) if purl else f"pkg:generic/{clean_name(name)}@{version}"
        
        # Build standard properties
        properties = comp.get('properties', [])
        evidence_sources = set()
        
        # Resolve evidence sources from Syft properties
        for prop in properties:
            if 'path' in prop.get('name', ''):
                evidence_sources.add(prop.get('value', ''))
                
        if not evidence_sources:
            evidence_sources.add("Syft Scan Discovery")
            
        cpes = []
        if comp.get('cpe'):
            cpes.append(comp.get('cpe'))
        for prop in properties:
            if prop.get('name') == 'syft:cpe23':
                cpes.append(prop.get('value'))
                
        # Deduplicate CPE list
        cpes = list(sorted(set(cpes)))
        
        # Build unified internal model
        unified_comp = {
            "bom-ref": purl or f"pkg:generic/{clean_name(name)}@{version}",
            "type": comp.get('type', 'library'),
            "name": name,
            "version": version,
            "purl": purl or f"pkg:generic/{clean_name(name)}@{version}",
            "cpe": cpes[0] if cpes else comp.get('cpe'),
            "cpes": cpes,
            "hashes": comp.get('hashes', []),
            "licenses": comp.get('licenses', []),
            "description": comp.get('description', ''),
            "supplier": comp.get('supplier', {}),
            "properties": properties,
            "detected_by": ["syft"],
            "evidence_sources": list(evidence_sources),
            "merge_confidence": "100%",
            "merge_status": "Original",
            "unique_component_id": str(uuid.uuid4())
        }
        
        correlated_components[norm_purl] = unified_comp
        syft_to_unified_ref[comp.get('bom-ref') or purl] = unified_comp["bom-ref"]

    # --- STEP B: Ingest Trivy Components with Correlation ---
    trivy_components = trivy_data.get('components', [])
    for comp in trivy_components:
        trivy_count += 1
        name = comp.get('name')
        version = comp.get('version', 'unknown')
        purl = comp.get('purl', '')
        trivy_ref = comp.get('bom-ref') or purl
        
        norm_purl = normalize_purl(purl) if purl else f"pkg:generic/{clean_name(name)}@{version}"
        
        evidence_sources = set()
        properties = comp.get('properties', [])
        for prop in properties:
            if 'Class' in prop.get('name', ''):
                evidence_sources.add(prop.get('value', ''))
                
        if not evidence_sources:
            evidence_sources.add("Trivy Scan Discovery")
            
        # Match check 1: Exact PURL Match (100% confidence)
        if norm_purl in correlated_components:
            common_count += 1
            existing = correlated_components[norm_purl]
            if "trivy" not in existing["detected_by"]:
                existing["detected_by"].append("trivy")
            existing["merge_status"] = "Merged"
            existing["evidence_sources"] = list(set(existing["evidence_sources"]).union(evidence_sources))
            
            # Merge fields if missing in Syft
            if not existing.get('description') and comp.get('description'):
                existing['description'] = comp.get('description')
            if not existing.get('licenses') and comp.get('licenses'):
                existing['licenses'] = comp.get('licenses')
            if not existing.get('supplier') and comp.get('supplier'):
                existing['supplier'] = comp.get('supplier')
                
            trivy_to_unified_ref[trivy_ref] = existing["bom-ref"]
            
        else:
            # Match check 2: Fuzzy matching by Name + Version + Ecosystem (75% confidence)
            fuzzy_match = None
            for key, val in correlated_components.items():
                if clean_name(val['name']) == clean_name(name) and val['version'] == version:
                    # Match found!
                    fuzzy_match = val
                    break
                    
            if fuzzy_match:
                common_count += 1
                if "trivy" not in fuzzy_match["detected_by"]:
                    fuzzy_match["detected_by"].append("trivy")
                fuzzy_match["merge_status"] = "Merged (Fuzzy Name/Version)"
                fuzzy_match["merge_confidence"] = "75%"
                fuzzy_match["evidence_sources"] = list(set(fuzzy_match["evidence_sources"]).union(evidence_sources))
                
                # Merge details
                if not fuzzy_match.get('description') and comp.get('description'):
                    fuzzy_match['description'] = comp.get('description')
                if not fuzzy_match.get('licenses') and comp.get('licenses'):
                    fuzzy_match['licenses'] = comp.get('licenses')
                if not fuzzy_match.get('supplier') and comp.get('supplier'):
                    fuzzy_match['supplier'] = comp.get('supplier')
                    
                trivy_to_unified_ref[trivy_ref] = fuzzy_match["bom-ref"]
            else:
                # No match: Create new component unique to Trivy
                unified_comp = {
                    "bom-ref": purl or f"pkg:generic/{clean_name(name)}@{version}",
                    "type": comp.get('type', 'library'),
                    "name": name,
                    "version": version,
                    "purl": purl or f"pkg:generic/{clean_name(name)}@{version}",
                    "cpe": comp.get('cpe'),
                    "cpes": [comp.get('cpe')] if comp.get('cpe') else [],
                    "hashes": comp.get('hashes', []),
                    "licenses": comp.get('licenses', []),
                    "description": comp.get('description', ''),
                    "supplier": comp.get('supplier', {}),
                    "properties": properties,
                    "detected_by": ["trivy"],
                    "evidence_sources": list(evidence_sources),
                    "merge_confidence": "100%",
                    "merge_status": "Original",
                    "unique_component_id": str(uuid.uuid4())
                }
                correlated_components[norm_purl] = unified_comp
                trivy_to_unified_ref[trivy_ref] = unified_comp["bom-ref"]

    # 3. Process Vulnerability Array (Trivy -> Unified refs mapping)
    trivy_vulns = trivy_data.get('vulnerabilities', [])
    unified_vulns = []
    
    for vuln in trivy_vulns:
        vuln_copy = json.loads(json.dumps(vuln)) # Deep copy
        affects = vuln_copy.get('affects', [])
        new_affects = []
        
        for a in affects:
            trivy_ref = a.get('ref')
            if trivy_ref in trivy_to_unified_ref:
                a['ref'] = trivy_to_unified_ref[trivy_ref]
                new_affects.append(a)
                
        if new_affects:
            vuln_copy['affects'] = new_affects
            unified_vulns.append(vuln_copy)

    # 4. Reconcile Dependencies and Eliminate Cycles (DAG Rebuild)
    # Combine dependencies lists
    combined_deps = {}
    
    # Process Syft dependencies
    for dep in syft_data.get('dependencies', []):
        ref = dep.get('ref')
        unified_ref = syft_to_unified_ref.get(ref, ref)
        depends_on = [syft_to_unified_ref.get(d, d) for d in dep.get('dependsOn', [])]
        
        if unified_ref not in combined_deps:
            combined_deps[unified_ref] = set()
        combined_deps[unified_ref].update(depends_on)
        
    # Process Trivy dependencies
    for dep in trivy_data.get('dependencies', []):
        ref = dep.get('ref')
        unified_ref = trivy_to_unified_ref.get(ref, ref)
        depends_on = [trivy_to_unified_ref.get(d, d) for d in dep.get('dependsOn', [])]
        
        if unified_ref not in combined_deps:
            combined_deps[unified_ref] = set()
        combined_deps[unified_ref].update(depends_on)
        
    # Eliminate dependency cycles (simple DFS cycle finder)
    final_dependencies = []
    visited = {}
    path = set()
    
    def dfs_remove_cycles(node):
        visited[node] = True
        path.add(node)
        
        valid_depends = []
        for neighbor in list(combined_deps.get(node, [])):
            if neighbor in path:
                # Cycle detected! Break this edge
                print(f"Warning: Circular dependency loop detected ({node} -> {neighbor}). Breaking loop.")
                continue
            if neighbor not in visited:
                dfs_remove_cycles(neighbor)
            valid_depends.append(neighbor)
            
        path.remove(node)
        final_dependencies.append({
            "ref": node,
            "dependsOn": valid_depends
        })
        
    for node in list(combined_deps.keys()):
        if node not in visited:
            dfs_remove_cycles(node)

    # 5. Compile final raw merged CycloneDX structure
    components_list = list(correlated_components.values())
    
    # Store merge metadata details in custom properties at metadata level
    metadata = {
        "timestamp": trivy_data.get('metadata', {}).get('timestamp') or syft_data.get('metadata', {}).get('timestamp'),
        "tools": {
            "components": [
                {
                    "type": "application",
                    "name": "Enterprise SBOM Merge Engine",
                    "version": "1.0.0"
                }
            ]
        },
        "component": {
            "bom-ref": "unified-project",
            "type": "application",
            "name": syft_data.get('metadata', {}).get('component', {}).get('name', 'merged_project')
        },
        "properties": [
            {"name": "merge_engine:syft_total", "value": str(syft_count)},
            {"name": "merge_engine:trivy_total", "value": str(trivy_count)},
            {"name": "merge_engine:common_total", "value": str(common_count)},
            {"name": "merge_engine:unique_final", "value": str(len(components_list))}
        ]
    }
    
    merged_sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": metadata,
        "components": components_list,
        "dependencies": final_dependencies,
        "vulnerabilities": unified_vulns
    }
    
    # 6. Save output
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(merged_sbom, f, indent=2)
        
    print(f"Successfully generated merged raw SBOM file: {output_path}")
    print(f" - Syft components: {syft_count}")
    print(f" - Trivy components: {trivy_count}")
    print(f" - Correlated & Merged: {common_count}")
    print(f" - Final unique components: {len(components_list)}")
    print(f" - Reconciled vulnerabilities: {len(unified_vulns)}")

def main():
    parser = argparse.ArgumentParser(description="Enterprise SBOM Correlation & Merge Engine")
    parser.add_argument("--syft", required=True, help="Path to Syft raw JSON")
    parser.add_argument("--trivy", required=True, help="Path to Trivy raw JSON")
    parser.add_argument("--config", required=True, help="Path to config JSON")
    parser.add_argument("--output", required=True, help="Output path for merged JSON SBOM")
    
    args = parser.parse_args()
    
    merge_sboms(args.syft, args.trivy, args.config, args.output)

if __name__ == "__main__":
    main()
