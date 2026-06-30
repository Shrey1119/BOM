import json
import os
import sys
import argparse
import uuid


def normalize_purl(purl):
    """Normalize PURL string for matching."""
    if not purl:
        return ""
    purl_clean = purl.split('?')[0].lower()
    return purl_clean


def clean_name(name):
    """Clean package names for comparison."""
    if not name:
        return ""
    return name.strip().lower()


# ══════════════════════════════════════════════════════════════════
# Pre-filter: Remove noise components that are not real packages
# ══════════════════════════════════════════════════════════════════
def is_noise_component(comp):
    """Return True if this component is scanner noise and should be discarded.

    Filters out:
    - Components with type 'application' (manifest files like requirements.txt)
    - Components with no PURL AND no version (or version is '?' / 'unknown')
    - Components whose name starts with './' (Syft filesystem path artifacts)
    - Components whose name looks like a file path (contains '/' and ends with
      common config/lockfile extensions)
    """
    comp_type = (comp.get('type') or '').lower()
    name = comp.get('name') or ''
    version = comp.get('version') or ''
    purl = comp.get('purl') or ''

    # 1. Manifest / application type entries are not packages
    if comp_type == 'application':
        return True

    # 2. Filesystem path artifacts from Syft (e.g. ./.github/actions/...)
    if name.startswith('./'):
        return True

    # 3. No PURL and no usable version = unidentifiable
    if not purl and (not version or version in ('?', 'unknown', 'None', '')):
        return True

    # 4. Lockfile / config file names sneaking in as components
    noise_suffixes = ('.yaml', '.yml', '.json', '.toml', '.txt', '.lock', '.cfg')
    if '/' in name and name.lower().endswith(noise_suffixes):
        return True

    return False


def filter_and_dedup(components, scanner_name):
    """Filter noise components and deduplicate by normalized PURL.

    Returns:
        (clean_list, stats_dict) where stats_dict has counts of
        noise_removed and intra_duplicates_removed.
    """
    noise_removed = 0
    intra_dups = 0
    seen_purls = {}
    clean = []

    for comp in components:
        if is_noise_component(comp):
            noise_removed += 1
            continue

        purl = comp.get('purl', '')
        norm = normalize_purl(purl) if purl else None

        # Deduplicate within this scanner by normalized PURL
        if norm and norm in seen_purls:
            intra_dups += 1
            continue

        if norm:
            seen_purls[norm] = True
        clean.append(comp)

    stats = {
        'original': len(components),
        'noise_removed': noise_removed,
        'intra_dups': intra_dups,
        'clean': len(clean),
    }

    if noise_removed > 0 or intra_dups > 0:
        print(f"  [{scanner_name}] Filtered: {noise_removed} noise, {intra_dups} intra-duplicates "
              f"({len(components)} -> {len(clean)} components)")

    return clean, stats

def merge_components(syft_grype_comps, trivy_comps, cdxgen_comps):
    """Deduplicate and merge component lists from all three scanners.

    Pre-filters noise components, deduplicates within each scanner,
    then performs cross-scanner PURL-exact and fuzzy name+version merging.
    Copies hashes from cdxgen into entries that lack them.
    """
    # ── Pre-filter and intra-dedup each scanner ──
    syft_grype_comps, syft_stats = filter_and_dedup(syft_grype_comps, "Syft+Grype")
    trivy_comps, trivy_stats = filter_and_dedup(trivy_comps, "Trivy")
    cdxgen_comps, cdxgen_stats = filter_and_dedup(cdxgen_comps, "cdxgen")

    unified_components = {}
    
    # 1. Ingest Syft + Grype
    for comp in syft_grype_comps:
        name = comp.get('name')
        version = comp.get('version', 'unknown')
        purl = comp.get('purl', '')
        bom_ref = comp.get('bom-ref') or purl or f"pkg:generic/{clean_name(name)}@{version}"
        
        norm_purl = normalize_purl(purl) if purl else f"pkg:generic/{clean_name(name)}@{version}".lower()
        
        # Build evidence sources from paths in properties
        evidence_sources = set()
        properties = comp.get('properties', [])
        for prop in properties:
            if 'path' in prop.get('name', ''):
                evidence_sources.add(prop.get('value'))
        if not evidence_sources:
            evidence_sources.add("Syft Scan Discovery")
            
        cpes = []
        if comp.get('cpe'):
            cpes.append(comp.get('cpe'))
        for prop in properties:
            if prop.get('name') == 'syft:cpe23':
                cpes.append(prop.get('value'))
        cpes = list(sorted(set(cpes)))
        
        unified_comp = {
            "bom-ref": bom_ref,
            "type": comp.get('type', 'library'),
            "name": name,
            "version": version,
            "purl": purl or bom_ref,
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
        unified_components[norm_purl] = unified_comp

    # 2. Merge Trivy Components
    for comp in trivy_comps:
        name = comp.get('name')
        version = comp.get('version', 'unknown')
        purl = comp.get('purl', '')
        bom_ref = comp.get('bom-ref') or purl or f"pkg:generic/{clean_name(name)}@{version}"
        norm_purl = normalize_purl(purl) if purl else f"pkg:generic/{clean_name(name)}@{version}".lower()
        
        evidence_sources = set()
        properties = comp.get('properties', [])
        for prop in properties:
            if 'class' in prop.get('name', '').lower() or 'path' in prop.get('name', '').lower():
                evidence_sources.add(prop.get('value'))
        if not evidence_sources:
            evidence_sources.add("Trivy Scan Discovery")
            
        # Match check: exact PURL
        if norm_purl in unified_components:
            existing = unified_components[norm_purl]
            if "trivy" not in existing["detected_by"]:
                existing["detected_by"].append("trivy")
            existing["merge_status"] = "Merged"
            existing["evidence_sources"] = list(set(existing["evidence_sources"]).union(evidence_sources))
            
            # Combine properties without duplicates
            existing_prop_names = {p.get('name') for p in existing["properties"]}
            for p in properties:
                if p.get('name') not in existing_prop_names:
                    existing["properties"].append(p)
                    
            if not existing.get('description') and comp.get('description'):
                existing['description'] = comp.get('description')
            if not existing.get('licenses') and comp.get('licenses'):
                existing['licenses'] = comp.get('licenses')
            if not existing.get('supplier') and comp.get('supplier'):
                existing['supplier'] = comp.get('supplier')
        else:
            # Fuzzy match by name and version
            fuzzy_match = None
            for key, val in unified_components.items():
                if clean_name(val['name']) == clean_name(name) and val['version'] == version:
                    fuzzy_match = val
                    break
                    
            if fuzzy_match:
                if "trivy" not in fuzzy_match["detected_by"]:
                    fuzzy_match["detected_by"].append("trivy")
                fuzzy_match["merge_status"] = "Merged (Fuzzy Name/Version)"
                fuzzy_match["merge_confidence"] = "75%"
                fuzzy_match["evidence_sources"] = list(set(fuzzy_match["evidence_sources"]).union(evidence_sources))
                
                existing_prop_names = {p.get('name') for p in fuzzy_match["properties"]}
                for p in properties:
                    if p.get('name') not in existing_prop_names:
                        fuzzy_match["properties"].append(p)
            else:
                # Add new component unique to Trivy
                unified_comp = {
                    "bom-ref": bom_ref,
                    "type": comp.get('type', 'library'),
                    "name": name,
                    "version": version,
                    "purl": purl or bom_ref,
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
                unified_components[norm_purl] = unified_comp

    # 3. Merge cdxgen Components
    for comp in cdxgen_comps:
        name = comp.get('name')
        version = comp.get('version', 'unknown')
        purl = comp.get('purl', '')
        bom_ref = comp.get('bom-ref') or purl or f"pkg:generic/{clean_name(name)}@{version}"
        norm_purl = normalize_purl(purl) if purl else f"pkg:generic/{clean_name(name)}@{version}".lower()
        
        evidence_sources = set()
        properties = comp.get('properties', [])
        # Extract reachability/evidence properties if present
        for prop in properties:
            if 'evidence' in prop.get('name', '').lower() or 'path' in prop.get('name', '').lower():
                evidence_sources.add(prop.get('value'))
        if not evidence_sources:
            evidence_sources.add("cdxgen Scan Discovery")
            
        if norm_purl in unified_components:
            existing = unified_components[norm_purl]
            if "cdxgen" not in existing["detected_by"]:
                existing["detected_by"].append("cdxgen")
            existing["merge_status"] = "Merged"
            existing["evidence_sources"] = list(set(existing["evidence_sources"]).union(evidence_sources))
            
            # ── Copy hashes from cdxgen if existing has none ──
            cdxgen_hashes = comp.get('hashes', [])
            if cdxgen_hashes and not existing.get('hashes'):
                existing['hashes'] = cdxgen_hashes

            # ── Copy evidence block from cdxgen if it exists ──
            if comp.get('evidence'):
                existing['evidence'] = comp.get('evidence')

            existing_prop_names = {p.get('name') for p in existing["properties"]}
            for p in properties:
                if p.get('name') not in existing_prop_names:
                    existing["properties"].append(p)
        else:
            fuzzy_match = None
            for key, val in unified_components.items():
                if clean_name(val['name']) == clean_name(name) and val['version'] == version:
                    fuzzy_match = val
                    break
                    
            if fuzzy_match:
                if "cdxgen" not in fuzzy_match["detected_by"]:
                    fuzzy_match["detected_by"].append("cdxgen")
                fuzzy_match["merge_status"] = "Merged (Fuzzy Name/Version)"
                fuzzy_match["merge_confidence"] = "75%"
                fuzzy_match["evidence_sources"] = list(set(fuzzy_match["evidence_sources"]).union(evidence_sources))
                
                # ── Copy hashes from cdxgen if fuzzy match has none ──
                cdxgen_hashes = comp.get('hashes', [])
                if cdxgen_hashes and not fuzzy_match.get('hashes'):
                    fuzzy_match['hashes'] = cdxgen_hashes

                # ── Copy evidence block from cdxgen if it exists ──
                if comp.get('evidence'):
                    fuzzy_match['evidence'] = comp.get('evidence')

                existing_prop_names = {p.get('name') for p in fuzzy_match["properties"]}
                for p in properties:
                    if p.get('name') not in existing_prop_names:
                        fuzzy_match["properties"].append(p)
            else:
                unified_comp = {
                    "bom-ref": bom_ref,
                    "type": comp.get('type', 'library'),
                    "name": name,
                    "version": version,
                    "purl": purl or bom_ref,
                    "cpe": comp.get('cpe'),
                    "cpes": [comp.get('cpe')] if comp.get('cpe') else [],
                    "hashes": comp.get('hashes', []),
                    "licenses": comp.get('licenses', []),
                    "description": comp.get('description', ''),
                    "supplier": comp.get('supplier', {}),
                    "properties": properties,
                    "detected_by": ["cdxgen"],
                    "evidence_sources": list(evidence_sources),
                    "merge_confidence": "100%",
                    "merge_status": "Original",
                    "unique_component_id": str(uuid.uuid4())
                }
                if comp.get('evidence'):
                    unified_comp['evidence'] = comp.get('evidence')
                unified_components[norm_purl] = unified_comp

    return list(unified_components.values())

def merge_sboms(syft_grype_path, trivy_path, cdxgen_path, output_path):
    """Loads raw SBOMs, merges them and saves unified master CycloneDX."""
    print(f"Merging SBOM inputs:\n - Syft+Grype: {syft_grype_path}\n - Trivy: {trivy_path}\n - cdxgen: {cdxgen_path}")
    
    with open(syft_grype_path, 'r', encoding='utf-8') as f:
        syft_data = json.load(f)
    with open(trivy_path, 'r', encoding='utf-8') as f:
        trivy_data = json.load(f)
    with open(cdxgen_path, 'r', encoding='utf-8') as f:
        cdxgen_data = json.load(f)
        
    syft_comps = syft_data.get('components', [])
    trivy_comps = trivy_data.get('components', [])
    cdxgen_comps = cdxgen_data.get('components', [])
    
    # 1. Merge all components
    merged_comps = merge_components(syft_comps, trivy_comps, cdxgen_comps)
    
    # Map raw refs to unified refs for dependency mappings and vulnerabilities
    ref_map = {}
    for comp in merged_comps:
        purl = comp.get('purl')
        name = comp.get('name')
        version = comp.get('version')
        
        # Match against raw components to construct ref translations
        for rc in syft_comps:
            if rc.get('purl') == purl or (clean_name(rc.get('name')) == clean_name(name) and rc.get('version') == version):
                ref_map[rc.get('bom-ref') or rc.get('purl')] = comp.get('bom-ref')
                
        for rc in trivy_comps:
            if rc.get('purl') == purl or (clean_name(rc.get('name')) == clean_name(name) and rc.get('version') == version):
                ref_map[rc.get('bom-ref') or rc.get('purl')] = comp.get('bom-ref')
                
        for rc in cdxgen_comps:
            if rc.get('purl') == purl or (clean_name(rc.get('name')) == clean_name(name) and rc.get('version') == version):
                ref_map[rc.get('bom-ref') or rc.get('purl')] = comp.get('bom-ref')

    # 2. Merge dependencies and clean cycles
    combined_deps = {}
    
    def ingest_deps(deps_list, r_map):
        for dep in deps_list:
            ref = dep.get('ref')
            unified_ref = r_map.get(ref, ref)
            depends_on = [r_map.get(d, d) for d in dep.get('dependsOn', [])]
            
            if unified_ref not in combined_deps:
                combined_deps[unified_ref] = set()
            combined_deps[unified_ref].update(depends_on)
            
    ingest_deps(syft_data.get('dependencies', []), ref_map)
    ingest_deps(trivy_data.get('dependencies', []), ref_map)
    ingest_deps(cdxgen_data.get('dependencies', []), ref_map)
    
    # DFS cycle removal
    final_dependencies = []
    visited = {}
    path = set()
    
    def dfs_remove_cycles(node):
        visited[node] = True
        path.add(node)
        
        valid_depends = []
        for neighbor in list(combined_deps.get(node, [])):
            if neighbor in path:
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

    # Ensure all merged components are present in the final dependencies list
    # (CycloneDX schema and CERT-In validation require every component to have a mapping)
    existing_dep_refs = {d.get('ref') for d in final_dependencies}
    for comp in merged_comps:
        comp_ref = comp.get('bom-ref')
        if comp_ref and comp_ref not in existing_dep_refs:
            final_dependencies.append({
                "ref": comp_ref,
                "dependsOn": []
            })

    # 3. Merge Vulnerabilities
    unified_vulns = {}
    
    def ingest_vulns(vulns_list, r_map):
        for vuln in vulns_list:
            vuln_id = vuln.get('id')
            if not vuln_id:
                continue
            
            # Map affects refs to unified refs
            affects_list = []
            for affect in vuln.get('affects', []):
                raw_ref = affect.get('ref')
                mapped_ref = r_map.get(raw_ref, raw_ref)
                
                # Check if this component exists in our merged components
                matched_comp_ref = None
                for c in merged_comps:
                    if c.get('bom-ref') == mapped_ref or c.get('purl') == mapped_ref:
                        matched_comp_ref = c.get('bom-ref')
                        break
                
                if matched_comp_ref:
                    affect_copy = affect.copy()
                    affect_copy['ref'] = matched_comp_ref
                    affects_list.append(affect_copy)
            
            if affects_list:
                if vuln_id not in unified_vulns:
                    vuln_copy = json.loads(json.dumps(vuln))
                    vuln_copy['affects'] = affects_list
                    unified_vulns[vuln_id] = vuln_copy
                else:
                    # Append affects from another tool without duplicating
                    existing_aff_refs = {a.get('ref') for a in unified_vulns[vuln_id]['affects']}
                    for a in affects_list:
                        if a.get('ref') not in existing_aff_refs:
                            unified_vulns[vuln_id]['affects'].append(a)
                            existing_aff_refs.add(a.get('ref'))

    ingest_vulns(syft_data.get('vulnerabilities', []), ref_map)
    ingest_vulns(trivy_data.get('vulnerabilities', []), ref_map)
    ingest_vulns(cdxgen_data.get('vulnerabilities', []), ref_map)

    # 4. Compose Metadata and properties
    syft_count = len(syft_comps)
    trivy_count = len(trivy_comps)
    cdxgen_count = len(cdxgen_comps)
    common_count = sum(1 for c in merged_comps if len(c.get('detected_by', [])) > 1)
    
    metadata = {
        "timestamp": trivy_data.get('metadata', {}).get('timestamp') or cdxgen_data.get('metadata', {}).get('timestamp'),
        "tools": {
            "components": [
                {
                    "type": "application",
                    "name": "Enterprise SBOM Merge Engine (manifest-cli logic)",
                    "version": "2.0.0"
                }
            ]
        },
        "component": {
            "bom-ref": "unified-project",
            "type": "application",
            "name": trivy_data.get('metadata', {}).get('component', {}).get('name', 'merged_project')
        },
        "properties": [
            {"name": "merge_engine:syft_total", "value": str(syft_count)},
            {"name": "merge_engine:trivy_total", "value": str(trivy_count)},
            {"name": "merge_engine:cdxgen_total", "value": str(cdxgen_count)},
            {"name": "merge_engine:common_total", "value": str(common_count)},
            {"name": "merge_engine:unique_final", "value": str(len(merged_comps))}
        ]
    }

    merged_sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": metadata,
        "components": merged_comps,
        "dependencies": final_dependencies,
        "vulnerabilities": list(unified_vulns.values())
    }

    # Save output
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(merged_sbom, f, indent=2)

    # ── Merge Quality Metrics ──
    with_hash = sum(1 for c in merged_comps if c.get('hashes'))
    with_purl = sum(1 for c in merged_comps if c.get('purl'))
    multi_scanner = sum(1 for c in merged_comps if len(c.get('detected_by', [])) >= 2)
    triple_scanner = sum(1 for c in merged_comps if len(c.get('detected_by', [])) >= 3)

    print(f"")
    if sys.stdout.isatty():
        print(f"  ┌──────────────────────────────────────────────────┐")
        print(f"  │  MERGE ENGINE — QUALITY REPORT                   │")
        print(f"  ├──────────────────────────────────────────────────┤")
        print(f"  │  Syft+Grype input (after filter): {syft_count:>5}          │")
        print(f"  │  Trivy input (after filter)     : {trivy_count:>5}          │")
        print(f"  │  cdxgen input (after filter)    : {cdxgen_count:>5}          │")
        print(f"  ├──────────────────────────────────────────────────┤")
        print(f"  │  Final unique components        : {len(merged_comps):>5}          │")
        print(f"  │  Correlated (2+ scanners)       : {multi_scanner:>5}          │")
        print(f"  │  Triple-confirmed (3 scanners)  : {triple_scanner:>5}          │")
        print(f"  │  With cryptographic hashes      : {with_hash:>5}          │")
        print(f"  │  With valid PURL                : {with_purl:>5}          │")
        print(f"  │  Reconciled vulnerabilities     : {len(unified_vulns):>5}          │")
        print(f"  └──────────────────────────────────────────────────┘")
    else:
        print(f"  +--------------------------------------------------+")
        print(f"  |  MERGE ENGINE - QUALITY REPORT                   |")
        print(f"  +--------------------------------------------------+")
        print(f"  |  Syft+Grype input (after filter): {syft_count:>5}          |")
        print(f"  |  Trivy input (after filter)     : {trivy_count:>5}          |")
        print(f"  |  cdxgen input (after filter)    : {cdxgen_count:>5}          |")
        print(f"  +--------------------------------------------------+")
        print(f"  |  Final unique components        : {len(merged_comps):>5}          |")
        print(f"  |  Correlated (2+ scanners)       : {multi_scanner:>5}          |")
        print(f"  |  Triple-confirmed (3 scanners)  : {triple_scanner:>5}          |")
        print(f"  |  With cryptographic hashes      : {with_hash:>5}          |")
        print(f"  |  With valid PURL                : {with_purl:>5}          |")
        print(f"  |  Reconciled vulnerabilities     : {len(unified_vulns):>5}          |")
        print(f"  +--------------------------------------------------+")
    print(f"")
    print(f"  Output: {output_path}")

def main():
    parser = argparse.ArgumentParser(description="Programmatic manifest-cli SBOM Merger")
    parser.add_argument("--syft-grype", required=True, help="Path to Syft+Grype CycloneDX JSON")
    parser.add_argument("--trivy", required=True, help="Path to Trivy CycloneDX JSON")
    parser.add_argument("--cdxgen", required=True, help="Path to cdxgen CycloneDX JSON")
    parser.add_argument("--output", required=True, help="Output path for merged JSON SBOM")
    
    args = parser.parse_args()
    
    merge_sboms(args.syft_grype, args.trivy, args.cdxgen, args.output)

if __name__ == "__main__":
    main()
