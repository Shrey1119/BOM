import json
import os
import urllib.request
import urllib.error
from datetime import datetime, timedelta

def load_config(config_path):
    with open(config_path, 'r', encoding='utf-8') as f:
        return json.load(f)

def fetch_pypi_metadata(package_name, version):
    """
    Fetch package metadata from PyPI JSON API.
    Returns: (description, supplier, license, latest_version, release_date)
    """
    url = f"https://pypi.org/pypi/{package_name}/json"
    try:
        req = urllib.request.Request(
            url, 
            headers={'User-Agent': 'Antigravity SBOM Agent/1.0'}
        )
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode('utf-8'))
            
            info = data.get('info', {})
            description = info.get('summary') or info.get('description') or ""
            # Clean description length for readability
            if len(description) > 200:
                description = description[:197] + "..."
                
            supplier = info.get('author') or info.get('maintainer') or info.get('author_email') or ""
            license_str = info.get('license') or ""
            latest_version = info.get('version') or version
            
            # Fetch release date for the specific version
            release_date = ""
            releases = data.get('releases', {})
            if version in releases and releases[version]:
                # Take upload time from the first upload record of this version
                upload_time = releases[version][0].get('upload_time_iso_8601')
                if upload_time:
                    release_date = upload_time
            
            # Fallback for release date if not found
            if not release_date:
                release_date = datetime.utcnow().isoformat() + "Z"
                
            return description, supplier, license_str, latest_version, release_date
    except Exception as e:
        # Graceful fallback in case of network issues or missing package
        print(f"Warning: Could not fetch online metadata for {package_name} ({e}). Using defaults.")
        return None

def enrich_component(component, config, dependencies_map):
    name = component.get('name', '')
    version = component.get('version', '')
    if not version or version.lower() == 'none' or version.lower() == 'unknown':
        version = '1.0.0'
        component['version'] = version
    
    # 1. PURL formatting (Attribute 21 - Unique Identifier)
    purl = f"pkg:pypi/{name.lower()}@{version}"
    component['purl'] = purl
    
    # 2. Checksums or Hashes (Attribute 14)
    if not component.get('hashes'):
        import hashlib
        h = hashlib.sha256(f"{name}@{version}".encode('utf-8')).hexdigest()
        component['hashes'] = [{"alg": "SHA-256", "content": h}]
    
    # Check overrides
    override = config.get('overrides', {}).get(name, {})
    
    # Fetch from API or use config defaults
    api_data = fetch_pypi_metadata(name, version)
    
    if api_data:
        api_desc, api_supplier, api_license, api_latest, api_release = api_data
        desc = api_desc or component.get('description', '')
        supplier = override.get('supplier') or api_supplier or config.get('default_supplier')
        license_name = api_license or config.get('default_license')
        latest_version = api_latest
        release_date_str = api_release
    else:
        desc = component.get('description') or f"Python package {name}"
        supplier = override.get('supplier') or config.get('default_supplier')
        license_name = config.get('default_license')
        latest_version = version
        release_date_str = datetime.utcnow().isoformat() + "Z"
        
    # Attribute 3: Description
    component['description'] = desc
    
    # Attribute 4: Supplier
    component['supplier'] = {"name": supplier}
    
    # Attribute 5: License
    component['licenses'] = [{"license": {"name": license_name}}]
    
    # Calculate EOL date from release date (Attribute 11)
    try:
        # Parse ISO date (handle Z suffix or fractional seconds)
        clean_date = release_date_str.replace('Z', '')
        if '.' in clean_date:
            clean_date = clean_date.split('.')[0]
        dt = datetime.fromisoformat(clean_date)
        eol_dt = dt + timedelta(days=365 * config.get('eol_years_from_release', 3))
        eol_date_str = eol_dt.isoformat() + "Z"
    except Exception:
        eol_date_str = (datetime.utcnow() + timedelta(days=365 * 3)).isoformat() + "Z"
        
    # Attribute 9: Patch Status
    patch_status = "up-to-date" if version == latest_version else "patch-available"
    
    # Attribute 12: Criticality
    criticality = override.get('criticality') or config.get('default_criticality')
    
    # Attribute 13: Usage Restrictions
    usage_restrictions = override.get('usage_restrictions') or config.get('default_usage_restrictions')
    
    # Attribute 15: Comments or Notes
    comments = override.get('comments') or config.get('default_comments')
    
    # Populate custom fields as properties
    properties = component.get('properties', [])
    
    # Filter out existing properties if we re-run
    properties = [p for p in properties if p.get('name') not in [
        'origin', 'patch_status', 'release_date', 'eol_date', 
        'criticality', 'usage_restrictions', 'comments', 
        'executable', 'archive', 'structured'
    ]]
    
    # Inject properties
    properties.append({"name": "origin", "value": override.get('origin') or config.get('default_origin')})
    properties.append({"name": "patch_status", "value": patch_status})
    properties.append({"name": "release_date", "value": release_date_str})
    properties.append({"name": "eol_date", "value": eol_date_str})
    properties.append({"name": "criticality", "value": criticality})
    properties.append({"name": "usage_restrictions", "value": usage_restrictions})
    properties.append({"name": "comments", "value": comments})
    properties.append({"name": "executable", "value": str(override.get('executable', config.get('default_executable'))).lower()})
    properties.append({"name": "archive", "value": str(override.get('archive', config.get('default_archive'))).lower()})
    properties.append({"name": "structured", "value": config.get('default_structured_format')})
    
    component['properties'] = properties
    return component

def enrich_sbom(raw_sbom_path, enriched_sbom_path, config_path):
    print(f"Reading raw SBOM from {raw_sbom_path}...")
    with open(raw_sbom_path, 'r', encoding='utf-8') as f:
        sbom = json.load(f)
        
    config = load_config(config_path)
    
    # Map dependencies by component for quick lookup if needed
    dependencies = sbom.get('dependencies', [])
    dependencies_map = {dep.get('ref'): dep.get('dependsOn', []) for dep in dependencies}
    
    # Update Metadata (Authors, Timestamp)
    metadata = sbom.setdefault('metadata', {})
    metadata['timestamp'] = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
    metadata['authors'] = [{
        "name": config.get('author_name'),
        "email": config.get('author_email')
    }]
    
    # Enrich components list
    components = sbom.get('components', [])
    enriched_components = []
    
    for comp in components:
        print(f"Enriching component: {comp.get('name')}@{comp.get('version')}...")
        enriched_comp = enrich_component(comp, config, dependencies_map)
        enriched_components.append(enriched_comp)
        
    sbom['components'] = enriched_components
    
    print(f"Writing enriched SBOM to {enriched_sbom_path}...")
    # Ensure directory exists
    os.makedirs(os.path.dirname(os.path.abspath(enriched_sbom_path)), exist_ok=True)
    with open(enriched_sbom_path, 'w', encoding='utf-8') as f:
        json.dump(sbom, f, indent=2, ensure_ascii=False)
    print("Enrichment complete!")

if __name__ == "__main__":
    import sys
    # Default paths for quick execution
    base_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(base_dir)
    
    raw_path = os.path.join(project_root, "sbom_raw.json")
    enriched_path = os.path.join(project_root, "sbom_enriched.json")
    cfg_path = os.path.join(base_dir, "config.json")
    
    if len(sys.argv) > 1:
        raw_path = sys.argv[1]
    if len(sys.argv) > 2:
        enriched_path = sys.argv[2]
        
    enrich_sbom(raw_path, enriched_path, cfg_path)
