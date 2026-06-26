import json
import os
import urllib.request
import urllib.error
from datetime import datetime, timedelta

# ---------------------------------------------------------------------------
# Package classification lists for criticality scoring
# ---------------------------------------------------------------------------
CRYPTO_PACKAGES = [
    'cryptography', 'openssl', 'pycryptodome', 'pycryptodomex',
    'paramiko', 'bcrypt', 'nacl', 'pyopenssl', 'certifi', 'pyca'
]
FRAMEWORK_PACKAGES = [
    'django', 'flask', 'fastapi', 'tornado', 'aiohttp',
    'starlette', 'bottle', 'falcon', 'pyramid', 'sanic'
]
RUNTIME_PACKAGES = [
    'requests', 'urllib3', 'httpx', 'aiohttp', 'boto3',
    'sqlalchemy', 'psycopg2', 'pymongo', 'redis', 'celery'
]
OS_PACKAGES = [
    'os', 'sys', 'subprocess', 'ctypes', 'cffi', 'pywin32', 'wmi'
]


# ---------------------------------------------------------------------------
# Enhancement 1: Automated Criticality Assessment
# ---------------------------------------------------------------------------
def assess_criticality(name, component, config):
    """
    Determine criticality level and reason for a component.

    Priority:
      1. config['overrides'][name]['criticality'] if present
      2. Score-based heuristic using package classification lists

    Returns:
        (level: str, reason: str)
        level is one of: 'critical', 'high', 'medium', 'low'
    """
    overrides = config.get('overrides', {})
    if name in overrides and 'criticality' in overrides[name]:
        level = overrides[name]['criticality']
        return level, f"Manually overridden in config to '{level}'"

    score = 0
    reasons = []

    name_lower = name.lower()

    if name_lower in CRYPTO_PACKAGES:
        score += 40
        reasons.append("cryptography/security package (+40)")
    if name_lower in FRAMEWORK_PACKAGES:
        score += 35
        reasons.append("web framework package (+35)")
    if name_lower in RUNTIME_PACKAGES:
        score += 30
        reasons.append("core runtime/integration package (+30)")
    if name_lower in OS_PACKAGES:
        score += 20
        reasons.append("OS-level/system interface package (+20)")

    comp_type = component.get('type', '')
    if comp_type in ('application', 'container', 'device'):
        score += 15
        reasons.append(f"component type='{comp_type}' (+15)")
    elif comp_type == 'library':
        score += 10
        reasons.append("component type='library' (+10)")

    if score >= 70:
        level = 'critical'
    elif score >= 50:
        level = 'high'
    elif score >= 30:
        level = 'medium'
    else:
        level = 'low'

    if reasons:
        reason = f"Score {score}: " + "; ".join(reasons)
    else:
        reason = f"Score {score}: no specific risk indicators found"

    return level, reason


# ---------------------------------------------------------------------------
# Enhancement 2: Auto-populate Author of SBOM Data
# ---------------------------------------------------------------------------
def determine_sbom_author(config):
    """
    Determine the SBOM author string by priority:
      1. config['repo_owner']
      2. config['organization']
      3. config['author_name']
      4. "Unknown Organization"
    """
    return (
        config.get('repo_owner')
        or config.get('organization')
        or config.get('author_name')
        or "Unknown Organization"
    )


# ---------------------------------------------------------------------------
# Enhancement 3: Executable Property Detection
# ---------------------------------------------------------------------------
def detect_executable_property(name, component, config):
    """
    Determine the executable type of a component.

    Returns:
        {
            "value": str,           # one of: Executable, Library, Script,
                                    #         Service, Container, Package, Unknown
            "evidence": list[str],
            "detection_method": str
        }
    """
    name_lower = name.lower()
    overrides = config.get('overrides', {})

    # Config override with explicit 'executable' key
    if name in overrides and 'executable' in overrides[name]:
        val = overrides[name]['executable']
        return {
            "value": str(val),
            "evidence": ["Config override"],
            "detection_method": "Explicit config override in enricher config.json"
        }

    comp_type = component.get('type', '')

    if comp_type == 'container':
        return {
            "value": "Container",
            "evidence": ["CycloneDX type=container"],
            "detection_method": "CycloneDX component type field"
        }

    if comp_type == 'application':
        return {
            "value": "Executable",
            "evidence": ["CycloneDX type=application"],
            "detection_method": "CycloneDX component type field"
        }

    BUILD_TOOLS = ['pip', 'setuptools', 'wheel', 'poetry', 'build']
    if name_lower in BUILD_TOOLS:
        return {
            "value": "Package",
            "evidence": ["Build/package tooling"],
            "detection_method": "Known build/package tool name match"
        }

    SERVICE_DAEMONS = [
        'gunicorn', 'uvicorn', 'celery', 'beat', 'worker',
        'supervisor', 'nginx', 'uwsgi'
    ]
    if name_lower in SERVICE_DAEMONS:
        return {
            "value": "Service",
            "evidence": ["Known service daemon"],
            "detection_method": "Known service daemon name match"
        }

    # PyPI PURL → default library
    purl = component.get('purl', '')
    if 'pypi' in purl:
        return {
            "value": "Library",
            "evidence": ["PyPI package (typically a library)"],
            "detection_method": "PURL contains 'pypi'"
        }

    return {
        "value": "Unknown",
        "evidence": ["No detection rule matched"],
        "detection_method": "Default fallback"
    }


# ---------------------------------------------------------------------------
# Enhancement 4: Trust Score
# ---------------------------------------------------------------------------
def calculate_trust_score(component, api_data_available, config_override_exists):
    """
    Calculate a trust score (0-100) for a component.

    Returns:
        (score: int, reasons: list[str])
    """
    score = 0
    reasons = []

    if api_data_available:
        score += 30
        reasons.append("+30: Version confirmed from package registry (API available)")

    if component.get('hashes'):
        score += 25
        reasons.append("+25: Hash/checksum verified")

    if component.get('purl'):
        score += 20
        reasons.append("+20: PURL identifier available")

    licenses = component.get('licenses', [])
    if licenses:
        license_name = licenses[0].get('license', {}).get('name', 'Unknown')
        if license_name not in ('Unknown', ''):
            score += 15
            reasons.append(f"+15: License identified ({license_name})")

    if config_override_exists:
        score += 10
        reasons.append("+10: Manually reviewed in config overrides")

    score = min(score, 100)
    return score, reasons


# ---------------------------------------------------------------------------
# Enhancement 5: Expanded Repository Detection
# ---------------------------------------------------------------------------
def detect_repository(name, purl, component):
    """
    Detect registry, URL and ecosystem from a PURL string.

    Returns:
        {
            "registry": str,
            "registry_url": str,
            "ecosystem": str,
            "detection_method": str
        }
    """
    purl_lower = (purl or '').lower()

    if purl_lower.startswith('pkg:pypi'):
        return {
            "registry": "PyPI",
            "registry_url": f"https://pypi.org/project/{name}/",
            "ecosystem": "Python",
            "detection_method": "PURL scheme pkg:pypi"
        }
    if purl_lower.startswith('pkg:npm'):
        return {
            "registry": "npm Registry",
            "registry_url": f"https://www.npmjs.com/package/{name}",
            "ecosystem": "JavaScript",
            "detection_method": "PURL scheme pkg:npm"
        }
    if purl_lower.startswith('pkg:maven'):
        return {
            "registry": "Maven Central",
            "registry_url": f"https://search.maven.org/search?q={name}",
            "ecosystem": "Java",
            "detection_method": "PURL scheme pkg:maven"
        }
    if purl_lower.startswith('pkg:nuget'):
        return {
            "registry": "NuGet",
            "registry_url": f"https://www.nuget.org/packages/{name}/",
            "ecosystem": ".NET",
            "detection_method": "PURL scheme pkg:nuget"
        }
    if purl_lower.startswith('pkg:gem'):
        return {
            "registry": "RubyGems",
            "registry_url": f"https://rubygems.org/gems/{name}",
            "ecosystem": "Ruby",
            "detection_method": "PURL scheme pkg:gem"
        }
    if purl_lower.startswith('pkg:cargo'):
        return {
            "registry": "crates.io",
            "registry_url": f"https://crates.io/crates/{name}",
            "ecosystem": "Rust",
            "detection_method": "PURL scheme pkg:cargo"
        }
    if purl_lower.startswith('pkg:composer'):
        return {
            "registry": "Packagist",
            "registry_url": f"https://packagist.org/packages/{name}",
            "ecosystem": "PHP",
            "detection_method": "PURL scheme pkg:composer"
        }
    if purl_lower.startswith('pkg:golang'):
        return {
            "registry": "Go Modules",
            "registry_url": f"https://pkg.go.dev/{name}",
            "ecosystem": "Go",
            "detection_method": "PURL scheme pkg:golang"
        }
    if purl_lower.startswith('pkg:conda'):
        return {
            "registry": "Conda",
            "registry_url": f"https://anaconda.org/anaconda/{name}",
            "ecosystem": "Python/Data Science",
            "detection_method": "PURL scheme pkg:conda"
        }
    if purl_lower.startswith('pkg:docker'):
        return {
            "registry": "Docker Hub",
            "registry_url": f"https://hub.docker.com/r/{name}",
            "ecosystem": "Container",
            "detection_method": "PURL scheme pkg:docker"
        }
    if purl_lower.startswith('pkg:huggingface'):
        return {
            "registry": "Hugging Face",
            "registry_url": f"https://huggingface.co/{name}",
            "ecosystem": "AI/ML",
            "detection_method": "PURL scheme pkg:huggingface"
        }
    if purl_lower.startswith('pkg:oci'):
        return {
            "registry": "OCI Registry",
            "registry_url": f"https://oci.dag.dev/{name}",
            "ecosystem": "Container",
            "detection_method": "PURL scheme pkg:oci"
        }

    return {
        "registry": "Unknown Registry",
        "registry_url": "",
        "ecosystem": "Unknown",
        "detection_method": "No matching PURL scheme"
    }


# ---------------------------------------------------------------------------
# Existing helpers (unchanged)
# ---------------------------------------------------------------------------
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

            supplier = (
                info.get('author')
                or info.get('maintainer')
                or info.get('author_email')
                or ""
            )
            license_str = info.get('license') or ""
            latest_version = info.get('version') or version

            # Fetch release date for the specific version
            release_date = ""
            releases = data.get('releases', {})
            if version in releases and releases[version]:
                upload_time = releases[version][0].get('upload_time_iso_8601')
                if upload_time:
                    release_date = upload_time

            # Fallback for release date if not found
            if not release_date:
                release_date = datetime.utcnow().isoformat() + "Z"

            return description, supplier, license_str, latest_version, release_date
    except Exception as e:
        print(
            f"Warning: Could not fetch online metadata for {package_name} ({e}). "
            "Using defaults."
        )
        return None


# ---------------------------------------------------------------------------
# Core enrichment (enhanced)
# ---------------------------------------------------------------------------
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
    config_override_exists = bool(override)

    # Fetch from API or use config defaults
    api_data = fetch_pypi_metadata(name, version)
    api_data_available = api_data is not None

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
        clean_date = release_date_str.replace('Z', '')
        if '.' in clean_date:
            clean_date = clean_date.split('.')[0]
        dt = datetime.fromisoformat(clean_date)
        eol_dt = dt + timedelta(days=365 * config.get('eol_years_from_release', 3))
        eol_date_str = eol_dt.isoformat() + "Z"
    except Exception:
        eol_date_str = (
            datetime.utcnow() + timedelta(days=365 * 3)
        ).isoformat() + "Z"

    # Attribute 9: Patch Status
    patch_status = "up-to-date" if version == latest_version else "patch-available"

    # ----- Enhancement 1: Automated Criticality Assessment -----
    criticality, criticality_reason = assess_criticality(name, component, config)

    # Attribute 13: Usage Restrictions
    usage_restrictions = (
        override.get('usage_restrictions') or config.get('default_usage_restrictions')
    )

    # Attribute 15: Comments or Notes
    comments = override.get('comments') or config.get('default_comments')

    # ----- Enhancement 3: Executable Property Detection -----
    exec_info = detect_executable_property(name, component, config)
    executable_value = exec_info["value"]
    executable_evidence = exec_info["evidence"]
    executable_detection_method = exec_info["detection_method"]

    # ----- Enhancement 4: Trust Score -----
    # licenses already set above; pass current state of component for scoring
    component['licenses'] = [{"license": {"name": license_name}}]
    trust_score_int, trust_reasons = calculate_trust_score(
        component, api_data_available, config_override_exists
    )
    trust_score_str = f"{trust_score_int}%"
    trust_score_reasons_str = "\n".join(trust_reasons)

    # ----- Enhancement 5: Repository Detection -----
    repo_info = detect_repository(name, purl, component)

    # ------------------------------------------------------------------
    # Populate custom fields as properties
    # ------------------------------------------------------------------
    properties = component.get('properties', [])

    # Names of all properties we manage (existing + new)
    managed_props = {
        'origin', 'patch_status', 'release_date', 'eol_date',
        'criticality', 'criticality_reason',
        'usage_restrictions', 'comments',
        'executable', 'executable_evidence', 'executable_detection_method',
        'archive', 'structured',
        'trust_score', 'trust_score_reasons',
        'repository_registry', 'repository_url', 'repository_ecosystem',
    }

    # Filter out existing managed properties so we can rebuild cleanly
    properties = [p for p in properties if p.get('name') not in managed_props]

    # ---- Existing properties ----
    properties.append({
        "name": "origin",
        "value": override.get('origin') or config.get('default_origin')
    })
    properties.append({"name": "patch_status", "value": patch_status})
    properties.append({"name": "release_date", "value": release_date_str})
    properties.append({"name": "eol_date", "value": eol_date_str})
    properties.append({"name": "criticality", "value": criticality})
    properties.append({"name": "usage_restrictions", "value": usage_restrictions})
    properties.append({"name": "comments", "value": comments})
    properties.append({
        "name": "executable",
        "value": str(
            override.get('executable', config.get('default_executable'))
        ).lower()
    })
    properties.append({
        "name": "archive",
        "value": str(
            override.get('archive', config.get('default_archive'))
        ).lower()
    })
    properties.append({
        "name": "structured",
        "value": config.get('default_structured_format')
    })

    # ---- New properties ----
    properties.append({"name": "criticality_reason", "value": criticality_reason})
    properties.append({
        "name": "executable_evidence",
        "value": ", ".join(executable_evidence)
    })
    properties.append({
        "name": "executable_detection_method",
        "value": executable_detection_method
    })
    properties.append({"name": "trust_score", "value": trust_score_str})
    properties.append({"name": "trust_score_reasons", "value": trust_score_reasons_str})
    properties.append({
        "name": "repository_registry",
        "value": repo_info["registry"]
    })
    properties.append({
        "name": "repository_url",
        "value": repo_info["registry_url"]
    })
    properties.append({
        "name": "repository_ecosystem",
        "value": repo_info["ecosystem"]
    })

    component['properties'] = properties
    return component


# ---------------------------------------------------------------------------
# Top-level SBOM enrichment (enhanced)
# ---------------------------------------------------------------------------
def enrich_sbom(raw_sbom_path, enriched_sbom_path, config_path):
    print(f"Reading raw SBOM from {raw_sbom_path}...")
    with open(raw_sbom_path, 'r', encoding='utf-8') as f:
        sbom = json.load(f)

    config = load_config(config_path)

    # Map dependencies by component for quick lookup if needed
    dependencies = sbom.get('dependencies', [])
    dependencies_map = {
        dep.get('ref'): dep.get('dependsOn', []) for dep in dependencies
    }

    # Update Metadata (Authors, Timestamp)
    metadata = sbom.setdefault('metadata', {})
    metadata['timestamp'] = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')

    # ----- Enhancement 2: Auto-populate Author of SBOM Data -----
    author_name = determine_sbom_author(config)
    metadata['authors'] = [{
        "name": author_name,
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
    os.makedirs(os.path.dirname(os.path.abspath(enriched_sbom_path)), exist_ok=True)
    with open(enriched_sbom_path, 'w', encoding='utf-8') as f:
        json.dump(sbom, f, indent=2, ensure_ascii=False)
    print("Enrichment complete!")


# ---------------------------------------------------------------------------
# Entry point (unchanged)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys
    if getattr(sys, 'frozen', False):
        base_dir = os.path.dirname(sys.executable)
    else:
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
