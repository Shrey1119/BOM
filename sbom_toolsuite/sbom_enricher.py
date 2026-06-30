import json
import os
import urllib.request
import urllib.error
from datetime import datetime, timedelta

# ---------------------------------------------------------------------------
# Package classification lists for criticality scoring
# ---------------------------------------------------------------------------
CRYPTO_PACKAGES = {
    'cryptography', 'openssl', 'pycryptodome', 'pycryptodomex',
    'paramiko', 'bcrypt', 'nacl', 'pyopenssl', 'certifi', 'pyca',
    'pynacl', 'passlib', 'itsdangerous', 'jwt', 'pyjwt', 'python-jose',
    'argon2-cffi', 'scrypt', 'pyargon2',
    # npm
    'jsonwebtoken', 'bcryptjs', 'node-forge', 'crypto-js', 'jose',
    # nuget
    'bouncycastle', 'system.security.cryptography',
}
FRAMEWORK_PACKAGES = {
    'django', 'flask', 'fastapi', 'tornado', 'aiohttp',
    'starlette', 'bottle', 'falcon', 'pyramid', 'sanic',
    'rails', 'sinatra', 'express', 'koa', 'hapi', 'nestjs',
    'spring', 'spring-boot', 'quarkus', 'micronaut',
    'laravel', 'symfony', 'codeigniter',
    'gin', 'echo', 'fiber',
}
RUNTIME_PACKAGES = {
    'requests', 'urllib3', 'httpx', 'boto3',
    'sqlalchemy', 'psycopg2', 'pymongo', 'redis', 'celery',
    'aiohttp', 'httpcore', 'grpcio', 'grpc',
    # auth / identity
    'authlib', 'oauthlib', 'python-oauth2', 'social-auth-core',
    # infra clients
    'boto', 'azure-mgmt', 'google-cloud', 'kubernetes',
    # serialisation / parsing (high-exposure)
    'pyyaml', 'lxml', 'xmltodict', 'defusedxml',
    # npm equivalents
    'axios', 'node-fetch', 'got', 'superagent', 'mongoose', 'sequelize',
    'passport', 'express-jwt',
}
OS_PACKAGES = {
    'ctypes', 'cffi', 'pywin32', 'wmi', 'winreg',
    'pyinstaller', 'cx-freeze', 'nuitka',
}

# Name substrings that raise a flag regardless of exact name match
_HIGH_RISK_SUBSTRINGS = (
    'crypto', 'cipher', 'encrypt', 'decrypt', 'tls', 'ssl', 'cert',
    'auth', 'oauth', 'saml', 'ldap', 'jwt', 'token', 'secret',
    'password', 'passwd', 'keyring', 'vault', 'credential',
    'sql', 'database', 'db', 'orm',
    'network', 'socket', 'http', 'grpc', 'rpc', 'websocket',
)

# High-risk licenses: copyleft / viral
_COPYLEFT_LICENSES = {
    'GPL-2.0', 'GPL-3.0', 'LGPL-2.0', 'LGPL-2.1', 'LGPL-3.0',
    'AGPL-3.0', 'AGPL-1.0', 'GPL-2.0-only', 'GPL-3.0-only',
    'LGPL-2.1-only', 'LGPL-3.0-only', 'AGPL-3.0-only',
    'GPL-2.0-or-later', 'GPL-3.0-or-later',
    'GNU General Public License', 'GNU GPL', 'GNU LGPL', 'GNU AGPL',
}


# ---------------------------------------------------------------------------
# License → Usage Restrictions derivation
# ---------------------------------------------------------------------------
_PERMISSIVE_LICENSES = {
    'MIT', 'MIT License', 'Apache-2.0', 'Apache 2.0', 'Apache License 2.0',
    'BSD-2-Clause', 'BSD-3-Clause', 'ISC', 'Unlicense', 'CC0-1.0',
    'PSF', 'Python Software Foundation License', 'WTFPL', 'Zlib',
    'BSD', '0BSD',
}
_WEAK_COPYLEFT_LICENSES = {
    'LGPL-2.0', 'LGPL-2.1', 'LGPL-3.0', 'LGPL-2.1-only', 'LGPL-3.0-only',
    'MPL-2.0', 'Mozilla Public License 2.0', 'CDDL-1.0', 'EPL-1.0', 'EPL-2.0',
}
_STRONG_COPYLEFT_LICENSES = {
    'GPL-2.0', 'GPL-3.0', 'GPL-2.0-only', 'GPL-3.0-only',
    'GPL-2.0-or-later', 'GPL-3.0-or-later',
    'GNU General Public License', 'GNU GPL',
}
_NETWORK_COPYLEFT_LICENSES = {
    'AGPL-3.0', 'AGPL-1.0', 'AGPL-3.0-only', 'AGPL-3.0-or-later', 'GNU AGPL',
}
_COMMERCIAL_RESTRICTED = {
    'Commercial', 'Proprietary', 'All Rights Reserved', 'Elastic License',
    'SSPL', 'BSL', 'Business Source License',
}


def derive_usage_restrictions(license_name: str, override_text: str = None) -> str:
    """
    Derive a human-readable usage-restrictions string from a license name.

    Priority:
      1. override_text (from config.json override or usage_restrictions_overrides)
      2. Rule-based derivation from license_name
    """
    if override_text and override_text.strip().lower() not in ('', 'none'):
        return override_text

    if not license_name or license_name.strip().lower() in ('', 'unknown', 'none'):
        return "License unknown — manual review required before commercial use"

    lic = license_name.strip()
    lic_upper = lic.upper()

    # Check network-copyleft (AGPL) first — most restrictive
    if lic in _NETWORK_COPYLEFT_LICENSES or 'AGPL' in lic_upper:
        return (
            "AGPL copyleft: any networked service using this component must open-source "
            "its entire application under AGPL. Commercial SaaS use requires legal review."
        )

    # Strong copyleft (GPL)
    if lic in _STRONG_COPYLEFT_LICENSES or ('GPL' in lic_upper and 'LGPL' not in lic_upper):
        return (
            "GPL copyleft: derivative works and linked binaries must be distributed under GPL. "
            "Attribution required. Incompatible with proprietary distribution without a commercial exception."
        )

    # Weak copyleft (LGPL / MPL / EPL)
    if lic in _WEAK_COPYLEFT_LICENSES or 'LGPL' in lic_upper or 'MPL' in lic_upper or 'EPL' in lic_upper:
        return (
            "Weak copyleft (LGPL/MPL/EPL): modifications to this library must be released under "
            "the same license. Dynamic linking from proprietary code is generally permitted."
        )

    # Commercial / proprietary
    if lic in _COMMERCIAL_RESTRICTED or any(
        kw in lic_upper for kw in ('COMMERCIAL', 'PROPRIETARY', 'ALL RIGHTS RESERVED', 'ELASTIC', 'SSPL', 'BSL')
    ):
        return (
            "Proprietary/commercial license: usage may require a paid license agreement. "
            "Review terms before redistribution or commercial deployment."
        )

    # Permissive — no material restrictions
    if lic in _PERMISSIVE_LICENSES or any(
        kw in lic_upper for kw in ('MIT', 'APACHE', 'BSD', 'ISC', 'UNLICENSE', 'CC0', 'PSF', 'ZLIB')
    ):
        return "Permissive license: use, modify, and distribute freely; attribution required where specified."

    # Unknown / exotic
    return f"Non-standard license ({lic}) — manual compliance review recommended before commercial or government use."


# ---------------------------------------------------------------------------
# Enhancement 1: Automated Criticality Assessment
# ---------------------------------------------------------------------------
def assess_criticality(name, component, config):
    """
    Determine criticality level and reason for a component.

    Priority:
      1. config['overrides'][name]['criticality'] if present
      2. Multi-factor scoring:
           - Package category membership (crypto/framework/runtime/os)
           - Name-substring heuristics (auth, sql, http, …)
           - Component type (application > library > file)
           - Purl ecosystem (container > app > lib)
           - Vulnerability count on the component (pre-enrichment)
           - Dependency depth / dependsOn count
           - License risk (copyleft raises score)

    Score thresholds:  ≥75 → critical | ≥50 → high | ≥25 → medium | else → low
    """
    overrides = config.get('overrides', {})
    if name in overrides and 'criticality' in overrides[name]:
        level = overrides[name]['criticality']
        return level, f"Manually overridden in config to '{level}'"

    score = 0
    reasons = []
    name_lower = name.lower()

    # --- Factor 1: curated package category lists ---
    if name_lower in CRYPTO_PACKAGES:
        score += 40
        reasons.append("cryptography/security package (+40)")
    if name_lower in FRAMEWORK_PACKAGES:
        score += 35
        reasons.append("web framework (+35)")
    if name_lower in RUNTIME_PACKAGES:
        score += 30
        reasons.append("core runtime/integration package (+30)")
    if name_lower in OS_PACKAGES:
        score += 25
        reasons.append("OS-level/system interface package (+25)")

    # --- Factor 2: name-substring heuristics ---
    substring_hits = [s for s in _HIGH_RISK_SUBSTRINGS if s in name_lower]
    # Only score if not already covered by exact-list match (avoid double-counting)
    if substring_hits and name_lower not in CRYPTO_PACKAGES and name_lower not in RUNTIME_PACKAGES:
        sub_score = min(len(substring_hits) * 8, 24)  # cap at +24
        score += sub_score
        reasons.append(f"name contains risk-related substrings {substring_hits} (+{sub_score})")

    # --- Factor 3: CycloneDX component type ---
    comp_type = component.get('type', '')
    if comp_type in ('application', 'container', 'device', 'firmware'):
        score += 20
        reasons.append(f"component type='{comp_type}' (+20)")
    elif comp_type == 'library':
        score += 10
        reasons.append("component type='library' (+10)")
    elif comp_type == 'framework':
        score += 18
        reasons.append("component type='framework' (+18)")

    # --- Factor 4: PURL ecosystem signal ---
    purl = component.get('purl', '').lower()
    if purl.startswith('pkg:docker') or purl.startswith('pkg:oci'):
        score += 20
        reasons.append("container image in purl (+20)")
    elif purl.startswith('pkg:golang') or purl.startswith('pkg:cargo'):
        # Systems-language packages often have low-level access
        score += 8
        reasons.append(f"systems-language package (Go/Rust) (+8)")

    # --- Factor 5: existing vulnerability annotations ---
    # Some scanners annotate the component before enrichment
    props = {p.get('name'): p.get('value') for p in component.get('properties', [])}
    pre_vulns = props.get('vulnerabilities', '') or ''
    vuln_count = 0
    if pre_vulns and pre_vulns.lower() not in ('none', '0', ''):
        # Count comma-separated CVE references
        vuln_count = len([v for v in pre_vulns.split(',') if v.strip()])
    if vuln_count >= 5:
        score += 30
        reasons.append(f"has {vuln_count} known vulnerabilities (+30)")
    elif vuln_count >= 2:
        score += 20
        reasons.append(f"has {vuln_count} known vulnerabilities (+20)")
    elif vuln_count == 1:
        score += 10
        reasons.append("has 1 known vulnerability (+10)")

    # --- Factor 6: dependency fan-out (dependents = widely used) ---
    # dependsOn on this component's own ref can be inferred from the passed
    # component object; the dependencies_map isn't available here, but the
    # component may carry a 'dependsOn' count from the merge step.
    depends_on = component.get('dependsOn', [])
    dep_count = len(depends_on) if isinstance(depends_on, list) else 0
    if dep_count >= 20:
        score += 15
        reasons.append(f"has {dep_count} direct dependsOn entries (+15)")
    elif dep_count >= 5:
        score += 8
        reasons.append(f"has {dep_count} direct dependsOn entries (+8)")

    # --- Factor 7: license risk ---
    license_name = ""
    lics = component.get('licenses', [])
    if lics and isinstance(lics, list):
        lic_obj = lics[0].get('license', {})
        license_name = lic_obj.get('name', '') or lic_obj.get('id', '')
    if license_name in _NETWORK_COPYLEFT_LICENSES or 'AGPL' in license_name.upper():
        score += 10
        reasons.append("AGPL license (legal/compliance risk) (+10)")
    elif license_name in _STRONG_COPYLEFT_LICENSES or ('GPL' in license_name.upper() and 'LGPL' not in license_name.upper()):
        score += 6
        reasons.append("GPL copyleft license (+6)")

    # --- Map score to level ---
    if score >= 70:
        level = 'critical'
    elif score >= 40:
        level = 'high'
    elif score >= 18:
        level = 'medium'
    else:
        level = 'low'

    if reasons:
        reason = f"Score {score}: " + "; ".join(reasons)
    else:
        reason = f"Score {score}: standard library, no elevated risk indicators"

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
        return None


def fetch_npm_metadata(package_name, version):
    """
    Fetch package metadata from NPM Registry API.
    Returns: (description, supplier, license, latest_version, release_date)
    """
    url = f"https://registry.npmjs.org/{package_name}"
    try:
        req = urllib.request.Request(
            url,
            headers={'User-Agent': 'Antigravity SBOM Agent/1.0'}
        )
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode('utf-8'))
            
            description = data.get('description', '')
            if len(description) > 200:
                description = description[:197] + "..."
                
            author = data.get('author', {})
            supplier = ""
            if isinstance(author, dict):
                supplier = author.get('name', '')
            elif isinstance(author, str):
                supplier = author
            if not supplier:
                maintainers = data.get('maintainers', [])
                if maintainers and isinstance(maintainers, list):
                    first = maintainers[0]
                    if isinstance(first, dict):
                        supplier = first.get('name', '')
                        
            license_str = data.get('license', '')
            if isinstance(license_str, dict):
                license_str = license_str.get('type', '')
            
            dist_tags = data.get('dist-tags', {})
            latest_version = dist_tags.get('latest', version)
            
            release_date = ""
            time_data = data.get('time', {})
            if version in time_data:
                release_date = time_data[version]
            elif 'modified' in time_data:
                release_date = time_data['modified']
                
            if not release_date:
                release_date = datetime.utcnow().isoformat() + "Z"
                
            return description, supplier, license_str, latest_version, release_date
    except Exception:
        return None


def fetch_nuget_metadata(package_name, version):
    """
    Fetch package metadata from NuGet API.
    Returns: (description, supplier, license, latest_version, release_date)
    """
    name_lower = package_name.lower()
    url = f"https://api.nuget.org/v3/registration5-semver1/{name_lower}/index.json"
    try:
        req = urllib.request.Request(
            url,
            headers={'User-Agent': 'Antigravity SBOM Agent/1.0'}
        )
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode('utf-8'))
            items = data.get('items', [])
            if not items:
                return None
            
            catalog_entry = None
            latest_version = version
            release_date = ""
            
            all_entries = []
            for page in items:
                page_items = page.get('items', [])
                if page_items:
                    all_entries.extend(page_items)
                else:
                    all_entries.extend([page])
            
            for entry in all_entries:
                cat_entry = entry.get('catalogEntry', {})
                entry_version = cat_entry.get('version', '')
                if entry_version == version:
                    catalog_entry = cat_entry
                    release_date = entry.get('commitTimeStamp', '')
                    break
            
            if not catalog_entry and all_entries:
                catalog_entry = all_entries[-1].get('catalogEntry', {})
                release_date = all_entries[-1].get('commitTimeStamp', '')
                latest_version = catalog_entry.get('version', version)
                
            if catalog_entry:
                description = catalog_entry.get('description', '')
                if len(description) > 200:
                    description = description[:197] + "..."
                supplier = catalog_entry.get('authors', '')
                license_str = catalog_entry.get('licenseExpression') or catalog_entry.get('licenseUrl') or ''
                if not release_date:
                    release_date = datetime.utcnow().isoformat() + "Z"
                return description, supplier, license_str, latest_version, release_date
    except Exception:
        pass
    return None


def fetch_golang_metadata(module_name, version):
    """
    Fetch module metadata from Go Proxy API.
    Returns: (description, supplier, license, latest_version, release_date)
    """
    escaped_name = ""
    for char in module_name:
        if char.isupper():
            escaped_name += "!" + char.lower()
        else:
            escaped_name += char
            
    url = f"https://proxy.golang.org/{escaped_name}/@v/{version}.info"
    try:
        req = urllib.request.Request(
            url,
            headers={'User-Agent': 'Antigravity SBOM Agent/1.0'}
        )
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode('utf-8'))
            release_date = data.get('Time', '')
            if not release_date:
                release_date = datetime.utcnow().isoformat() + "Z"
            return f"Go module {module_name}", "", "", version, release_date
    except Exception:
        pass
    return None


def detect_archive_property(name, component):
    """Detect if a component is an archive/compressed file."""
    name_lower = name.lower()
    purl_lower = component.get('purl', '').lower()
    
    archive_exts = ('.zip', '.tar', '.gz', '.tgz', '.tar.gz', '.bz2', '.xz', '.jar', '.war', '.ear', '.whl', '.gem')
    is_archive = False
    
    if any(name_lower.endswith(ext) for ext in archive_exts):
        is_archive = True
    elif any(ext in purl_lower for ext in archive_exts):
        is_archive = True
    elif component.get('type') == 'file' and any(name_lower.endswith(ext) for ext in archive_exts):
        is_archive = True
        
    return "true" if is_archive else "false"


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
    # Check if a valid PURL already exists first. Do not overwrite scanner values.
    purl = component.get('purl')
    if not purl:
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

    # Resolve existing license if present in scanner metadata
    existing_license = None
    if component.get('licenses'):
        lics = component['licenses']
        if isinstance(lics, list) and len(lics) > 0:
            first_lic = lics[0]
            if isinstance(first_lic, dict):
                lic_obj = first_lic.get('license', {})
                if isinstance(lic_obj, dict):
                    existing_license = lic_obj.get('name') or lic_obj.get('id')
                elif isinstance(first_lic.get('license'), str):
                    existing_license = first_lic.get('license')

    # Query registry based on PURL ecosystem
    purl_lower = purl.lower()
    purl_name = name
    
    if purl_lower.startswith('pkg:'):
        # Extract clean package name from namespace if necessary
        parts = purl.split('?')[0].split('#')[0].split('@')
        if len(parts) > 0:
            left_part = parts[0]
            if '/' in left_part:
                subparts = left_part.split('/')
                # Skip the type part (subparts[0])
                purl_name = '/'.join(subparts[1:])

    api_data = None
    if purl_lower.startswith('pkg:pypi'):
        api_data = fetch_pypi_metadata(purl_name, version)
    elif purl_lower.startswith('pkg:npm'):
        api_data = fetch_npm_metadata(purl_name, version)
    elif purl_lower.startswith('pkg:nuget'):
        api_data = fetch_nuget_metadata(purl_name, version)
    elif purl_lower.startswith('pkg:golang'):
        api_data = fetch_golang_metadata(purl_name, version)
        
    api_data_available = api_data is not None

    if api_data:
        api_desc, api_supplier, api_license, api_latest, api_release = api_data
        desc = api_desc or component.get('description') or f"Component {name}"
        # Overwrite local inconsistent data with registry standardized fields
        supplier = override.get('supplier') or api_supplier or component.get('supplier', {}).get('name') or config.get('default_supplier')
        license_name = override.get('license') or api_license or existing_license or config.get('default_license')
        latest_version = api_latest
        release_date_str = api_release
    else:
        desc = component.get('description') or f"Component {name}"
        supplier = override.get('supplier') or component.get('supplier', {}).get('name') or config.get('default_supplier')
        license_name = override.get('license') or existing_license or config.get('default_license')
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

    # Attribute 13: Usage Restrictions — derive from license text
    usage_restrictions = derive_usage_restrictions(
        license_name,
        override_text=override.get('usage_restrictions') or config.get('usage_restrictions_overrides', {}).get(name)
    )

    # Attribute 15: Comments or Notes
    comments = override.get('comments') or config.get('default_comments')

    # ----- Enhancement 3: Executable Property Detection -----
    exec_info = detect_executable_property(name, component, config)
    executable_value = exec_info["value"]
    executable_evidence = exec_info["evidence"]
    executable_detection_method = exec_info["detection_method"]

    # ----- Enhancement 4: Trust Score -----
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
    
    # Executable logic using detected value
    properties.append({
        "name": "executable",
        "value": str(override.get('executable') or executable_value)
    })
    
    # Archive logic using helper
    properties.append({
        "name": "archive",
        "value": str(override.get('archive') or detect_archive_property(name, component))
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
    total = len(components)

    import sys
    print(f"Enriching {total} components...")
    for i, comp in enumerate(components, 1):
        name = comp.get('name', 'unknown')
        version = comp.get('version', 'unknown')
        
        # Display clean in-place text loading bar (using CP1252-safe ASCII characters)
        bar_length = 30
        percent = int(100 * i / total)
        filled_length = int(bar_length * i // total)
        bar = '#' * filled_length + '-' * (bar_length - filled_length)
        
        sys.stdout.write(f"\r  Enrichment Progress: |{bar}| {percent}% ({i}/{total}) - {name}@{version}               ")
        sys.stdout.flush()

        enriched_comp = enrich_component(comp, config, dependencies_map)
        enriched_components.append(enriched_comp)

    sys.stdout.write("\n")
    sys.stdout.flush()

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

