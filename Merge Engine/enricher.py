import json
import os
import urllib.request
import urllib.error
import sys
import re
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
        print(f"Warning: Could not fetch online metadata for {package_name} ({e}). Using defaults.")
        return None

def get_git_author_or_owner(src_dir):
    """Search upwards for .git and extract the owner of the remote origin repository."""
    try:
        curr = os.path.abspath(src_dir)
        git_dir = None
        for _ in range(5):
            if os.path.exists(os.path.join(curr, ".git")):
                git_dir = curr
                break
            parent = os.path.dirname(curr)
            if parent == curr:
                break
            curr = parent
        
        if git_dir:
            import subprocess
            cmd = ["git", "config", "--get", "remote.origin.url"]
            res = subprocess.run(cmd, cwd=git_dir, capture_output=True, text=True, check=True)
            url = res.stdout.strip()
            if url:
                m = re.search(r'(?:git@|https?://)[^/:]+[/:][^/]+/(.+?)(?:\.git)?$', url)
                if m:
                    parts = url.replace('\\', '/').split('/')
                    if len(parts) >= 2:
                        last_part = parts[-2]
                        if ":" in last_part:
                            last_part = last_part.split(":")[-1]
                        return last_part
            
            # Fallback to git user.name
            cmd = ["git", "config", "--get", "user.name"]
            res = subprocess.run(cmd, cwd=git_dir, capture_output=True, text=True, check=True)
            name = res.stdout.strip()
            if name:
                return name
    except Exception:
        pass
    return None

def get_root_project_author(src_dir):
    """Scan root configuration files for project owner/author or organization."""
    try:
        # 1. pyproject.toml
        pyproject = os.path.join(src_dir, "pyproject.toml")
        if os.path.exists(pyproject):
            with open(pyproject, 'r', encoding='utf-8') as f:
                content = f.read()
                m = re.search(r'authors\s*=\s*\[\s*\{\s*name\s*=\s*"([^"]+)"', content)
                if m:
                    return m.group(1)
                m = re.search(r'name\s*=\s*"([^"]+)"', content)
                if m:
                    return m.group(1)
        
        # 2. package.json
        pkg_json = os.path.join(src_dir, "package.json")
        if os.path.exists(pkg_json):
            with open(pkg_json, 'r', encoding='utf-8') as f:
                data = json.load(f)
                author = data.get('author')
                if isinstance(author, dict) and author.get('name'):
                    return author['name']
                elif isinstance(author, str):
                    return author
                
        # 3. setup.py
        setup_py = os.path.join(src_dir, "setup.py")
        if os.path.exists(setup_py):
            with open(setup_py, 'r', encoding='utf-8') as f:
                content = f.read()
                m = re.search(r'author\s*=\s*[\'"]([^\'"]+)[\'"]', content)
                if m:
                    return m.group(1)
                m = re.search(r'author_email\s*=\s*[\'"]([^\'"]+)[\'"]', content)
                if m:
                    return m.group(1)
                    
        # 4. pom.xml
        pom_xml = os.path.join(src_dir, "pom.xml")
        if os.path.exists(pom_xml):
            with open(pom_xml, 'r', encoding='utf-8') as f:
                content = f.read()
                m = re.search(r'<organization>\s*<name>([^<]+)</name>', content)
                if m:
                    return m.group(1)
                m = re.search(r'<developer>\s*<name>([^<]+)</name>', content)
                if m:
                    return m.group(1)
    except Exception:
        pass
    return None

def detect_repository_source(component, src_dir):
    """Examine package attributes, PURLs, and paths to determine repository source name & URL."""
    name = component.get('name', '').lower()
    purl = component.get('purl', '').lower()
    
    # Retrieve local path properties from Syft/cdxgen
    paths = []
    for p in component.get('properties', []):
        p_name = p.get('name', '')
        if (p_name.startswith('syft:location:') and p_name.endswith(':path')) or p_name == 'SrcFile':
            paths.append(p.get('value', '').lower())
            
    # AI Ecosystem check (highest priority based on package naming and namespace)
    if 'huggingface' in purl or 'huggingface' in name or 'transformers' in name or any('huggingface' in pt or 'transformers' in pt for pt in paths):
        return "Hugging Face (https://huggingface.co)"
    if 'modelscope' in purl or 'modelscope' in name or any('modelscope' in pt for pt in paths):
        return "ModelScope (https://modelscope.cn)"
    if 'ollama' in purl or 'ollama' in name or any('ollama' in pt for pt in paths):
        return "Ollama Model Registry (https://ollama.com/library)"
    if 'onnx' in purl or 'onnx' in name or any('onnx' in pt for pt in paths):
        return "ONNX Model Zoo (https://github.com/onnx/models)"
    if 'tfhub' in purl or 'tensorflow-hub' in purl or 'tfhub' in name or 'tensorflow-hub' in name or any('tfhub' in pt or 'tensorflow-hub' in pt for pt in paths):
        return "TensorFlow Hub (https://tfhub.dev)"

    # Ecosystem parsing by PURL type
    if purl.startswith("pkg:pypi/"):
        if any('conda' in pt or 'anaconda' in pt or 'miniconda' in pt for pt in paths):
            return "Conda (https://repo.anaconda.com/pkgs)"
        return "PyPI (https://pypi.org/simple)"
    
    if purl.startswith("pkg:npm/"):
        if os.path.exists(os.path.join(src_dir, "pnpm-lock.yaml")):
            return "pnpm (https://registry.pnpmjs.org)"
        if os.path.exists(os.path.join(src_dir, "yarn.lock")):
            return "Yarn (https://registry.yarnpkg.com)"
        return "npm (https://registry.npmjs.org)"
        
    if purl.startswith("pkg:maven/"):
        if any('.m2/repository' in pt for pt in paths):
            return "Local Maven Cache (file://~/.m2/repository)"
        if 'spring' in purl or 'spring' in name:
            return "Spring Repository (https://repo.spring.io/release)"
        if 'apache' in purl or 'apache' in name:
            return "Apache Repository (https://repository.apache.org/snapshots)"
        if 'gradle' in purl:
            return "Gradle Plugin Portal (https://plugins.gradle.org/m2)"
        return "Maven Central (https://repo1.maven.org/maven2)"

    if purl.startswith("pkg:nuget/"):
        return "NuGet (https://api.nuget.org/v3/index.json)"
        
    if purl.startswith("pkg:golang/") or purl.startswith("pkg:go/"):
        return "Go Modules (https://proxy.golang.org)"
        
    if purl.startswith("pkg:cargo/") or purl.startswith("pkg:rust/"):
        return "crates.io (https://crates.io)"
        
    if purl.startswith("pkg:composer/"):
        return "Packagist (https://packagist.org)"
        
    if purl.startswith("pkg:gem/"):
        return "RubyGems (https://rubygems.org)"
        
    if purl.startswith("pkg:docker/") or purl.startswith("pkg:oci/"):
        return "Docker Hub (https://registry.hub.docker.com)"
        
    # Fallback heuristic based on generic metadata
    for p in component.get('properties', []):
        val = p.get('value', '').lower()
        if 'npm' in val:
            return "npm (https://registry.npmjs.org)"
        if 'pypi' in val or 'pip' in val:
            return "PyPI (https://pypi.org/simple)"
        if 'nuget' in val:
            return "NuGet (https://api.nuget.org/v3/index.json)"
        if 'maven' in val:
            return "Maven Central (https://repo1.maven.org/maven2)"
        if 'cargo' in val:
            return "crates.io (https://crates.io)"

    return "Unknown Repository (Unknown)"

def resolve_component_file(component, src_dir):
    """Attempt to locate the actual physical file of the component in the filesystem."""
    for p in component.get('properties', []):
        p_name = p.get('name', '')
        if (p_name.startswith('syft:location:') and p_name.endswith(':path')) or p_name == 'SrcFile':
            rel_path = p.get('value', '')
            cleaned_path = rel_path.lstrip('\\').lstrip('/')
            
            # Paths to try
            paths_to_try = [
                os.path.join(src_dir, cleaned_path),
                os.path.join(os.path.dirname(src_dir), cleaned_path),
                rel_path,
                os.path.abspath(os.path.join(src_dir, rel_path.replace('\\', '/').split('/')[-1]))
            ]
            for path in paths_to_try:
                if os.path.exists(path) and os.path.isfile(path):
                    return path
    return None

def detect_executable_property(component, file_path):
    """Categorize component (Executable, Library, Script, etc.) and construct a list of evidence."""
    evidence = []
    purl = component.get('purl', '').lower()
    name = component.get('name', '').lower()
    
    # 1. Check containers first
    if purl.startswith("pkg:docker/") or purl.startswith("pkg:oci/") or "docker" in name:
        return "Container", ["Component ecosystem type matches Docker/OCI container"]
        
    # 2. Check service indicators
    if "service" in name or "daemon" in name or "server" in name:
        evidence.append("Component naming pattern matches service or background daemon")
        return "Service", evidence

    # 3. Analyze file signature and metadata if present
    if file_path:
        base = os.path.basename(file_path).lower()
        ext = os.path.splitext(base)[1]
        
        try:
            with open(file_path, 'rb') as f:
                header = f.read(4)
                
                # Windows PE headers
                if header.startswith(b'MZ'):
                    evidence.append("Windows Portable Executable (PE) binary header signature detected (MZ)")
                    if ext in ['.exe', '.bat', '.cmd']:
                        evidence.append("File extension is a direct executable format")
                        return "Executable", evidence
                    else:
                        evidence.append("PE binary structured as shared dll library")
                        return "Library", evidence
                        
                # Unix ELF headers
                elif header.startswith(b'\x7fELF'):
                    evidence.append("Unix Executable and Linkable Format (ELF) header signature detected")
                    if os.name == 'posix':
                        if os.access(file_path, os.X_OK):
                            evidence.append("File system execute bit is enabled")
                            return "Executable", evidence
                        else:
                            evidence.append("No execution bits enabled; identified as shared object library")
                            return "Library", evidence
                    else:
                        if ext in ['.so', '.dylib'] or 'lib' in base:
                            evidence.append("File name or extension is typical of shared libraries")
                            return "Library", evidence
                        evidence.append("Assuming Unix standalone binary executable")
                        return "Executable", evidence
                        
                # Script shebang
                elif header.startswith(b'#!'):
                    evidence.append("Script shebang signature (#!/...) detected at file head")
                    return "Script", evidence
                    
                # Zip archive / Java archive manifest check
                elif header.startswith(b'PK\x03\x04'):
                    evidence.append("PK-ZIP Archive header signature detected")
                    if ext in ['.jar', '.war']:
                        evidence.append("Java package extension matches JAR/WAR")
                        import zipfile
                        try:
                            if zipfile.is_zipfile(file_path):
                                with zipfile.ZipFile(file_path) as z:
                                    if "META-INF/MANIFEST.MF" in z.namelist():
                                        manifest = z.read("META-INF/MANIFEST.MF").decode('utf-8', errors='ignore')
                                        if "Main-Class:" in manifest:
                                            evidence.append("Java JAR Manifest contains a valid 'Main-Class' entry point")
                                            return "Executable", evidence
                        except Exception:
                            pass
                        return "Package", evidence
        except Exception as e:
            evidence.append(f"Header signature checks failed: {str(e)}")
            
        # Fallback ext checks
        if ext in ['.exe']:
            evidence.append("Identified by .exe executable extension")
            return "Executable", evidence
        elif ext in ['.py', '.js', '.sh', '.bat', '.ps1', '.rb', '.pl']:
            evidence.append(f"Extension ({ext}) indicates an executable script file")
            return "Script", evidence
        elif ext in ['.dll', '.so', '.dylib']:
            evidence.append(f"Extension ({ext}) indicates a linkable library binary")
            return "Library", evidence

    # 4. Ecosystem default fallbacks
    if purl.startswith("pkg:pypi/"):
        evidence.append("Python PyPI dependency package (resolves to Library code)")
        return "Library", evidence
    if purl.startswith("pkg:npm/"):
        evidence.append("Node.js package registry library")
        return "Library", evidence
    if purl.startswith("pkg:nuget/"):
        evidence.append("C#/.NET NuGet assembly library")
        return "Library", evidence
    if purl.startswith("pkg:maven/"):
        evidence.append("Java Maven dependency library")
        return "Library", evidence

    evidence.append("Defaulting to Package type due to generic dependency metadata")
    return "Package", evidence

def inspect_archive_metadata(file_path, component):
    """Retrieve compression layout and contents for archive properties."""
    purl = component.get('purl', '').lower()
    ext = ""
    if file_path:
        ext = os.path.splitext(file_path)[1].lower()
    elif purl.startswith("pkg:pypi/"):
        ext = ".whl"
    elif purl.startswith("pkg:npm/"):
        ext = ".tgz"
    elif purl.startswith("pkg:maven/"):
        ext = ".jar"
        
    meta = {
        "archive_type": "Unknown",
        "compression_format": "None",
        "original_size": "N/A",
        "extracted_size": "N/A",
        "compression_ratio": "N/A",
        "nested_archives": "False"
    }
    
    if file_path and os.path.exists(file_path):
        size = os.path.getsize(file_path)
        meta["original_size"] = f"{size / 1024:.1f} KB"
        
        # Zip compressed formats
        if ext in ['.zip', '.jar', '.war', '.whl']:
            meta["archive_type"] = ext.lstrip('.').upper()
            import zipfile
            try:
                if zipfile.is_zipfile(file_path):
                    with zipfile.ZipFile(file_path) as z:
                        total_extracted = 0
                        nested = False
                        compression = "Deflate"
                        for info in z.infolist():
                            total_extracted += info.file_size
                            nested_ext = os.path.splitext(info.filename)[1].lower()
                            if nested_ext in ['.zip', '.jar', '.tar', '.gz', '.tgz', '.whl', '.dll', '.exe']:
                                nested = True
                            if info.compress_type == zipfile.ZIP_DEFLATED:
                                compression = "Deflate"
                            elif info.compress_type == zipfile.ZIP_BZIP2:
                                compression = "BZIP2"
                            elif info.compress_type == zipfile.ZIP_LZMA:
                                compression = "LZMA"
                                
                        meta["compression_format"] = compression
                        meta["extracted_size"] = f"{total_extracted / 1024:.1f} KB"
                        meta["nested_archives"] = "True" if nested else "False"
                        if total_extracted > 0:
                            ratio = size / total_extracted
                            meta["compression_ratio"] = f"{ratio:.2f}:1"
            except Exception:
                pass
                
        # Tar compressed formats
        elif ext in ['.tar', '.gz', '.tgz', '.tar.gz']:
            meta["archive_type"] = "TAR"
            import tarfile
            try:
                if tarfile.is_tarfile(file_path):
                    meta["compression_format"] = "Gzip" if ext in ['.tgz', '.tar.gz', '.gz'] else "None"
                    with tarfile.open(file_path) as t:
                        total_extracted = 0
                        nested = False
                        for member in t.getmembers():
                            total_extracted += member.size
                            nested_ext = os.path.splitext(member.name)[1].lower()
                            if nested_ext in ['.zip', '.jar', '.tar', '.gz', '.tgz', '.whl', '.dll', '.exe']:
                                nested = True
                        meta["extracted_size"] = f"{total_extracted / 1024:.1f} KB"
                        meta["nested_archives"] = "True" if nested else "False"
                        if total_extracted > 0:
                            ratio = size / total_extracted
                            meta["compression_ratio"] = f"{ratio:.2f}:1"
            except Exception:
                pass
                
    # Offline fallback definitions
    if meta["archive_type"] == "Unknown":
        if ext == ".whl":
            meta["archive_type"] = "WHL"
            meta["compression_format"] = "Deflate (Estimated)"
        elif ext == ".tgz":
            meta["archive_type"] = "TGZ"
            meta["compression_format"] = "Gzip (Estimated)"
        elif ext == ".jar":
            meta["archive_type"] = "JAR"
            meta["compression_format"] = "Deflate (Estimated)"
            
    return meta

def compute_evidence_and_trust_score(component, api_data_fetched, has_override, has_license):
    """Score the detection confidence of the component (0-100%) and return verification list."""
    score = 0
    reasons = []
    evidence_list = []
    
    purl = component.get('purl', '')
    
    # 1. PURL availability (+20)
    if purl:
        score += 20
        reasons.append("PURL availability (+20)")
        evidence_list.append("PURL available")
        
    # 2. PURL confirmation (+30)
    if purl and api_data_fetched:
        score += 30
        reasons.append("PURL confirmation (+30)")
        evidence_list.append("PURL confirmed")
        
    # 3. Hash presence (+25)
    hashes = component.get('hashes', [])
    if hashes:
        score += 25
        reasons.append("Hash presence (+25)")
        for h in hashes:
            evidence_list.append(f"Hash value: {h.get('alg')}:{h.get('content')}")
            
    # 4. Identified license (+15)
    if has_license:
        score += 15
        reasons.append("Identified license (+15)")
        evidence_list.append("License identified")
        
    # 5. Config override review (+10)
    if has_override:
        score += 10
        reasons.append("Config override review (+10)")
        evidence_list.append("Override settings reviewed")
        
    score = min(score, 100)
    return score, reasons, evidence_list

def compute_component_criticality(is_cryptographic, is_runtime, is_os_component):
    """Quantitatively classify risks as Critical/High/Medium/Low based on component categories."""
    score = 15  # CycloneDX component (+15) baseline
    reasons = ["CycloneDX component (+15)"]
    
    if is_cryptographic:
        score += 40
        reasons.append("Cryptographics (+40)")
        
    if is_runtime:
        score += 30
        reasons.append("Code runtime libraries (+30)")
        
    if is_os_component:
        score += 20
        reasons.append("OS level packages (+20)")
        
    # Level assignments
    if score >= 70:
        level = "critical"
    elif score >= 40:
        level = "high"
    elif score >= 15:
        level = "medium"
    else:
        level = "low"
        
    reason_str = f"Assigned {level.upper()} (score: {score}) based on: " + "; ".join(reasons)
    return level, reason_str

def calculate_dependency_depths(sbom):
    """Construct dependency adjacency graph and compute BFS distance to each package."""
    metadata = sbom.get('metadata', {})
    root_component = metadata.get('component', {})
    root_ref = root_component.get('bom-ref')
    
    dependencies = sbom.get('dependencies', [])
    adj = {}
    for dep in dependencies:
        ref = dep.get('ref')
        depends_on = dep.get('dependsOn', [])
        if ref:
            adj[ref] = depends_on
            
    depths = {}
    if root_ref:
        from collections import deque
        queue = deque([(root_ref, 0)])
        visited = {root_ref}
        while queue:
            curr, d = queue.popleft()
            depths[curr] = d
            for child in adj.get(curr, []):
                if child not in visited:
                    visited.add(child)
                    queue.append((child, d + 1))
                    
    # Fallback check for unvisited components
    components = sbom.get('components', [])
    for comp in components:
        ref = comp.get('bom-ref') or comp.get('purl')
        if ref not in depths:
            is_child = False
            for dep in dependencies:
                if ref in dep.get('dependsOn', []):
                    is_child = True
                    break
            depths[ref] = 2 if is_child else 1
            
    return depths

def get_vulnerable_refs(sbom):
    """Aggregate all component references affected by Grype warnings."""
    v_refs = set()
    for v in sbom.get('vulnerabilities', []):
        for a in v.get('affects', []):
            ref = a.get('ref')
            if ref:
                v_refs.add(ref)
    return v_refs

def enrich_component(component, config, sbom_context):
    """Enrich a component with CycloneDX fields and our expanded enterprise metadata."""
    name = component.get('name', '')
    version = component.get('version', '')
    purl = component.get('purl', '')
    
    if purl and purl.startswith("pkg:pypi/"):
        purl_part = purl.split('?')[0]
        parts = purl_part.split('/')
        if len(parts) > 1:
            pkg_part = parts[-1]
            if '@' in pkg_part:
                purl_name, purl_ver = pkg_part.split('@', 1)
                if not name:
                    name = purl_name
                if not version or version.lower() == 'none' or version.lower() == 'unknown':
                    version = purl_ver

    if not version or version.lower() == 'none' or version.lower() == 'unknown':
        version = '1.0.0'
        component['version'] = version
        
    if not name:
        name = 'unknown-package'
        component['name'] = name
    
    # PURL formatting (Attribute 21 - Unique Identifier)
    purl = f"pkg:pypi/{name.lower()}@{version}"
    component['purl'] = purl
    
    if not component.get('bom-ref'):
        component['bom-ref'] = purl
    
    # Checksums or Hashes (Attribute 14)
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
        
    component['description'] = desc
    component['supplier'] = {"name": supplier}
    component['licenses'] = [{"license": {"name": license_name}}]
    
    # Calculate EOL date
    try:
        clean_date = release_date_str.replace('Z', '')
        if '.' in clean_date:
            clean_date = clean_date.split('.')[0]
        dt = datetime.fromisoformat(clean_date)
        eol_dt = dt + timedelta(days=365 * config.get('eol_years_from_release', 3))
        eol_date_str = eol_dt.isoformat() + "Z"
    except Exception:
        eol_date_str = (datetime.utcnow() + timedelta(days=365 * 3)).isoformat() + "Z"
        
    patch_status = "up-to-date" if version == latest_version else "patch-available"
    comments = override.get('comments') or config.get('default_comments')
    usage_restrictions = override.get('usage_restrictions') or config.get('default_usage_restrictions')

    # Locate local component file path
    src_dir = sbom_context['src_dir']
    file_path = resolve_component_file(component, src_dir)

    # Executable classifier
    executable_type, executable_evidence = detect_executable_property(component, file_path)

    # Archive characteristics
    archive_meta = inspect_archive_metadata(file_path, component)
    is_archive_flag = "true" if archive_meta["archive_type"] != "Unknown" else "false"
    archive_desc = f"Type: {archive_meta['archive_type']}, Format: {archive_meta['compression_format']}, Ratio: {archive_meta['compression_ratio']}, Nested: {archive_meta['nested_archives']}"

    # Repository detection
    repo_source = detect_repository_source(component, src_dir)

    # Trust Score assessment
    has_license = bool(license_name and license_name.lower() not in ['', 'unknown', 'none'])
    has_override = bool(override)
    
    trust_score, trust_reasons, trust_evidences = compute_evidence_and_trust_score(
        component, 
        api_data_fetched=(api_data is not None), 
        has_override=has_override, 
        has_license=has_license
    )
    trust_score_str = f"{trust_score}%"
    trust_reason_str = "Reasons: " + "; ".join(trust_reasons)
    evidence_desc = "Evidence: " + ", ".join(trust_evidences)

    # Criticality quantitative evaluation
    is_core = (name.lower() in ['django', 'flask', 'fastapi', 'numpy', 'pandas', 'tensorflow', 'torch', 'spring-core']) or (override.get('criticality') == 'critical')
    is_crypto = any(word in name.lower() or word in desc.lower() for word in [
        'crypto', 'ssl', 'hash', 'md5', 'sha', 'encrypt', 'decrypt', 'cipher', 'bcrypt', 'tls', 'jwt'
    ])
    purl_low = purl.lower()
    is_os = any(os_type in purl_low for os_type in ['pkg:rpm', 'pkg:deb', 'pkg:apk', 'pkg:alpm']) or any(
        'dpkg' in p.get('value', '').lower() or 'rpm' in p.get('value', '').lower() for p in component.get('properties', [])
    )
    # Known vulnerabilities
    bom_ref = component.get('bom-ref') or purl
    has_vulns = bom_ref in sbom_context['vulnerable_refs']
    # Runtime package check
    is_runtime = not any(word in name.lower() or any(word in pt for pt in [
        p.get('value', '').lower() for p in component.get('properties', []) if 'path' in p.get('name', '')
    ]) for word in ['test', 'dev', 'pytest', 'tox', 'black', 'flake8', 'pylint', 'sphinx', 'bandit'])

    # Override defaults if specified in config.json
    config_criticality = override.get('criticality')
    if config_criticality:
        criticality_level = config_criticality
        criticality_reason = f"Overridden by config.json to: {config_criticality}"
    else:
        criticality_level, criticality_reason = compute_component_criticality(
            is_cryptographic=is_crypto,
            is_runtime=is_runtime,
            is_os_component=is_os
        )

    # Format execution evidence
    exe_evidence_str = "Evidence: " + ", ".join(executable_evidence)

    # Populate properties (Attr 6, 9, 10, 11, 12, 13, 15, 18, 19, 20)
    properties = component.get('properties', [])
    
    # Filter out existing properties if we re-run
    properties = [p for p in properties if p.get('name') not in [
        'origin', 'patch_status', 'release_date', 'eol_date', 
        'criticality', 'criticality_reason', 'usage_restrictions', 'comments', 
        'executable', 'executable_evidence', 'archive', 'archive_metadata', 'structured',
        'trust_score', 'trust_score_reason', 'repository_source', 'evidence_findings'
    ]]
    
    # Standard properties
    properties.append({"name": "origin", "value": override.get('origin') or config.get('default_origin')})
    properties.append({"name": "patch_status", "value": patch_status})
    properties.append({"name": "release_date", "value": release_date_str})
    properties.append({"name": "eol_date", "value": eol_date_str})
    properties.append({"name": "criticality", "value": criticality_level})
    properties.append({"name": "criticality_reason", "value": criticality_reason})
    properties.append({"name": "usage_restrictions", "value": usage_restrictions})
    properties.append({"name": "comments", "value": comments})
    properties.append({"name": "executable", "value": executable_type})
    properties.append({"name": "executable_evidence", "value": exe_evidence_str})
    properties.append({"name": "archive", "value": is_archive_flag})
    properties.append({"name": "archive_metadata", "value": archive_desc})
    properties.append({"name": "structured", "value": config.get('default_structured_format')})
    properties.append({"name": "trust_score", "value": trust_score_str})
    properties.append({"name": "trust_score_reason", "value": trust_reason_str})
    properties.append({"name": "evidence_findings", "value": evidence_desc})
    properties.append({"name": "repository_source", "value": repo_source})
    
    component['properties'] = properties
    return component

def enrich_sbom(raw_sbom_path, enriched_sbom_path, config_path):
    print(f"Reading raw SBOM from {raw_sbom_path}...")
    with open(raw_sbom_path, 'r', encoding='utf-8') as f:
        sbom = json.load(f)
        
    config = load_config(config_path)
    
    # 1. Resolve source path & dynamic SBOM author
    src_dir = sbom.get('metadata', {}).get('component', {}).get('name', '')
    if not src_dir or not os.path.isdir(src_dir):
        src_dir = os.getcwd()
        
    print(f"Detected target scan source directory: {src_dir}")
    
    repo_owner = get_git_author_or_owner(src_dir)
    project_author = get_root_project_author(src_dir)
    
    final_author = repo_owner or project_author or config.get('author_name')
    print(f"Resolved Owner/Author of SBOM Data: {final_author}")
    
    # Update Metadata (Authors, Timestamp)
    metadata = sbom.setdefault('metadata', {})
    metadata['timestamp'] = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
    metadata['authors'] = [{
        "name": final_author,
        "email": config.get('author_email')
    }]
    
    # Calculate global details for criticality
    depths = calculate_dependency_depths(sbom)
    vulnerable_refs = get_vulnerable_refs(sbom)
    
    sbom_context = {
        "src_dir": src_dir,
        "depths": depths,
        "vulnerable_refs": vulnerable_refs
    }
    
    # Enrich components list
    components = sbom.get('components', [])
    enriched_components = []
    
    for comp in components:
        print(f"Enriching component: {comp.get('name')}@{comp.get('version')}...")
        enriched_comp = enrich_component(comp, config, sbom_context)
        enriched_components.append(enriched_comp)
        
    sbom['components'] = enriched_components
    
    # Clean and align dependencies list
    dependencies = sbom.setdefault('dependencies', [])
    existing_refs = {dep.get('ref') for dep in dependencies if dep.get('ref')}
    
    for comp in enriched_components:
        ref = comp.get('bom-ref') or comp.get('purl')
        if ref and ref not in existing_refs:
            dependencies.append({
                "ref": ref,
                "dependsOn": []
            })
            existing_refs.add(ref)
            
    sbom['dependencies'] = dependencies
    
    print(f"Writing enriched SBOM to {enriched_sbom_path}...")
    os.makedirs(os.path.dirname(os.path.abspath(enriched_sbom_path)), exist_ok=True)
    with open(enriched_sbom_path, 'w', encoding='utf-8') as f:
        json.dump(sbom, f, indent=2, ensure_ascii=False)
    print("Enrichment complete!")

if __name__ == "__main__":
    base_dir = os.path.dirname(os.path.abspath(__file__))
    
    raw_path = os.path.join(base_dir, "sbom_raw.json")
    enriched_path = os.path.join(base_dir, "sbom_enriched.json")
    cfg_path = os.path.join(base_dir, "config.json")
    
    if len(sys.argv) > 1:
        raw_path = sys.argv[1]
    if len(sys.argv) > 2:
        enriched_path = sys.argv[2]
    if len(sys.argv) > 3:
        cfg_path = sys.argv[3]
        
    enrich_sbom(raw_path, enriched_path, cfg_path)
