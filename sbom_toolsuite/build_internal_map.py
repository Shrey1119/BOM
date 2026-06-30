import json
import datetime
import os

# Paths
ENRICHED = 'sbom_output/sbom_enriched.json'
VEX      = 'sbom_output/vex.json'
CONFIG   = 'sbom_toolsuite/config.json'
OUTPUT   = 'sbom_output/internal_map.json'

os.makedirs('sbom_output', exist_ok=True)

# Fallbacks for flexibility
if not os.path.exists(ENRICHED) and os.path.exists('sbom_enriched.json'):
    ENRICHED = 'sbom_enriched.json'
if not os.path.exists(VEX) and os.path.exists('vex.json'):
    VEX = 'vex.json'
if not os.path.exists(VEX) and os.path.exists('sbom_output/vex.json'):
    VEX = 'sbom_output/vex.json'

print("Loading enriched SBOM and configurations...")
with open(ENRICHED, encoding='utf-8') as f: 
    sbom = json.load(f)
with open(CONFIG, encoding='utf-8') as f: 
    config = json.load(f)

# Load VEX vulnerability statuses (keyed by CVE id)
vex_status = {}
if os.path.exists(VEX):
    print(f"Loading VEX classifications from {VEX}...")
    with open(VEX, encoding='utf-8') as f: 
        vex = json.load(f)
    for v in vex.get('vulnerabilities', []):
        vex_status[v['id']] = v.get('analysis', {}).get('state', 'unknown')
else:
    print("Warning: VEX file not found. Components will have 'not_evaluated' vulnerability status.")

components = sbom.get('components', [])
crit_map   = config.get('criticality_overrides', {})
origin_map = config.get('origin_overrides', {})
restr_map  = config.get('usage_restrictions_overrides', {})
comments   = config.get('comments', {})

now = datetime.datetime.now(datetime.UTC).isoformat() + "Z" if hasattr(datetime, 'UTC') else datetime.datetime.utcnow().isoformat() + "Z"

internal_map = {
    "generated_at": now,
    "author": config.get("author"),
    "organization": config.get("organization"),
    "total_components": len(components),
    "components": []
}

for c in components:
    name = c.get('name', '').lower()
    props = {p['name']: p.get('value') for p in c.get('properties', [])}

    # Resolve CVE statuses for this component
    vulns = sbom.get('vulnerabilities', [])
    comp_cves = [
        {"id": v["id"], "severity": v.get("ratings",[{}])[0].get("severity","unknown"),
         "vex_status": vex_status.get(v["id"], "not_evaluated")}
        for v in vulns
        if any(a.get("ref") == c.get("bom-ref") for a in v.get("affects",[]))
    ]

    entry = {
        "name":               c.get('name'),
        "version":            c.get('version'),
        "purl":               c.get('purl'),
        "type":               c.get('type', 'library'),
        "supplier":           c.get('supplier', {}).get('name', 'unknown'),
        "license":            ', '.join(l.get('license',{}).get('id', l.get('license',{}).get('name', 'unknown')) for l in c.get('licenses',[])),
        "criticality":        crit_map.get(name, config.get('default_criticality', 'medium')),
        "origin":             origin_map.get(name, config.get('default_origin', 'open-source')),
        "usage_restrictions": restr_map.get(name, config.get('default_usage_restrictions', 'None')),
        "eol_date":           props.get('eol_date', 'unknown'),
        "release_date":       props.get('release_date', 'unknown'),
        "internal_comment":   comments.get(name, ''),
        "cve_exposure":       comp_cves,
        "active_in_build":    True
    }
    internal_map["components"].append(entry)

with open(OUTPUT, 'w', encoding='utf-8') as f:
    json.dump(internal_map, f, indent=2, ensure_ascii=False)

print(f'[OK] internal_map.json written — {len(components)} components mapped.')
