import json
import datetime
import os
import uuid

ENRICHED = 'sbom_output/sbom_enriched.json'
TRIAGE   = 'sbom_toolsuite/triage.json'
CONFIG   = 'sbom_toolsuite/config.json'
VEX_OUT  = 'sbom_output/vex.json'
CSAF_OUT = 'sbom_output/csaf.json'

# Ensure directories exist
os.makedirs('sbom_output', exist_ok=True)

print("Starting VEX & CSAF generation...")

# Check files
if not os.path.exists(ENRICHED):
    # Fallback to local files if output directory differs
    if os.path.exists('sbom_enriched.json'):
        ENRICHED = 'sbom_enriched.json'
    else:
        print(f"Error: {ENRICHED} not found.")
        exit(1)

with open(ENRICHED) as f: 
    sbom = json.load(f)
with open(TRIAGE) as f: 
    triage = json.load(f)
with open(CONFIG) as f: 
    config = json.load(f)

# Use datetime.datetime.now(datetime.UTC) or timezone-aware timestamps
now = datetime.datetime.now(datetime.UTC).isoformat() + "Z" if hasattr(datetime, 'UTC') else datetime.datetime.utcnow().isoformat() + "Z"

# ── Build CVE → SBOM vulnerability lookup ─────────────────────
sbom_vulns = {v['id']: v for v in sbom.get('vulnerabilities', [])}

# ── VEX Document ──────────────────────────────────────────────
vex = {
    "bomFormat":   "CycloneDX",
    "specVersion": "1.5",
    "version":     1,
    "serialNumber": f"urn:uuid:{uuid.uuid4()}",
    "metadata": {
        "timestamp": now,
        "authors": [{"name": config["author"]}],
        "component": {"name": config["organization"], "type": "application"}
    },
    "vulnerabilities": []
}

for t in triage:
    base = sbom_vulns.get(t['cve_id'], {})
    ratings = base.get('ratings', [{}])

    entry = {
        "id": t['cve_id'],
        "source": {"name": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{t['cve_id']}"},
        "ratings": ratings,
        "affects": [{
            "ref": t['component'],
            "versions": [{"version": t['version'], "status": t['status']}]
        }],
        "analysis": {
            "state":         t['status'],
            "justification": t['justification'],
            "response":      ["will_not_fix"] if t['status'] == 'not_affected'
                             else ["update"] if t['status'] == 'fixed'
                             else ["workaround_available"] if t['status'] == 'affected'
                             else []
        }
    }
    vex["vulnerabilities"].append(entry)

with open(VEX_OUT, 'w') as f:
    json.dump(vex, f, indent=2)
print(f"[OK] vex.json written — {len(triage)} vulnerabilities classified.")

# ── Build CSAF Advisory ───────────────────────────────────────
# Filter only 'affected' entries for the advisory
affected = [t for t in triage if t['status'] == 'affected']

csaf = {
    "document": {
        "csaf_version": "2.0",
        "title":        f"Security Advisory — {config['organization']}",
        "publisher": {
            "name":      config["author"],
            "namespace": "https://antigravity.ai/security",
            "category":  "vendor"
        },
        "tracking": {
            "id":                f"AA-{datetime.datetime.now(datetime.UTC).strftime('%Y%m%d') if hasattr(datetime, 'UTC') else datetime.datetime.utcnow().strftime('%Y%m%d')}-001",
            "status":            "final",
            "version":           "1",
            "initial_release_date": now,
            "current_release_date": now,
            "revision_history": [{
                "date":    now,
                "number": "1",
                "summary":"Initial release"
            }]
        },
        "distribution": {"tlp": {"label": "AMBER"}},
        "references": [{
            "url":      "https://nvd.nist.gov",
            "summary": "National Vulnerability Database"
        }]
    },
    "product_tree": {
        "branches": [{
            "category": "product_family",
            "name":     config["organization"],
            "branches": [{
                "category": "product_version",
                "name":     t["component"] + "@" + t["version"],
                "product":  {
                    "name":       t["component"],
                    "product_id": t["component"]
                }
            } for t in affected]
        }]
    },
    "vulnerabilities": [{
        "cve": t["cve_id"],
        "title": f"Affected: {t['component']} {t['version']}",
        "notes": [{
            "category": "description",
            "text": t["justification"]
        }],
        "product_status": {
            "known_affected":    [t["component"]],
            "fixed":             [t["component"]] if t.get("fixed_version") else []
        },
        "remediations": [{
            "category":   "vendor_fix",
            "details":    f"Upgrade to {t['component']} {t['fixed_version']}"
                          if t.get("fixed_version") else "Apply compensating control — see justification",
            "product_ids": [t["component"]]
        }],
        "scores": sbom_vulns.get(t['cve_id'], {}).get('ratings', [])
    } for t in affected]
}

with open(CSAF_OUT, 'w') as f:
    json.dump(csaf, f, indent=2)
print(f"[OK] csaf.json written — {len(affected)} affected vulnerabilities documented.")
