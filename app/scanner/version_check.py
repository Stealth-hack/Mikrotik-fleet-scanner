"""Maps a device's RouterOS version to known CVEs it's affected by.

Version comparison here is deliberately simple (tuple comparison of dotted
version strings) — RouterOS versions don't have the pre-release/build-suffix
mess that would need something like `packaging.version`. If you start seeing
versions like "7.15rc3" break the comparison, that's the point to revisit it,
not before.
"""
import json
from pathlib import Path

CVE_DATA_PATH = Path(__file__).parent.parent / "cve_data" / "routeros_cves.json"


def _version_tuple(v: str) -> tuple:
    # strips anything after a non-digit/dot char, e.g. "6.49.7 (stable)" -> "6.49.7"
    core = v.split()[0]
    return tuple(int(p) for p in core.split(".") if p.isdigit())


def load_cve_data() -> list[dict]:
    with open(CVE_DATA_PATH) as f:
        return json.load(f)["cves"]


def check_version(routeros_version: str) -> list[dict]:
    """Returns a list of finding dicts (category/severity/title/detail/reference)
    for every known CVE the given version is affected by."""
    findings = []
    try:
        current = _version_tuple(routeros_version)
    except ValueError:
        # Unparseable version string — flag it rather than silently skipping,
        # since "we couldn't tell" is a finding an operator should see too.
        return [{
            "category": "cve",
            "severity": "low",
            "title": "Could not parse RouterOS version for CVE matching",
            "detail": f"Raw version string: {routeros_version!r}",
            "reference": None,
        }]

    for cve in load_cve_data():
        if current < _version_tuple(cve["affected_before"]):
            findings.append({
                "category": "cve",
                "severity": cve["severity"],
                "title": f"Affected by {cve['cve_id']}",
                "detail": cve["description"],
                "reference": cve["cve_id"],
            })
    return findings
