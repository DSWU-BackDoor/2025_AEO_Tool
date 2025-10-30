# aeo_tool/map.py
import json
import csv
from pathlib import Path
from typing import Dict, List, Any

def _safe(d: Dict, *keys, default=None):
    cur = d
    for k in keys:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(k, default)
        if cur is default:
            return default
    return cur

def map_sbom_vulns(sbom_path: str, vuln_path: str, out_csv: str) -> None:
    sbom_p = Path(sbom_path)
    vuln_p = Path(vuln_path)
    out_p = Path(out_csv)
    out_p.parent.mkdir(parents=True, exist_ok=True)

    if not sbom_p.exists():
        raise FileNotFoundError(f"SBOM not found: {sbom_p}")
    if not vuln_p.exists():
        raise FileNotFoundError(f"Vuln JSON not found: {vuln_p}")

    sbom = json.loads(sbom_p.read_text(encoding="utf-8"))
    vuln = json.loads(vuln_p.read_text(encoding="utf-8"))

    # Build component lookup by (name,version) and by purl
    comps_by_nv = {}
    comps_by_purl = {}
    for comp in sbom.get("components", []) or []:
        name = comp.get("name") or ""
        ver = comp.get("version") or ""
        purl = comp.get("purl")
        comps_by_nv.setdefault((name, ver), []).append(comp)
        if purl:
            comps_by_purl.setdefault(purl, []).append(comp)

    # Prepare CSV
    fieldnames = [
        "package",
        "package_version",
        "vulnerability_id",
        "severity",
        "fix_version",
        "component_name",
        "component_version",
        "component_purl",
    ]

    rows = []

    # Grype-like matches: robust handling
    matches = vuln.get("matches") if isinstance(vuln, dict) else []
    for m in matches:
        # artifact info (package)
        artifact = m.get("artifact", {}) or {}
        pkg_name = artifact.get("name") or _safe(m, "vulnerability", "package") or ""
        pkg_ver = artifact.get("version") or artifact.get("version", "") or ""

        # vulnerability info
        vuln_info = m.get("vulnerability", {}) or {}
        vuln_id = vuln_info.get("id") or vuln_info.get("vulnId") or ""
        severity = vuln_info.get("severity") or vuln_info.get("cvss", {}).get("severity") or ""
        # fix version: different schemas, try several fields
        fix_version = ""
        # grype sometimes has "fix" list or "fix" dict
        fix = vuln_info.get("fix", None)
        if isinstance(fix, dict):
            fix_version = fix.get("versions") or fix.get("version") or ""
            if isinstance(fix_version, list):
                fix_version = ",".join(fix_version)
        elif isinstance(fix, list) and fix:
            if isinstance(fix[0], dict):
                fv = fix[0].get("versions") or fix[0].get("version")
                if isinstance(fv, list):
                    fix_version = ",".join(fv)
                else:
                    fix_version = fv or ""
        else:
            # try metadata
            fix_version = vuln_info.get("metadata", {}).get("fix_version") or ""

        # attempt to find matching SBOM component
        component = None
        purl = artifact.get("purl")
        if purl and purl in comps_by_purl:
            component = comps_by_purl[purl][0]
        else:
            key = (pkg_name, pkg_ver)
            if key in comps_by_nv:
                component = comps_by_nv[key][0]

        comp_name = component.get("name") if component else ""
        comp_ver = component.get("version") if component else ""
        comp_purl = component.get("purl") if component else ""

        rows.append({
            "package": pkg_name,
            "package_version": pkg_ver,
            "vulnerability_id": vuln_id,
            "severity": severity,
            "fix_version": fix_version,
            "component_name": comp_name,
            "component_version": comp_ver,
            "component_purl": comp_purl,
        })

    # write CSV
    with out_p.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for r in rows:
            writer.writerow(r)
