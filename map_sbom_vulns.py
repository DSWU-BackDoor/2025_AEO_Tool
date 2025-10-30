import json, csv, pathlib, sys

sbom_path = pathlib.Path("out/sbom-cyclonedx.json")
vuln_path = pathlib.Path("out/vulns.json")
out_csv = pathlib.Path("out/mapping.csv")

if not sbom_path.exists():
    print("SBOM 파일 없음:", sbom_path); sys.exit(1)
if not vuln_path.exists():
    print("VULN 파일 없음:", vuln_path); sys.exit(1)

sbom = json.loads(sbom_path.read_text(encoding='utf-8'))
vuln = json.loads(vuln_path.read_text(encoding='utf-8'))

components_by_nv = {}
components_by_purl = {}
for comp in sbom.get("components", []) or []:
    name = comp.get("name","")
    ver = comp.get("version","")
    purl = comp.get("purl")
    components_by_nv.setdefault((name,ver), []).append(comp)
    if purl:
        components_by_purl.setdefault(purl, []).append(comp)

raw_matches = vuln.get("matches", []) if isinstance(vuln, dict) else []
rows = []

for m in raw_matches:
    art = m.get("artifact", {}) or {}
    vac = m.get("vulnerability", {}) or {}
    aname = art.get("name") or art.get("id") or ""
    aver = art.get("version") or ""
    vid = vac.get("id") or vac.get("vulnId") or vac.get("cve") or ""
    severity = vac.get("severity") or ""
    fix = ""
    fix_info = vac.get("fix", {})
    if isinstance(fix_info, dict):
        v = fix_info.get("versions") or fix_info.get("version")
        if isinstance(v, list):
            fix = ", ".join(v)
        elif v:
            fix = str(v)
    mapped = []
    if (aname, aver) in components_by_nv:
        mapped = components_by_nv[(aname, aver)]
    art_purl = art.get("purl") or art.get("id")
    if not mapped and art_purl and art_purl in components_by_purl:
        mapped = components_by_purl[art_purl]
    if not mapped:
        for (n,v), comps in components_by_nv.items():
            if n == aname:
                mapped.extend(comps)
    if not mapped:
        rows.append({
            "package": aname, "package_version": aver, "vulnerability_id": vid,
            "severity": severity, "fix_version": fix, "component_name": "", "component_version": "", "component_purl": ""
        })
    else:
        for comp in mapped:
            rows.append({
                "package": aname, "package_version": aver, "vulnerability_id": vid,
                "severity": severity, "fix_version": fix,
                "component_name": comp.get("name",""), "component_version": comp.get("version",""), "component_purl": comp.get("purl","")
            })

with out_csv.open("w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=["package","package_version","vulnerability_id","severity","fix_version","component_name","component_version","component_purl"])
    writer.writeheader()
    for r in rows:
        writer.writerow(r)

print("생성완료:", out_csv, "행:", len(rows))
