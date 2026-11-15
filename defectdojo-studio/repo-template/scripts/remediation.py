"""Remediation guidance from the verified threat-feed snapshot (no live calls in offline posture).

    remediation.py --id CVE-2021-44228 [--component log4j-core] [--version 2.14.1]

Combines: CISA KEV (requiredAction + dueDate), OSV affected ranges (fixed versions per package),
GHSA first_patched_version, NVD CVSS / CWE / references (Patch + Vendor Advisory first) and
internal zero-day bulletins (interim mitigations), into ordered, step-by-step instructions.
"""
from __future__ import annotations

import sys
from typing import Any, Dict, List, Optional

from common import AutomationError, cfg_get, emit, load_config, log
from feeds import FeedStore, open_store
from ids import normalize_id

_REF_ORDER = {"Patch": 0, "Vendor Advisory": 1, "Mitigation": 2, "Third Party Advisory": 3, "US Government Resource": 4}


def _fixed_versions(store: FeedStore, vid: str, component: Optional[str]) -> List[Dict[str, Any]]:
    adv = store.advisories_for(vid)
    fixes: Dict[str, Dict[str, Any]] = {}
    for o in adv["osv"]:
        for aff in o.get("affected") or []:
            pkg = aff.get("package") or {}
            name = pkg.get("name") or ""
            for rng in aff.get("ranges") or []:
                for ev in rng.get("events") or []:
                    if ev.get("fixed"):
                        key = f"{pkg.get('ecosystem')}:{name}"
                        f = fixes.setdefault(key, {"ecosystem": pkg.get("ecosystem"), "package": name, "fixed": [], "source": o["id"]})
                        if ev["fixed"] not in f["fixed"]:
                            f["fixed"].append(ev["fixed"])
    for g in adv["ghsa"]:
        for v in g.get("vulnerabilities") or []:
            pkg = v.get("package") or {}
            patched = v.get("first_patched_version")
            if isinstance(patched, dict):
                patched = patched.get("identifier")
            if patched:
                key = f"{pkg.get('ecosystem')}:{pkg.get('name')}"
                f = fixes.setdefault(key, {"ecosystem": pkg.get("ecosystem"), "package": pkg.get("name"), "fixed": [], "source": g["ghsa_id"]})
                if patched not in f["fixed"]:
                    f["fixed"].append(patched)
    out = list(fixes.values())
    if component:
        c = component.lower().replace(":", "/")
        out.sort(key=lambda f: 0 if c.endswith(str(f["package"]).lower().replace(":", "/").split("/")[-1]) else 1)
    return out


def guide(store: FeedStore, vid: str, component: Optional[str] = None, version: Optional[str] = None) -> Dict[str, Any]:
    n = normalize_id(vid)
    if not n:
        raise AutomationError(f"invalid vulnerability id {vid}")
    canonical, aliases = store.resolver.resolve([n])
    canonical = canonical or n
    cve = next((a for a in aliases if a.startswith("CVE-")), canonical if canonical.startswith("CVE-") else None)
    kev = store.kev.get(cve or "") if cve else None
    epss = store.epss.get(cve or "") if cve else None
    cvss = store.cvss(cve) if cve else {}
    fixes = _fixed_versions(store, canonical, component)
    adv = store.advisories_for(canonical)
    zday = adv["zeroday"]
    refs = store.references(cve) if cve else []
    refs.sort(key=lambda r: min([_REF_ORDER.get(t, 9) for t in r["tags"]] or [9]))
    for g in adv["ghsa"]:
        if g.get("html_url"):
            refs.append({"url": g["html_url"], "tags": ["GitHub Advisory"]})
    for o in adv["osv"]:
        for r in o.get("references") or []:
            if r.get("url") and all(r["url"] != x["url"] for x in refs):
                refs.append({"url": r["url"], "tags": [r.get("type") or "OSV"]})

    steps: List[Dict[str, str]] = []
    if kev:
        steps.append({"title": "Meet the CISA KEV deadline",
                      "detail": f"Listed in CISA KEV on {kev.get('dateAdded')}; federal due date {kev.get('dueDate')}. Required action: {kev.get('requiredAction')}"})
    for z in zday:
        for m in z.get("mitigations") or []:
            steps.append({"title": f"Interim mitigation ({z['id']})", "detail": m})
    if fixes:
        for f in fixes[:4]:
            target = ", ".join(f["fixed"])
            cur = f" (installed {version})" if version else ""
            steps.append({"title": f"Upgrade {f['package']}{cur}",
                          "detail": f"Upgrade {f['ecosystem']} package {f['package']} to {target} or later; rebuild and redeploy the image, "
                                    "then re-run the Trivy/Grype SBOM scan to confirm closure."})
    elif component:
        steps.append({"title": f"Upgrade {component}", "detail": "No fixed version is recorded in the synced OSV/GHSA data; follow the vendor advisory below."})
    if not steps or (not fixes and not kev):
        steps.append({"title": "Apply the vendor fix or compensating control",
                      "detail": "Apply the patch referenced by the vendor advisory. If no fix exists, restrict exposure (NetworkPolicy, WAF rule, "
                                "feature flag) and record a risk acceptance with an expiry in DefectDojo."})
    steps.append({"title": "Verify and close", "detail": "Re-scan; the reimport closes the DefectDojo finding and the automation closes the Jira ticket. "
                                                         "Recurrence reopens the same ticket."})
    desc = store.description(cve) if cve else ""
    if not desc and zday:
        desc = zday[0].get("summary", "")
    if not desc and adv["ghsa"]:
        desc = adv["ghsa"][0].get("summary", "")
    return {
        "id": canonical, "aliases": aliases, "cve": cve, "summary": desc,
        "cvss": cvss, "cwe": store.cwes(cve) if cve else [],
        "epss": {"score": float(epss["epss"]), "percentile": float(epss["percentile"]), "date": epss.get("date")} if epss else None,
        "kev": {"dateAdded": kev.get("dateAdded"), "dueDate": kev.get("dueDate"), "requiredAction": kev.get("requiredAction"),
                "knownRansomwareCampaignUse": kev.get("knownRansomwareCampaignUse"), "vendorProject": kev.get("vendorProject"),
                "product": kev.get("product")} if kev else None,
        "zeroday": [{"id": z["id"], "title": z.get("title"), "status": z.get("status")} for z in zday],
        "patchedVersions": fixes, "steps": steps, "references": refs[:15],
        "snapshot": {"manifestSha256": store.state.get("manifestSha256"), "offline": bool(store.state.get("offline")),
                     "generated": store.state.get("generated")},
    }


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="Remediation guide for a vulnerability id")
    ap.add_argument("--id", required=True)
    ap.add_argument("--component")
    ap.add_argument("--version")
    a = ap.parse_args()
    try:
        emit(guide(open_store(load_config()), a.id, a.component, a.version))
    except AutomationError as e:
        sys.stderr.write(f'{{"error": "{e}"}}\n')
        sys.exit(2)
