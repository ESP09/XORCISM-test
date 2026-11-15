"""Background NVD backfill for findings that are missing a CVE id.

For every active finding without a CVE in ``vulnerability_ids``:
  1. alias resolution against the verified snapshot (GHSA/PYSEC/GO/OSV -> CVE, ZDAY aliases);
  2. (online posture only) OSV lookup of the non-CVE id via ``/v1/vulns/{id}``;
  3. (online posture only) NVD ``keywordSearch`` on "<component> <version>" (exact match) - applied
     only when exactly one CVE matches, tagged ``cve-source:nvd-keyword`` for analyst review.
Then CVSS (NVD 2.0), CWE and remediation (patched versions / vendor references) are populated.
Offline posture never makes network calls - it uses the imported snapshot only.

    nvd_backfill.py run [--limit 200]
"""
from __future__ import annotations

import os
import sys
import time
import urllib.parse
from typing import Any, Dict, List, Optional

from common import AutomationError, cfg_get, emit, http_json, http_request, load_config, log, read_json, state_dir, utc_now, write_json
from dojo_client import Dojo
from enrich import finding_ids
from feeds import FeedStore, open_store, posture
from remediation import guide
from sync_feeds import _urls


def _nvd_get(cfg: Dict[str, Any], params: Dict[str, Any]) -> Dict[str, Any]:
    key = os.environ.get("NVD_API_KEY", "")
    url = _urls(cfg)["nvd"] + "?" + urllib.parse.urlencode(params)
    return http_json("GET", url, headers={"apiKey": key} if key else {})


def _cvss_from_nvd(c: Dict[str, Any]) -> Dict[str, Any]:
    m = c.get("metrics") or {}
    for k in ("cvssMetricV31", "cvssMetricV30"):
        if m.get(k):
            d = m[k][0].get("cvssData") or {}
            return {"score": d.get("baseScore"), "vector": d.get("vectorString")}
    return {}


def run(cfg: Dict[str, Any], limit: int = 200, dojo: Optional[Dojo] = None, store: Optional[FeedStore] = None) -> Dict[str, Any]:
    dojo = dojo or Dojo.from_config(cfg)
    store = store or open_store(cfg)
    offline = posture(cfg)["offline"]
    delay = float(os.environ.get("DOJO_NVD_DELAY", "0.7" if os.environ.get("NVD_API_KEY") else "6.5"))
    findings = [d for d in dojo.findings(active="true") if not any(i.startswith("CVE-") for i in finding_ids(d))]
    report: Dict[str, Any] = {"started": utc_now(), "offline": offline, "candidates": len(findings), "resolved": 0,
                              "via": {"alias": 0, "osv": 0, "nvd-keyword": 0}, "enriched": 0, "unresolved": [], "updates": []}
    for d in findings[:limit]:
        ids = finding_ids(d)
        cve, via = None, None
        canonical, aliases = store.resolver.resolve(ids)
        cve = next((a for a in aliases if a.startswith("CVE-")), None)
        if cve:
            via = "alias"
        if not cve and not offline:
            for i in ids:
                r = http_request("GET", _urls(cfg)["osv"].rstrip("/") + "/vulns/" + urllib.parse.quote(i), expect_ok=False)
                if r.ok:
                    cve = next((a for a in r.json().get("aliases") or [] if a.startswith("CVE-")), None)
                    if cve:
                        via = "osv"
                        break
        if not cve and not offline and d.get("component_name"):
            kw = f"{d['component_name'].split(':')[-1].split('/')[-1]} {d.get('component_version') or ''}".strip()
            page = _nvd_get(cfg, {"keywordSearch": kw, "keywordExactMatch": "", "resultsPerPage": 5})
            vulns = page.get("vulnerabilities") or []
            if len(vulns) == 1:
                cve, via = vulns[0]["cve"]["id"], "nvd-keyword"
            time.sleep(delay)
        if not cve:
            report["unresolved"].append({"id": d["id"], "title": d.get("title"), "ids": ids})
            continue
        report["resolved"] += 1
        report["via"][via] += 1
        patch: Dict[str, Any] = {"vulnerability_ids": [{"vulnerability_id": x} for x in sorted(set(ids + [cve]))], "vuln_id_from_tool": cve}
        nvd = store.nvd.get(cve)
        if not nvd and not offline:
            page = _nvd_get(cfg, {"cveId": cve})
            nvd = ((page.get("vulnerabilities") or [{}])[0]).get("cve")
            time.sleep(delay)
        if nvd:
            cv = _cvss_from_nvd(nvd)
            if cv.get("score") is not None:
                patch["cvssv3_score"], patch["cvssv3"] = cv["score"], cv.get("vector")
            if not d.get("cwe"):
                for w in nvd.get("weaknesses") or []:
                    for x in w.get("description") or []:
                        v = x.get("value", "")
                        if v.startswith("CWE-") and v[4:].isdigit():
                            patch["cwe"] = int(v[4:])
        try:
            g = guide(store, cve, d.get("component_name"), d.get("component_version"))
            if g["steps"] and not d.get("mitigation"):
                patch["mitigation"] = "\n".join(f"{n + 1}. {s['title']}: {s['detail']}" for n, s in enumerate(g["steps"]))
            if g["references"] and not d.get("references"):
                patch["references"] = "\n".join(r["url"] for r in g["references"][:10])
        except AutomationError:
            pass
        tags = sorted(set((d.get("tags") or []) + [f"cve-source:{via}"]))
        patch["tags"] = tags
        dojo.patch(f"findings/{d['id']}", patch)
        report["enriched"] += 1
        report["updates"].append({"id": d["id"], "title": d.get("title"), "cve": cve, "via": via,
                                  "cvss": patch.get("cvssv3_score")})
    report["finished"] = utc_now()
    path = os.path.join(state_dir(cfg), "nvd-backfill.json")
    hist = read_json(path, {"runs": []}) or {"runs": []}
    hist["runs"] = (hist.get("runs") or [])[-49:] + [{k: v for k, v in report.items() if k not in ("updates", "unresolved")}]
    hist["last"] = report
    write_json(path, hist)
    log("nvd_backfill.done", resolved=report["resolved"], candidates=report["candidates"])
    return report


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--limit", type=int, default=200)
    sub.add_parser("status")
    a = ap.parse_args()
    cfg = load_config()
    try:
        if a.cmd == "status":
            emit(read_json(os.path.join(state_dir(cfg), "nvd-backfill.json"), {"runs": []}))
        else:
            emit(run(cfg, a.limit))
    except AutomationError as e:
        sys.stderr.write(f'{{"error": "{e}"}}\n')
        sys.exit(2)
