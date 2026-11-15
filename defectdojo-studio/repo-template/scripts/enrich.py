"""Enrich active DefectDojo findings with CVE / CVSS / EPSS / KEV metadata from the verified snapshot.

Sets (only when changed): ``cvssv3_score``, ``cvssv3``, ``epss_score``, ``epss_percentile``,
``known_exploited``, ``ransomware_used``, ``kev_date``, ``vuln_id_from_tool`` (canonical id) and,
when ``enrichment.kevMinSeverity`` is set, escalates KEV-listed findings to at least that severity.
Also refreshes ``watchlist.json`` (ids present in findings) consumed by ``sync_feeds.py``.
"""
from __future__ import annotations

import os
import sys
from typing import Any, Dict, List, Optional

from common import AutomationError, SEVERITIES, cfg_get, emit, load_config, log, state_dir, write_json
from dojo_client import Dojo
from feeds import FeedStore, open_store
from ids import normalize_id


def finding_ids(d: Dict[str, Any]) -> List[str]:
    ids = []
    for v in d.get("vulnerability_ids") or []:
        raw = v.get("vulnerability_id") if isinstance(v, dict) else v
        n = normalize_id(raw)
        if n and n not in ids:
            ids.append(n)
    n = normalize_id(d.get("vuln_id_from_tool"))
    if n and n not in ids:
        ids.insert(0, n)
    return ids


def enrich_one(store: FeedStore, d: Dict[str, Any], kev_min: Optional[str]) -> Dict[str, Any]:
    canonical, aliases = store.resolver.resolve(finding_ids(d))
    patch: Dict[str, Any] = {}
    if not canonical:
        return patch
    if d.get("vuln_id_from_tool") != canonical:
        patch["vuln_id_from_tool"] = canonical
    have = {(v.get("vulnerability_id") if isinstance(v, dict) else v) for v in d.get("vulnerability_ids") or []}
    if set(aliases) - have:
        patch["vulnerability_ids"] = [{"vulnerability_id": a} for a in aliases]
    cve = next((a for a in aliases if a.startswith("CVE-")), None)
    if not cve:
        return patch
    cv = store.cvss(cve)
    if cv.get("score") is not None and d.get("cvssv3_score") != cv["score"] and str(cv.get("version", "")).startswith("3"):
        patch["cvssv3_score"] = cv["score"]
        if cv.get("vector"):
            patch["cvssv3"] = cv["vector"]
    e = store.epss.get(cve)
    if e:
        sc, pc = round(float(e["epss"]), 5), round(float(e["percentile"]), 5)
        if d.get("epss_score") != sc:
            patch["epss_score"] = sc
        if d.get("epss_percentile") != pc:
            patch["epss_percentile"] = pc
    k = store.kev.get(cve)
    if bool(d.get("known_exploited")) != bool(k):
        patch["known_exploited"] = bool(k)
    if k:
        rw = str(k.get("knownRansomwareCampaignUse", "")).lower() == "known"
        if bool(d.get("ransomware_used")) != rw:
            patch["ransomware_used"] = rw
        if d.get("kev_date") != k.get("dateAdded"):
            patch["kev_date"] = k.get("dateAdded")
        if kev_min and SEVERITIES.index(d.get("severity", "Info")) > SEVERITIES.index(kev_min):
            patch["severity"] = kev_min
    if not d.get("cwe"):
        cw = store.cwes(cve)
        if cw and cw[0][4:].isdigit():
            patch["cwe"] = int(cw[0][4:])
    return patch


def run(cfg: Dict[str, Any], dojo: Optional[Dojo] = None, store: Optional[FeedStore] = None) -> Dict[str, Any]:
    dojo = dojo or Dojo.from_config(cfg)
    store = store or open_store(cfg)
    kev_min = cfg_get(cfg, "enrichment.kevMinSeverity", "High") or None
    findings = dojo.findings(active="true")
    updated, watch = 0, set()
    stats = {"kev": 0, "epss": 0, "cvss": 0, "canonicalised": 0}
    for d in findings:
        for i in finding_ids(d):
            watch.add(i)
        patch = enrich_one(store, d, kev_min)
        if patch:
            dojo.patch(f"findings/{d['id']}", patch)
            updated += 1
            stats["kev"] += int("known_exploited" in patch and patch["known_exploited"])
            stats["epss"] += int("epss_score" in patch)
            stats["cvss"] += int("cvssv3_score" in patch)
            stats["canonicalised"] += int("vuln_id_from_tool" in patch)
    write_json(os.path.join(state_dir(cfg), "watchlist.json"), sorted(watch))
    res = {"checked": len(findings), "updated": updated, "stats": stats, "watchlist": len(watch),
           "snapshot": store.state.get("manifestSha256"), "offline": bool(store.state.get("offline"))}
    log("enrich.done", **res)
    return res


if __name__ == "__main__":
    try:
        emit(run(load_config()))
    except AutomationError as e:
        sys.stderr.write(f'{{"error": "{e}"}}\n')
        sys.exit(2)
