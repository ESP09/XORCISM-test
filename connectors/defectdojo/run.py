"""run.py — XORCISM connector: DefectDojo → assets / components / vulns.

Bridges XORCISM with an open-source DefectDojo instance, notably the AWS GovCloud deployment built by
the DefectDojo Pro IaC Studio (ESP09/vuln-mgmt-comp1-IaC), whose automation already resolves every
finding to a canonical id (CVE > ZDAY > GHSA), de-duplicates across scanners and enriches CVSS / EPSS /
CISA KEV. This connector imports that curated view into XORCISM's risk model:

  - each DefectDojo Product (software)  -> ASSET (tagged with its Product Type = platform)
  - each finding                         -> VULNERABILITY on that asset, ref = canonical id
  - component_name / component_version   -> components

Live:    read-only GET {url}/api/v2/findings/?related_fields=true (paginated). Token from the worker
         env DD_API_TOKEN (never a parameter, so it is not stored in the job record). HTTPS only;
         TLS is always verified (SSL_CERT_FILE / REQUESTS_CA_BUNDLE add an internal CA); HTTPS_PROXY
         and NO_PROXY are honoured.
Offline: parse a saved findings JSON export (paginated response, or a bare list).

Stdlib only; no DB access (worker-safe). Returns {project, assets, services, cpes, components, vulns}.
"""
from __future__ import annotations

import json
import os
import re
import ssl
import urllib.parse
import urllib.request
from typing import Any, Dict, Iterable, List, Optional

SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"]
_SEV_OUT = {"Critical": "critical", "High": "high", "Medium": "medium", "Low": "low", "Info": "info"}
_ID_RE = re.compile(r"^(CVE-\d{4}-\d{4,}|ZDAY-\d{4}-\d{3,6}|GHSA(-[23456789cfghjmpqrvwx]{4}){3}|PYSEC-\d{4}-\d+|GO-\d{4}-\d{4,}|OSV-\d{4}-\d+)$", re.I)
_PRIORITY = {"CVE": 0, "ZDAY": 1, "GHSA": 2}
MAX_PAGES = 500


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    product = str(params.get("product") or "").strip()
    include_mitigated = str(params.get("include_mitigated") or "").lower() in ("1", "true", "yes")
    min_sev = str(params.get("min_severity") or "Info").strip().capitalize()
    if min_sev not in SEVERITIES:
        raise ValueError(f"defectdojo: min_severity must be one of {SEVERITIES}")
    if params.get("file"):
        with open(params["file"], "r", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
        findings = data.get("results", []) if isinstance(data, dict) else data
    else:
        base = str(params.get("url") or os.getenv("DD_URL") or "").strip().rstrip("/")
        if not base:
            raise RuntimeError("defectdojo: provide a 'file' (findings JSON export) or a 'url' (+ DD_API_TOKEN in the worker env) for live mode")
        findings = list(_fetch(base, product, include_mitigated, int(params.get("limit") or 5000)))
    return _parse(findings, product, include_mitigated, min_sev)


# ── Live API (read-only) ────────────────────────────────────────────────────
def _ssl_context() -> ssl.SSLContext:
    cafile = next((p for p in (os.getenv("SSL_CERT_FILE"), os.getenv("REQUESTS_CA_BUNDLE")) if p and os.path.isfile(p)), None)
    ctx = ssl.create_default_context(cafile=cafile)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx  # verification is never disabled


def _fetch(base: str, product: str, include_mitigated: bool, limit: int) -> Iterable[Dict[str, Any]]:
    if urllib.parse.urlsplit(base).scheme != "https":
        raise RuntimeError("defectdojo: only https:// URLs are accepted")
    token = os.getenv("DD_API_TOKEN") or ""
    if not token:
        raise RuntimeError("defectdojo: DD_API_TOKEN is required in the worker env for live mode")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler(), urllib.request.HTTPSHandler(context=_ssl_context()))
    query: Dict[str, Any] = {"related_fields": "true", "duplicate": "false", "limit": 200}
    if not include_mitigated:
        query["active"] = "true"
    if product:
        query["product_name"] = product
    url: Optional[str] = f"{base}/api/v2/findings/?{urllib.parse.urlencode(query)}"
    seen = 0
    for _ in range(MAX_PAGES):
        if not url:
            return
        if urllib.parse.urlsplit(url).netloc != urllib.parse.urlsplit(base).netloc:
            raise RuntimeError("defectdojo: refusing cross-origin pagination link")
        req = urllib.request.Request(url, headers={"Authorization": f"Token {token}", "Accept": "application/json",
                                                   "User-Agent": "xorcism-connector-defectdojo/1.0"})
        with opener.open(req, timeout=60) as resp:
            page = json.loads(resp.read().decode("utf-8"))
        for f in page.get("results") or []:
            yield f
            seen += 1
            if seen >= limit:
                return
        url = page.get("next")


# ── Mapping ─────────────────────────────────────────────────────────────────
def _ids(f: Dict[str, Any]) -> List[str]:
    out: List[str] = []
    for v in f.get("vulnerability_ids") or []:
        raw = v.get("vulnerability_id") if isinstance(v, dict) else v
        s = str(raw or "").strip().upper()
        if s.startswith("GHSA-"):
            s = "GHSA-" + s[5:].lower()
        if _ID_RE.match(s) and s not in out:
            out.append(s)
    return out


def canonical_id(f: Dict[str, Any]) -> Optional[str]:
    ids = _ids(f)
    if not ids:
        return None
    return sorted(ids, key=lambda i: (_PRIORITY.get(i.split("-", 1)[0], 3), i))[0]


def _rel(f: Dict[str, Any]) -> Dict[str, Any]:
    return (((f.get("related_fields") or {}).get("test") or {}).get("engagement") or {})


def _parse(findings: List[Dict[str, Any]], product_filter: str, include_mitigated: bool, min_sev: str) -> Dict[str, Any]:
    assets: Dict[str, Dict[str, Any]] = {}
    vulns: List[Dict[str, Any]] = []
    components: Dict[str, Dict[str, str]] = {}
    seen: set = set()
    min_rank = SEVERITIES.index(min_sev)
    for f in findings:
        if not isinstance(f, dict) or f.get("duplicate") or f.get("false_p") or f.get("out_of_scope"):
            continue
        if not include_mitigated and (not f.get("active", True) or f.get("is_mitigated")):
            continue
        sev = f.get("severity") if f.get("severity") in SEVERITIES else "Info"
        if SEVERITIES.index(sev) > min_rank:
            continue
        eng = _rel(f)
        prod = (eng.get("product") or {})
        asset = str(prod.get("name") or f.get("product_name") or f.get("service") or "defectdojo").strip()
        if product_filter and asset != product_filter:
            continue
        platform = str((prod.get("prod_type") or {}).get("name") or "")
        assets.setdefault(asset, {"hostname": asset, "key": asset, "tags": [t for t in ("defectdojo", f"platform:{platform}" if platform else "") if t]})
        ref = canonical_id(f) or f"DOJO-{f.get('id')}"
        key = (asset, ref)
        if key in seen:  # one XORCISM vuln per (asset, canonical id), as in DefectDojo's one-ticket-per-CVE model
            continue
        seen.add(key)
        v: Dict[str, Any] = {"asset": asset, "ref": ref, "name": str(f.get("title") or ref)[:300], "severity": _SEV_OUT[sev]}
        if f.get("cvssv3_score") is not None:
            v["cvss"] = f["cvssv3_score"]
        for k_src, k_dst in (("epss_score", "epss"), ("epss_percentile", "epss_percentile"), ("known_exploited", "kev"),
                             ("ransomware_used", "ransomware"), ("kev_date", "kev_date"), ("cwe", "cwe")):
            if f.get(k_src) not in (None, "", 0, False):
                v[k_dst] = f[k_src]
        aliases = [i for i in _ids(f) if i != ref]
        if aliases:
            v["aliases"] = aliases
        if eng.get("name"):
            v["engagement"] = eng["name"]
        vulns.append(v)
        comp = str(f.get("component_name") or "").strip()
        if comp:
            ver = str(f.get("component_version") or "").strip()
            components.setdefault(f"{comp}@{ver}", {"name": comp, "version": ver, "asset": asset})
    return {"project": product_filter or "defectdojo", "assets": list(assets.values()), "services": [], "cpes": [],
            "components": list(components.values()), "vulns": vulns}


if __name__ == "__main__":
    import argparse
    import tempfile

    ap = argparse.ArgumentParser(description="DefectDojo import (dry run)")
    ap.add_argument("--file")
    ap.add_argument("--url", default="")
    ap.add_argument("--product", default="")
    ap.add_argument("--include-mitigated", action="store_true")
    ap.add_argument("--min-severity", default="Info")
    a = ap.parse_args()
    res = run({"file": a.file, "url": a.url, "product": a.product, "include_mitigated": a.include_mitigated,
               "min_severity": a.min_severity}, tempfile.mkdtemp())
    print(json.dumps(res, indent=2, ensure_ascii=False))
    print(f"\n[defectdojo] {len(res['assets'])} asset(s), {len(res['vulns'])} vuln(s), {len(res['components'])} component(s)", flush=True)
