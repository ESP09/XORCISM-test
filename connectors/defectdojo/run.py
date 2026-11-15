"""run.py — XORCISM connector: DefectDojo → assets / components / vulns.

Bridges XORCISM with an open-source DefectDojo instance, notably the AWS GovCloud deployment built by
the DefectDojo Pro IaC Studio (ESP09/vuln-mgmt-comp1-IaC), whose automation already resolves every
finding to a canonical id (CVE > ZDAY > GHSA), de-duplicates across scanners and enriches CVSS / EPSS /
CISA KEV. This connector imports that curated view into XORCISM's risk model:

  - each DefectDojo Product (software)  -> ASSET (tagged with its Product Type = platform)
  - each finding                         -> VULNERABILITY on that asset, ref = canonical id
  - component_name / component_version   -> components

Live:    read-only GET $DD_URL/api/v2/findings/?related_fields=true (paginated). The URL and the token
         (DD_API_TOKEN) both come from the worker env, never from job parameters: a job cannot send the
         worker's token to another host. HTTPS only; TLS is always verified (SSL_CERT_FILE /
         REQUESTS_CA_BUNDLE add an internal CA); redirects are refused; HTTPS_PROXY and NO_PROXY are honoured.
Offline: parse a saved findings JSON export (paginated response, or a bare list) located in the job's
         workdir, XORCISM's upload directory (XORCISM_UPLOAD_DIR, os.pathsep-separated, else
         $XORCISM_DB_DIR/uploads) or this connector's folder; other paths are refused.

Stdlib only; no DB access (worker-safe). Returns {project, assets, services, cpes, components, vulns}.
"""
from __future__ import annotations

import json
import os
import re
import ssl
import sys
import urllib.parse
import urllib.request
from typing import Any, Dict, Iterable, List, Optional

SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"]
_SEV_OUT = {"Critical": "critical", "High": "high", "Medium": "medium", "Low": "low", "Info": "info"}
_ID_RE = re.compile(r"^(CVE-\d{4}-\d{4,}|ZDAY-\d{4}-\d{3,6}|GHSA(-[23456789cfghjmpqrvwx]{4}){3}|PYSEC-\d{4}-\d+|GO-\d{4}-\d{4,}|OSV-\d{4}-\d+)$", re.I)
_PRIORITY = {"CVE": 0, "ZDAY": 1, "GHSA": 2}
MAX_PAGES = 500
MAX_FILE_BYTES = 200 * 1024 * 1024
MAX_PAGE_BYTES = 50 * 1024 * 1024


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """urllib copies the Authorization header to a redirect target, even on another host: refuse redirects."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        raise RuntimeError(f"defectdojo: refusing HTTP {code} redirect to {newurl}")


def _allowed_file(path: str, workdir: str) -> str:
    real = os.path.realpath(path)
    # The job workdir, XORCISM's upload store (XORCISM_UPLOAD_DIR, else $XORCISM_DB_DIR/uploads) and this
    # connector's own folder (bundled sample.json for --selftest). Nothing else on the worker can be read.
    roots = [workdir, os.path.dirname(os.path.abspath(__file__))]
    roots += [d for d in os.getenv("XORCISM_UPLOAD_DIR", "").split(os.pathsep) if d]
    if not os.getenv("XORCISM_UPLOAD_DIR") and os.getenv("XORCISM_DB_DIR"):
        roots.append(os.path.join(os.environ["XORCISM_DB_DIR"], "uploads"))
    for root in roots:
        base = os.path.realpath(root)
        if real == base or real.startswith(base.rstrip(os.sep) + os.sep):
            if not os.path.isfile(real):
                raise ValueError("defectdojo: 'file' is not a regular file")
            if os.path.getsize(real) > MAX_FILE_BYTES:
                raise ValueError("defectdojo: 'file' exceeds the 200 MB limit")
            return real
    raise ValueError("defectdojo: 'file' must be inside the job workdir or XORCISM's upload directory")


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:
    product = str(params.get("product") or "").strip()
    include_mitigated = str(params.get("include_mitigated") or "").lower() in ("1", "true", "yes")
    min_sev = str(params.get("min_severity") or "Info").strip().capitalize()
    if min_sev not in SEVERITIES:
        raise ValueError(f"defectdojo: min_severity must be one of {SEVERITIES}")
    if params.get("url"):
        raise ValueError("defectdojo: the 'url' parameter was removed; set DD_URL in the worker environment")
    if params.get("file"):
        with open(_allowed_file(str(params["file"]), workdir), "r", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
        findings = data.get("results", []) if isinstance(data, dict) else data
    else:
        base = str(os.getenv("DD_URL") or "").strip().rstrip("/")
        if not base:
            raise RuntimeError("defectdojo: provide a 'file' (findings JSON export), or set DD_URL and DD_API_TOKEN in the worker env for live mode")
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
    opener = urllib.request.build_opener(urllib.request.ProxyHandler(), urllib.request.HTTPSHandler(context=_ssl_context()), _NoRedirect())
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
            raw = resp.read(MAX_PAGE_BYTES + 1)
            if len(raw) > MAX_PAGE_BYTES:
                raise RuntimeError("defectdojo: API page exceeds 50 MB")
            page = json.loads(raw.decode("utf-8"))
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
    # Operator CLI (outside the XORCISM worker): prints XORCISM's normalized result, e.g. to inspect or hand
    # over an export. Live mode reads DD_URL and DD_API_TOKEN from the environment, like the worker.
    import argparse
    import tempfile

    ap = argparse.ArgumentParser(description="DefectDojo -> XORCISM normalized result (assets, vulns, components)")
    ap.add_argument("--file", help="Offline: a saved GET /api/v2/findings/?related_fields=true export")
    ap.add_argument("--product", default="")
    ap.add_argument("--include-mitigated", action="store_true")
    ap.add_argument("--min-severity", default="Info")
    ap.add_argument("--out", help="Write the JSON result to this file instead of stdout")
    a = ap.parse_args()
    params = {"product": a.product, "include_mitigated": a.include_mitigated, "min_severity": a.min_severity}
    workdir = tempfile.mkdtemp()
    if a.file:
        params["file"] = os.path.abspath(a.file)
        workdir = os.path.dirname(params["file"])  # the operator chose this file explicitly
    res = run(params, workdir)
    text = json.dumps(res, indent=2, ensure_ascii=False)
    if a.out:
        with open(a.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        print(json.dumps({"out": a.out, "assets": len(res["assets"]), "vulns": len(res["vulns"]), "components": len(res["components"])}))
    else:
        print(text)
    print(f"[defectdojo] {len(res['assets'])} asset(s), {len(res['vulns'])} vuln(s), {len(res['components'])} component(s)", file=sys.stderr, flush=True)
