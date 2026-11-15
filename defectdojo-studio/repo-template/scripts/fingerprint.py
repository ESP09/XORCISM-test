"""Deterministic SHA-256 finding fingerprints and batch / cross-scanner de-duplication.

Fingerprint (algorithm ``v1``)::

    sha256( "v1" | location | line | vulnerability_type | source_scanner )

* ``location``  – normalised ``file_path``; falls back to the component (``purl`` or
  ``name@version``), then the URI (scheme://host[:port]/path, no query/fragment), then the asset.
* ``line``      – integer line number (0 when unknown).
* ``vulnerability_type`` – canonical vulnerability id (CVE / ZDAY / GHSA …) when known,
  else ``CWE-n``, else the scanner rule id, else a slug of the title.
* ``source_scanner`` – normalised scanner name (``zap``, ``trivy``, ``trivy-sbom`` …).

Path normalisation: ``\\`` -> ``/``, ``file://`` removed, repeated ``./`` stripped, ``//`` collapsed,
``/./`` removed, Windows drive letters lower-cased, trailing ``/`` removed.

De-duplication classes (assigned to the *incoming* finding):

``fingerprint-dup``   same fingerprint as an existing/earlier finding (exact duplicate)
``cross-source-dup``  same location+line+type but reported by a different scanner
``possible-dup``      same type and same base location (file without line / component without
                      version / URI path) – flagged for analyst review, still imported
``new``               none of the above
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
import urllib.parse
from typing import Any, Dict, Iterable, List, Optional, Tuple

from ids import normalize_id

ALGORITHM = "v1"

_SCANNER_ALIASES = {
    "zap": "zap", "owasp zap": "zap", "zap scan": "zap", "owasp-zap": "zap", "zaproxy": "zap",
    "trivy": "trivy", "trivy scan": "trivy", "trivy-sbom": "trivy-sbom", "trivy sbom": "trivy-sbom",
    "cyclonedx": "trivy-sbom", "cyclonedx scan": "trivy-sbom",
    "semgrep": "semgrep", "semgrep json report": "semgrep",
    "wazuh": "wazuh", "grype": "grype-sbom", "anchore grype": "grype-sbom", "grype-sbom": "grype-sbom",
    "gitleaks": "gitleaks", "gitleaks scan": "gitleaks", "prowler": "prowler", "nuclei": "nuclei",
    "nuclei scan": "nuclei", "tenable": "tenable", "tenable scan": "tenable", "nessus": "tenable",
    "sarif": "sarif", "manual": "manual", "manual input": "manual", "office": "manual",
}

_MULTI_SLASH = re.compile(r"/{2,}")
_DRIVE = re.compile(r"^([A-Za-z]):/")


def normalize_scanner(name: Any) -> str:
    s = re.sub(r"\s+", " ", str(name or "").strip().lower())
    return _SCANNER_ALIASES.get(s, re.sub(r"[^a-z0-9.-]+", "-", s).strip("-") or "unknown")


def normalize_path(path: Any) -> str:
    if path is None:
        return ""
    p = str(path).strip().replace("\\", "/")
    if p.lower().startswith("file://"):
        p = urllib.parse.unquote(p[7:])
        if re.match(r"^/[A-Za-z]:/", p):
            p = p[1:]
    p = _MULTI_SLASH.sub("/", p)
    while p.startswith("./"):
        p = p[2:]
    while "/./" in p:
        p = p.replace("/./", "/")
    if p.endswith("/."):
        p = p[:-2]
    m = _DRIVE.match(p)
    if m:
        p = m.group(1).lower() + p[1:]
    if len(p) > 1 and p.endswith("/"):
        p = p.rstrip("/")
    return p


def normalize_uri(uri: Any) -> str:
    if not uri:
        return ""
    s = str(uri).strip()
    if "://" not in s:
        return normalize_path(s)
    p = urllib.parse.urlsplit(s)
    scheme = p.scheme.lower()
    host = (p.hostname or "").lower()
    port = p.port
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        host = f"{host}:{port}"
    path = _MULTI_SLASH.sub("/", p.path or "/")
    if len(path) > 1:
        path = path.rstrip("/")
    return f"{scheme}://{host}{path}"


_OS_PURL_TYPES = {"deb", "rpm", "apk", "alpm", "alpine", "ubuntu", "debian"}


def _purl_parts(purl: str) -> Tuple[str, str]:
    s = str(purl).strip().split("#", 1)[0].split("?", 1)[0]
    if not s.lower().startswith("pkg:"):
        return s, ""
    body = s[4:]
    ptype, _, rest = body.partition("/")
    path, _, version = rest.partition("@")
    segs = [urllib.parse.unquote(x) for x in path.split("/") if x]
    if ptype.lower() in _OS_PURL_TYPES and segs:
        name = segs[-1]
    else:
        name = "/".join(segs)
    return name, urllib.parse.unquote(version)


def normalize_component(name: Any = None, version: Any = None, purl: Any = None) -> str:
    """Scanner-independent component key ``name@version``.

    Trivy reports ``org.apache.logging.log4j:log4j-core`` while Grype/CycloneDX report the purl
    ``pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1``; both normalise to
    ``org.apache.logging.log4j/log4j-core@2.14.1``. OS-package purls drop the distro namespace.
    """
    n, v = (str(name).strip() if name else ""), (str(version).strip() if version else "")
    if purl and (not n or not v):
        pn, pv = _purl_parts(str(purl))
        n, v = n or pn, v or pv
    if not n:
        return ""
    n = n.lower().replace(":", "/")
    if v.lower().startswith("v") and v[1:2].isdigit():
        v = v[1:]
    return f"{n}@{v}" if v else n


def _slug(text: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "-", str(text or "").lower()).strip("-")[:120]


def vulnerability_type(f: Dict[str, Any]) -> str:
    canonical = f.get("canonical_id") or (f.get("vuln_ids") or [None])[0]
    n = normalize_id(canonical) if canonical else None
    if n and not n.startswith("CWE-"):
        return n
    if f.get("cwe"):
        try:
            return f"CWE-{int(str(f['cwe']).upper().replace('CWE-', ''))}"
        except ValueError:
            pass
    if f.get("rule_id"):
        return "rule:" + str(f["rule_id"]).strip().lower()
    return "title:" + _slug(f.get("title"))


def location(f: Dict[str, Any]) -> Tuple[str, str]:
    """Return (kind, normalised location)."""
    if f.get("file_path"):
        return "file", normalize_path(f["file_path"])
    comp = normalize_component(f.get("component"), f.get("component_version"), f.get("purl"))
    if comp:
        return "component", comp
    if f.get("uri"):
        return "uri", normalize_uri(f["uri"])
    return "asset", str(f.get("asset") or "").strip().lower()


def base_location(f: Dict[str, Any]) -> str:
    k, loc = location(f)
    if k == "component":
        return loc.rsplit("@", 1)[0]
    return loc


def _line(f: Dict[str, Any]) -> int:
    try:
        return max(0, int(f.get("line") or 0))
    except (TypeError, ValueError):
        return 0


def _h(*parts: Any) -> str:
    return hashlib.sha256("|".join(str(p) for p in parts).encode("utf-8")).hexdigest()


def fingerprint(f: Dict[str, Any]) -> str:
    _, loc = location(f)
    return _h(ALGORITHM, loc, _line(f), vulnerability_type(f), normalize_scanner(f.get("scanner")))


def cross_source_key(f: Dict[str, Any]) -> str:
    _, loc = location(f)
    return _h(ALGORITHM, "xs", f.get("asset") or "", loc, _line(f), vulnerability_type(f))


def possible_key(f: Dict[str, Any]) -> str:
    return _h(ALGORITHM, "pd", f.get("asset") or "", base_location(f), vulnerability_type(f))


def annotate(f: Dict[str, Any]) -> Dict[str, Any]:
    f = dict(f)
    f["fingerprint"] = fingerprint(f)
    f["fingerprint_algorithm"] = ALGORITHM
    f["cross_source_key"] = cross_source_key(f)
    f["possible_dup_key"] = possible_key(f)
    return f


def classify(incoming: Iterable[Dict[str, Any]], existing: Iterable[Dict[str, Any]] = (),
             cross_source: bool = True, possible: bool = True) -> Dict[str, Any]:
    """Classify ``incoming`` against ``existing`` *and* against earlier members of the batch."""
    fp: Dict[str, str] = {}
    xs: Dict[str, Tuple[str, str]] = {}
    pd: Dict[str, str] = {}

    def remember(f: Dict[str, Any]) -> None:
        fp.setdefault(f["fingerprint"], f.get("id") or f["fingerprint"])
        xs.setdefault(f["cross_source_key"], (normalize_scanner(f.get("scanner")), f.get("id") or f["fingerprint"]))
        pd.setdefault(f["possible_dup_key"], f.get("id") or f["fingerprint"])

    for e in existing:
        remember(e if "fingerprint" in e and "cross_source_key" in e else annotate(e))

    out: List[Dict[str, Any]] = []
    counts = {"new": 0, "fingerprint-dup": 0, "cross-source-dup": 0, "possible-dup": 0}
    for raw in incoming:
        f = annotate(raw)
        scanner = normalize_scanner(f.get("scanner"))
        if f["fingerprint"] in fp:
            f["dedup"], f["duplicate_of"] = "fingerprint-dup", fp[f["fingerprint"]]
        elif cross_source and f["cross_source_key"] in xs and xs[f["cross_source_key"]][0] != scanner:
            f["dedup"], f["duplicate_of"] = "cross-source-dup", xs[f["cross_source_key"]][1]
        elif possible and f["possible_dup_key"] in pd:
            f["dedup"], f["duplicate_of"] = "possible-dup", pd[f["possible_dup_key"]]
        else:
            f["dedup"], f["duplicate_of"] = "new", None
        counts[f["dedup"]] += 1
        remember(f)
        out.append(f)
    return {"algorithm": ALGORITHM, "counts": counts, "findings": out,
            "to_upload": [f for f in out if f["dedup"] in ("new", "possible-dup")]}


def _load(path: str) -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if isinstance(data, dict):
        data = data.get("findings") or []
    return data


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="SHA-256 finding fingerprints / de-duplication")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("compute", help="annotate findings with fingerprints")
    c.add_argument("--in", dest="inp", required=True)
    d = sub.add_parser("dedup", help="classify incoming findings against existing ones")
    d.add_argument("--in", dest="inp", required=True)
    d.add_argument("--against", default=None)
    d.add_argument("--no-cross-source", action="store_true")
    d.add_argument("--no-possible", action="store_true")
    a = ap.parse_args()
    if a.cmd == "compute":
        json.dump([annotate(f) for f in _load(a.inp)], sys.stdout, indent=2)
    else:
        existing = _load(a.against) if a.against else []
        json.dump(classify(_load(a.inp), existing, not a.no_cross_source, not a.no_possible), sys.stdout, indent=2)
    print()
