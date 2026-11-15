"""Engagement / manual finding submissions (JSON MR submissions + office documents).

Submission JSON (``submissions/<product>/<yyyy-mm-dd>-<slug>.json``)::

    {"schema": "dojo-submission/v1",
     "engagement": {"name": "...", "product": "...", "platform": "EKS", "lead": "...",
                    "start": "YYYY-MM-DD", "end": "YYYY-MM-DD", "type": "Penetration Test"},
     "findings": [{"title": "...", "severity": "High", "cve": "CVE-…|GHSA-…|ZDAY-…", ...}]}

CLI::

    submissions.py validate FILE...            # any of .json .csv .xlsx .xml .ods .docx
    submissions.py validate-diff --base SHA    # CI: validate files changed under submissions/
    submissions.py convert FILE --out sub.json # office document -> submission JSON
    submissions.py to-generic FILE --out g.json  # -> DefectDojo Generic Findings Import
    submissions.py open-mr FILE                # create branch + commit + MR in GitLab (API)
"""
from __future__ import annotations

import base64
import fnmatch
import json
import os
import re
import subprocess
import sys
import urllib.parse
from typing import Any, Dict, List, Optional

from common import AutomationError, cfg_get, emit, http_json, load_config, normalize_severity, secret_env, SEVERITIES, utc_now
from external_parsers import UnsafeDocument, extract_records
from fingerprint import annotate
from ids import Resolver, extract_ids, normalize_id

SCHEMA = "dojo-submission/v1"
SUBMISSION_GLOBS = ["submissions/**/*.json", "submissions/**/*.csv", "submissions/**/*.xlsx", "submissions/**/*.xml",
                    "submissions/**/*.ods", "submissions/**/*.docx"]
_SECRET_PATTERNS = [
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS access key id"),
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "private key"),
    (re.compile(r"\bglpat-[0-9A-Za-z_\-]{20,}\b"), "GitLab personal access token"),
    (re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b"), "GitHub token"),
    (re.compile(r"(?i)\bpassword\s*[:=]\s*\S{6,}"), "inline password"),
]
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
MAX_FINDINGS = 5000


def records_to_submission(records: List[Dict[str, str]], meta: Dict[str, str], default_name: str) -> Dict[str, Any]:
    findings = []
    for r in records:
        f = {k: v for k, v in r.items() if not k.startswith("_") and not k.startswith("x_")}
        findings.append(f)
    eng = {
        "name": meta.get("engagement") or default_name,
        "product": meta.get("product") or meta.get("application") or meta.get("software") or (findings[0].get("asset") if findings else ""),
        "platform": meta.get("platform") or (findings[0].get("platform") if findings else ""),
        "lead": meta.get("lead") or meta.get("tester") or "",
        "start": meta.get("start") or "",
        "end": meta.get("end") or "",
        "type": meta.get("assessment") or "Manual Assessment",
    }
    return {"schema": SCHEMA, "engagement": eng, "findings": findings}


def load_submission(path: str, raw: Optional[bytes] = None) -> Dict[str, Any]:
    raw = raw if raw is not None else open(path, "rb").read()
    name = os.path.basename(path)
    if name.lower().endswith(".json"):
        data = json.loads(raw.decode("utf-8-sig"))
        if not isinstance(data, dict):
            raise ValueError("submission JSON must be an object")
        return data
    ext = extract_records(name, raw)
    sub = records_to_submission(ext["records"], ext["metadata"], os.path.splitext(name)[0])
    sub["_source"] = {"format": ext["format"], "sheets_used": ext["sheets_used"], "sheets_skipped": ext["sheets_skipped"]}
    return sub


def validate(sub: Dict[str, Any], resolver: Optional[Resolver] = None) -> Dict[str, Any]:
    resolver = resolver or Resolver()
    errors: List[str] = []
    warnings: List[str] = []
    if sub.get("schema") not in (None, SCHEMA):
        errors.append(f"schema must be {SCHEMA}")
    eng = sub.get("engagement") or {}
    if not str(eng.get("name") or "").strip():
        errors.append("engagement.name is required")
    if not str(eng.get("product") or "").strip():
        errors.append("engagement.product is required")
    for k in ("start", "end"):
        if eng.get(k) and not _DATE.match(str(eng[k])):
            errors.append(f"engagement.{k} must be YYYY-MM-DD")
    if eng.get("start") and eng.get("end") and str(eng["end"]) < str(eng["start"]):
        errors.append("engagement.end is before engagement.start")
    findings = sub.get("findings")
    if not isinstance(findings, list) or not findings:
        errors.append("findings must be a non-empty list")
        findings = []
    if len(findings) > MAX_FINDINGS:
        errors.append(f"too many findings ({len(findings)} > {MAX_FINDINGS})")
    normalized: List[Dict[str, Any]] = []
    detected: List[str] = []
    for i, f in enumerate(findings[:MAX_FINDINGS], start=1):
        where = f"findings[{i}]"
        if not isinstance(f, dict):
            errors.append(f"{where} must be an object")
            continue
        title = str(f.get("title") or "").strip()
        if not title:
            errors.append(f"{where}.title is required")
        if len(title) > 500:
            errors.append(f"{where}.title exceeds 500 characters")
        sev_raw = f.get("severity")
        sev = normalize_severity(sev_raw, "")
        if not sev:
            errors.append(f"{where}.severity '{sev_raw}' is not one of {', '.join(SEVERITIES)}")
        raw_ids = [x.strip() for x in re.split(r"[,;\s]+", str(f.get("cve") or "")) if x.strip()]
        ids: List[str] = []
        for x in raw_ids:
            n = normalize_id(x)
            if not n or n.startswith("CWE-"):
                errors.append(f"{where}.cve '{x}' is not a recognised CVE/GHSA/PYSEC/GO/OSV/ZDAY id")
            else:
                ids.append(n)
        mentioned = [x for x in extract_ids(" ".join(str(f.get(k) or "") for k in ("title", "description", "references"))) if x not in ids]
        if mentioned:
            warnings.append(f"{where}: detected {', '.join(mentioned)} in text; added as vulnerability ids")
            ids.extend(mentioned)
        canonical, aliases = resolver.resolve(ids)
        if canonical and canonical not in detected:
            detected.append(canonical)
        if f.get("line") not in (None, "") and not str(f.get("line")).isdigit():
            errors.append(f"{where}.line must be a positive integer")
        if f.get("cvss_score") not in (None, ""):
            try:
                sc = float(f["cvss_score"])
                if not 0 <= sc <= 10:
                    raise ValueError
            except ValueError:
                errors.append(f"{where}.cvss_score must be between 0 and 10")
        blob = " ".join(str(v) for v in f.values())
        for rx, label in _SECRET_PATTERNS:
            if rx.search(blob):
                errors.append(f"{where}: contains what looks like a {label}; remove it before submitting")
        cwe = f.get("cwe")
        cwe_n = None
        if cwe:
            m = re.search(r"(\d+)", str(cwe))
            cwe_n = int(m.group(1)) if m else None
        nf = {
            "title": title, "severity": sev or "Info", "description": str(f.get("description") or ""),
            "scanner": "manual", "asset": str(f.get("asset") or eng.get("product") or ""),
            "platform": str(f.get("platform") or eng.get("platform") or ""),
            "file_path": f.get("file_path") or None, "line": int(f["line"]) if str(f.get("line") or "").isdigit() else None,
            "component": f.get("component") or None, "component_version": f.get("component_version") or None,
            "uri": f.get("uri") or None, "cwe": cwe_n, "mitigation": str(f.get("mitigation") or ""),
            "references": [r for r in re.split(r"\s+", str(f.get("references") or "")) if r],
            "cvss_score": float(f["cvss_score"]) if str(f.get("cvss_score") or "").replace(".", "", 1).isdigit() else None,
            "vuln_ids": aliases or ids, "canonical_id": canonical, "engagement": eng.get("name"),
        }
        normalized.append(annotate(nf))
    return {"valid": not errors, "errors": errors, "warnings": warnings, "detected_ids": detected,
            "engagement": eng, "findings": normalized, "count": len(normalized), "source": sub.get("_source")}


def to_generic(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """DefectDojo Generic Findings Import payload; unique_id_from_tool = our SHA-256 fingerprint."""
    out = []
    for f in findings:
        ids = [i for i in (f.get("vuln_ids") or []) if i]
        desc = f.get("description") or f.get("title")
        out.append({
            "title": f["title"][:500], "severity": f["severity"], "description": desc,
            "mitigation": f.get("mitigation") or "", "references": "\n".join(f.get("references") or []),
            "active": True, "verified": False, "static_finding": bool(f.get("file_path")), "dynamic_finding": bool(f.get("uri")),
            "file_path": f.get("file_path"), "line": f.get("line"), "component_name": f.get("component"),
            "component_version": f.get("component_version"), "cwe": f.get("cwe"),
            "vulnerability_ids": ids, "unique_id_from_tool": f.get("fingerprint") or annotate(f)["fingerprint"],
            "vuln_id_from_tool": f.get("canonical_id") or (ids[0] if ids else None),
            "cvssv3_score": f.get("cvss_score"), "service": f.get("asset"),
            "tags": [t for t in ("scanner:" + str(f.get("scanner") or "manual"),
                                 ("platform:" + f["platform"]) if f.get("platform") else None) if t],
        })
    return {"findings": out}


def changed_submission_files(base: str, head: str = "HEAD") -> List[str]:
    proc = subprocess.run(["git", "diff", "--name-only", "--diff-filter=AMR", f"{base}...{head}"],
                          capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise AutomationError(f"git diff failed: {proc.stderr.strip()}")
    files = [l.strip() for l in proc.stdout.splitlines() if l.strip()]
    return [f for f in files if any(fnmatch.fnmatch(f, g) or fnmatch.fnmatch(f, g.replace("**/", "")) for g in SUBMISSION_GLOBS)]


def open_mr(path: str, cfg: Dict[str, Any]) -> Dict[str, Any]:
    gitlab = cfg_get(cfg, "gitlab.apiUrl") or (cfg_get(cfg, "gitlab.url", "").rstrip("/") + "/api/v4")
    project = urllib.parse.quote(cfg_get(cfg, "gitlab.submissionsProject") or cfg_get(cfg, "gitlab.projectPath"), safe="")
    token = secret_env("GITLAB_TOKEN")
    sub = load_submission(path)
    res = validate(sub)
    if not res["valid"]:
        raise AutomationError("submission invalid: " + "; ".join(res["errors"][:5]))
    eng = res["engagement"]
    slug = re.sub(r"[^a-z0-9]+", "-", (eng.get("name") or "engagement").lower()).strip("-")[:50]
    product = re.sub(r"[^a-z0-9]+", "-", (eng.get("product") or "product").lower()).strip("-")
    branch = f"submission/{product}/{slug}-{utc_now()[:10]}"
    file_path = f"submissions/{product}/{os.path.basename(path)}"
    with open(path, "rb") as fh:
        content = base64.b64encode(fh.read()).decode()
    hdr = {"PRIVATE-TOKEN": token}
    default_branch = cfg_get(cfg, "gitlab.defaultBranch", "main")
    http_json("POST", f"{gitlab}/projects/{project}/repository/commits", {
        "branch": branch, "start_branch": default_branch, "commit_message": f"Submission: {eng.get('name')} ({eng.get('product')})",
        "actions": [{"action": "create", "file_path": file_path, "content": content, "encoding": "base64"}],
    }, headers=hdr)
    mr = http_json("POST", f"{gitlab}/projects/{project}/merge_requests", {
        "source_branch": branch, "target_branch": default_branch, "remove_source_branch": True,
        "title": f"Engagement submission: {eng.get('name')} — {eng.get('product')}",
        "description": f"{res['count']} finding(s); detected ids: {', '.join(res['detected_ids']) or 'none'}.\n\n"
                       "Validated by `submissions.py validate`; the MR pipeline re-validates the diff.",
        "labels": "submission,defectdojo",
    }, headers=hdr)
    return {"branch": branch, "file": file_path, "merge_request": {"iid": mr.get("iid"), "web_url": mr.get("web_url")}, "validation": res}


def _resolver() -> Resolver:
    return Resolver.from_feed_dir(os.environ.get("DOJO_FEED_DIR"))


def main(argv: Optional[List[str]] = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("validate")
    v.add_argument("files", nargs="+")
    vd = sub.add_parser("validate-diff")
    vd.add_argument("--base", default=os.environ.get("CI_MERGE_REQUEST_DIFF_BASE_SHA", "origin/main"))
    c = sub.add_parser("convert")
    c.add_argument("file")
    c.add_argument("--out", default="-")
    g = sub.add_parser("to-generic")
    g.add_argument("file")
    g.add_argument("--out", default="-")
    m = sub.add_parser("open-mr")
    m.add_argument("file")
    a = ap.parse_args(argv)
    res = _resolver()
    if a.cmd in ("validate", "validate-diff"):
        files = a.files if a.cmd == "validate" else changed_submission_files(a.base)
        results = []
        ok = True
        for fpath in files:
            try:
                r = validate(load_submission(fpath), res)
            except (UnsafeDocument, ValueError, json.JSONDecodeError) as e:
                r = {"valid": False, "errors": [str(e)], "warnings": [], "detected_ids": [], "count": 0}
            r.pop("findings", None)
            r["file"] = fpath
            ok = ok and r["valid"]
            results.append(r)
        emit({"valid": ok, "files": results, "checked": len(files)})
        return 0 if ok else 1
    if a.cmd == "convert":
        out = load_submission(a.file)
        out.pop("_source", None)
    elif a.cmd == "to-generic":
        r = validate(load_submission(a.file), res)
        if not r["valid"]:
            emit(r)
            return 1
        out = to_generic(r["findings"])
    else:
        out = open_mr(a.file, load_config())
    if getattr(a, "out", "-") in ("-", None):
        emit(out)
    else:
        with open(a.out, "w", encoding="utf-8") as fh:
            json.dump(out, fh, indent=2)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AutomationError as e:
        print(json.dumps({"error": str(e)}), file=sys.stderr)
        sys.exit(2)
