"""Scanner report parsers -> normalised findings (stdlib only).

Default-enabled: OWASP ZAP, Trivy, Trivy SBOM (CycloneDX), Semgrep, Wazuh, Grype SBOM, Manual inputs.
Also supported: Gitleaks, Prowler (OCSF / JSON), Nuclei (JSONL), Tenable (CSV), SARIF 2.1.0.

Normalised finding keys::

    title severity description scanner asset file_path line component component_version purl
    uri vuln_ids cwe rule_id mitigation references cvss_score raw_id
"""
from __future__ import annotations

import csv
import io
import json
import re
from typing import Any, Callable, Dict, List, Optional

from common import normalize_severity, severity_from_cvss
from ids import extract_cwe, extract_ids, normalize_id

Finding = Dict[str, Any]

SCANNERS = {
    "zap": {"label": "OWASP ZAP", "dojo_scan_type": "ZAP Scan", "default": True},
    "trivy": {"label": "Trivy", "dojo_scan_type": "Trivy Scan", "default": True},
    "trivy-sbom": {"label": "Trivy SBOM (CycloneDX)", "dojo_scan_type": "CycloneDX Scan", "default": True},
    "semgrep": {"label": "Semgrep", "dojo_scan_type": "Semgrep JSON Report", "default": True},
    "wazuh": {"label": "Wazuh", "dojo_scan_type": "Wazuh", "default": True},
    "grype-sbom": {"label": "Grype SBOM", "dojo_scan_type": "Anchore Grype", "default": True},
    "manual": {"label": "Manual Inputs", "dojo_scan_type": "Generic Findings Import", "default": True},
    "gitleaks": {"label": "Gitleaks", "dojo_scan_type": "Gitleaks Scan", "default": False},
    "prowler": {"label": "Prowler", "dojo_scan_type": "AWS Prowler V3", "default": False},
    "nuclei": {"label": "Nuclei", "dojo_scan_type": "Nuclei Scan", "default": False},
    "tenable": {"label": "Tenable", "dojo_scan_type": "Tenable Scan", "default": False},
    "sarif": {"label": "SARIF", "dojo_scan_type": "SARIF", "default": False},
}


def _f(**kw: Any) -> Finding:
    base: Finding = {"title": "", "severity": "Info", "description": "", "scanner": "", "asset": "",
                     "file_path": None, "line": None, "component": None, "component_version": None,
                     "purl": None, "uri": None, "vuln_ids": [], "cwe": None, "rule_id": None,
                     "mitigation": "", "references": [], "cvss_score": None, "raw_id": None}
    base.update({k: v for k, v in kw.items() if v is not None})
    ids: List[str] = []
    for v in base.get("vuln_ids") or []:
        n = normalize_id(v)
        if n and not n.startswith("CWE-") and n not in ids:
            ids.append(n)
    base["vuln_ids"] = ids
    base["title"] = str(base["title"] or (ids[0] if ids else "Untitled finding"))[:500]
    return base


def _strip_html(s: Any) -> str:
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", str(s or ""))).strip()


# ── OWASP ZAP (traditional JSON report) ──────────────────────────────────────
_ZAP_RISK = {"3": "High", "2": "Medium", "1": "Low", "0": "Info"}


def parse_zap(data: Any, asset: str = "") -> List[Finding]:
    out: List[Finding] = []
    for site in data.get("site") or []:
        host = site.get("@name") or site.get("@host") or asset
        for al in site.get("alerts") or []:
            sev = _ZAP_RISK.get(str(al.get("riskcode")), normalize_severity(al.get("riskdesc", "").split(" ")[0]))
            cwe = al.get("cweid")
            refs = [r for r in re.split(r"\s+", _strip_html(al.get("reference"))) if r.startswith("http")]
            instances = al.get("instances") or [{}]
            for inst in instances:
                out.append(_f(title=al.get("alert") or al.get("name"), severity=sev, scanner="zap",
                              description=_strip_html(al.get("desc")), asset=asset or host,
                              uri=inst.get("uri") or host, rule_id=str(al.get("pluginid") or ""),
                              cwe=int(cwe) if str(cwe or "").isdigit() and int(cwe) > 0 else None,
                              mitigation=_strip_html(al.get("solution")), references=refs,
                              vuln_ids=extract_ids(al.get("reference")) + extract_ids(al.get("otherinfo"))))
    return out


# ── Trivy JSON ───────────────────────────────────────────────────────────────
def parse_trivy(data: Any, asset: str = "") -> List[Finding]:
    out: List[Finding] = []
    artifact = asset or data.get("ArtifactName") or "trivy-target"
    for res in data.get("Results") or []:
        target = res.get("Target") or ""
        for v in res.get("Vulnerabilities") or []:
            cvss = None
            for src in (v.get("CVSS") or {}).values():
                cvss = src.get("V3Score") or cvss
            out.append(_f(title=v.get("Title") or f"{v.get('VulnerabilityID')} in {v.get('PkgName')}",
                          severity=normalize_severity(v.get("Severity"), "Medium"), scanner="trivy",
                          description=v.get("Description") or "", asset=artifact,
                          component=v.get("PkgName"), component_version=v.get("InstalledVersion"),
                          purl=(v.get("PkgIdentifier") or {}).get("PURL"),
                          file_path=v.get("PkgPath") or None,
                          vuln_ids=[v.get("VulnerabilityID")] + list(v.get("VendorIDs") or []),
                          cwe=extract_cwe(" ".join(v.get("CweIDs") or [])),
                          mitigation=(f"Upgrade {v.get('PkgName')} to {v['FixedVersion']}" if v.get("FixedVersion") else ""),
                          references=v.get("References") or ([v["PrimaryURL"]] if v.get("PrimaryURL") else []),
                          cvss_score=cvss, raw_id=v.get("VulnerabilityID")))
        for m in res.get("Misconfigurations") or []:
            out.append(_f(title=m.get("Title") or m.get("ID"), severity=normalize_severity(m.get("Severity"), "Medium"),
                          scanner="trivy", description=m.get("Description") or m.get("Message") or "",
                          asset=artifact, file_path=target,
                          line=((m.get("CauseMetadata") or {}).get("StartLine")),
                          rule_id=m.get("AVDID") or m.get("ID"), mitigation=m.get("Resolution") or "",
                          references=m.get("References") or []))
        for s in res.get("Secrets") or []:
            out.append(_f(title=f"Secret: {s.get('Title') or s.get('RuleID')}", severity=normalize_severity(s.get("Severity"), "High"),
                          scanner="trivy", asset=artifact, file_path=target, line=s.get("StartLine"),
                          rule_id=s.get("RuleID"), cwe=798, mitigation="Revoke and rotate the secret; move it to AWS Secrets Manager."))
    return out


# ── CycloneDX (Trivy SBOM with vulnerabilities, or any CycloneDX VEX) ────────
def parse_cyclonedx(data: Any, asset: str = "", scanner: str = "trivy-sbom") -> List[Finding]:
    comps: Dict[str, Dict[str, Any]] = {}

    def walk(items: List[Dict[str, Any]]) -> None:
        for c in items or []:
            if c.get("bom-ref"):
                comps[c["bom-ref"]] = c
            walk(c.get("components") or [])

    walk(data.get("components") or [])
    meta = (data.get("metadata") or {}).get("component") or {}
    artifact = asset or meta.get("name") or "sbom"
    out: List[Finding] = []
    for v in data.get("vulnerabilities") or []:
        score, sev = None, None
        for r in v.get("ratings") or []:
            if r.get("score") is not None and (score is None or (r.get("method") or "").startswith("CVSSv3")):
                score = r.get("score")
            sev = sev or r.get("severity")
        ids = [v.get("id")] + [a.get("id") for a in v.get("references") or [] if isinstance(a, dict) and a.get("id")]
        cwes = v.get("cwes") or []
        for aff in v.get("affects") or [{}]:
            c = comps.get(aff.get("ref") or "", {})
            out.append(_f(title=f"{v.get('id')} in {c.get('name') or aff.get('ref') or 'component'}",
                          severity=normalize_severity(sev, severity_from_cvss(score)), scanner=scanner,
                          description=v.get("description") or v.get("detail") or "", asset=artifact,
                          component=c.get("name"), component_version=c.get("version"), purl=c.get("purl"),
                          vuln_ids=ids, cwe=cwes[0] if cwes else None, cvss_score=score,
                          mitigation=v.get("recommendation") or "", raw_id=v.get("id"),
                          references=[a.get("url") for a in v.get("advisories") or [] if a.get("url")]))
    return out


# ── Semgrep JSON ─────────────────────────────────────────────────────────────
def parse_semgrep(data: Any, asset: str = "") -> List[Finding]:
    out: List[Finding] = []
    for r in data.get("results") or []:
        extra = r.get("extra") or {}
        meta = extra.get("metadata") or {}
        cwe_raw = meta.get("cwe")
        cwe = extract_cwe(" ".join(cwe_raw) if isinstance(cwe_raw, list) else cwe_raw)
        refs = meta.get("references") or []
        out.append(_f(title=(extra.get("message") or r.get("check_id") or "")[:200],
                      severity=normalize_severity(extra.get("severity"), "Medium"), scanner="semgrep",
                      description=extra.get("message") or "", asset=asset or "repository",
                      file_path=r.get("path"), line=(r.get("start") or {}).get("line"), rule_id=r.get("check_id"),
                      cwe=cwe, references=refs if isinstance(refs, list) else [refs],
                      vuln_ids=extract_ids(json.dumps(meta)), mitigation=extra.get("fix") or ""))
    return out


# ── Wazuh vulnerability detector (API or indexer export) ─────────────────────
def parse_wazuh(data: Any, asset: str = "") -> List[Finding]:
    items: List[Dict[str, Any]] = []
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        if "data" in data and isinstance(data["data"], dict):
            items = data["data"].get("affected_items") or []
        elif "hits" in data:
            items = [h.get("_source") or {} for h in (data["hits"].get("hits") or [])]
        else:
            items = data.get("vulnerabilities") or data.get("affected_items") or []
    out: List[Finding] = []
    for it in items:
        vuln = it.get("vulnerability") if isinstance(it.get("vulnerability"), dict) else {}
        pkg = it.get("package") if isinstance(it.get("package"), dict) else {}
        agent = it.get("agent") if isinstance(it.get("agent"), dict) else {}
        vid = vuln.get("id") or it.get("cve")
        score = (vuln.get("score") or {}).get("base") if isinstance(vuln.get("score"), dict) else it.get("cvss3_score")
        name = pkg.get("name") or it.get("name")
        version = pkg.get("version") or it.get("version")
        out.append(_f(title=f"{vid} in {name}" if name else str(vid), scanner="wazuh",
                      severity=normalize_severity(vuln.get("severity") or it.get("severity"), severity_from_cvss(score)),
                      description=vuln.get("description") or it.get("title") or "",
                      asset=asset or agent.get("name") or it.get("agent_name") or "wazuh-agent",
                      component=name, component_version=version, vuln_ids=[vid], cvss_score=score,
                      references=[vuln.get("reference")] if vuln.get("reference") else [], raw_id=vid))
    return out


# ── Grype JSON (SBOM scan: `grype sbom:./sbom.cdx.json -o json`) ─────────────
def parse_grype(data: Any, asset: str = "") -> List[Finding]:
    src = (data.get("source") or {}).get("target") or {}
    artifact = asset or (src.get("userInput") if isinstance(src, dict) else str(src)) or "sbom"
    out: List[Finding] = []
    for m in data.get("matches") or []:
        v = m.get("vulnerability") or {}
        a = m.get("artifact") or {}
        score = None
        for c in v.get("cvss") or []:
            score = (c.get("metrics") or {}).get("baseScore") or score
        related = [r.get("id") for r in m.get("relatedVulnerabilities") or [] if r.get("id")]
        fix = v.get("fix") or {}
        loc = (a.get("locations") or [{}])[0].get("path")
        out.append(_f(title=f"{v.get('id')} in {a.get('name')}", severity=normalize_severity(v.get("severity"), "Medium"),
                      scanner="grype-sbom", description=v.get("description") or "", asset=artifact,
                      component=a.get("name"), component_version=a.get("version"), purl=a.get("purl"),
                      file_path=None if a.get("purl") else loc,
                      vuln_ids=[v.get("id")] + related, cvss_score=score, raw_id=v.get("id"),
                      mitigation=("Upgrade to " + ", ".join(fix.get("versions") or [])) if fix.get("versions") else "",
                      references=v.get("urls") or []))
    return out


# ── Gitleaks ─────────────────────────────────────────────────────────────────
def parse_gitleaks(data: Any, asset: str = "") -> List[Finding]:
    return [_f(title=f"Secret: {d.get('Description') or d.get('RuleID')}", severity="High", scanner="gitleaks",
               asset=asset or "repository", file_path=d.get("File"), line=d.get("StartLine"), rule_id=d.get("RuleID"),
               cwe=798, description=f"Commit {str(d.get('Commit') or '')[:12]} by {d.get('Author') or 'unknown'}",
               mitigation="Revoke the credential, rotate it in AWS Secrets Manager and purge it from history.")
            for d in (data if isinstance(data, list) else [])]


# ── Prowler (OCSF JSON array or legacy JSON) ─────────────────────────────────
def parse_prowler(data: Any, asset: str = "") -> List[Finding]:
    out: List[Finding] = []
    for d in data if isinstance(data, list) else []:
        status = str(d.get("status_code") or d.get("Status") or "").upper()
        if status and status not in ("FAIL",):
            continue
        fi = d.get("finding_info") or {}
        res = (d.get("resources") or [{}])[0]
        out.append(_f(title=fi.get("title") or d.get("CheckTitle"), scanner="prowler",
                      severity=normalize_severity(d.get("severity") or d.get("Severity"), "Medium"),
                      description=fi.get("desc") or d.get("Description") or "",
                      asset=asset or (d.get("cloud") or {}).get("account", {}).get("uid") or d.get("AccountId") or "aws",
                      uri=res.get("uid") or d.get("ResourceArn"), rule_id=(d.get("metadata") or {}).get("event_code") or d.get("CheckID"),
                      mitigation=_prowler_fix(d)))
    return out


def _prowler_fix(d: Dict[str, Any]) -> str:
    rem = d.get("remediation")
    if isinstance(rem, dict) and rem.get("desc"):
        return str(rem["desc"])
    legacy = d.get("Remediation")
    if isinstance(legacy, dict):
        return str((legacy.get("Recommendation") or {}).get("Text") or "")
    return ""


# ── Nuclei JSONL ─────────────────────────────────────────────────────────────
def parse_nuclei(text: str, asset: str = "") -> List[Finding]:
    out: List[Finding] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        d = json.loads(line)
        info = d.get("info") or {}
        cls = info.get("classification") or {}
        out.append(_f(title=info.get("name") or d.get("template-id"), scanner="nuclei",
                      severity=normalize_severity(info.get("severity"), "Info"), asset=asset or d.get("host") or "",
                      uri=d.get("matched-at") or d.get("host"), rule_id=d.get("template-id"),
                      vuln_ids=list(cls.get("cve-id") or []) + [d.get("template-id")],
                      cwe=extract_cwe(" ".join(cls.get("cwe-id") or [])), cvss_score=cls.get("cvss-score"),
                      description=info.get("description") or "", references=info.get("reference") or []))
    return out


# ── Tenable / Nessus CSV export ──────────────────────────────────────────────
def parse_tenable(text: str, asset: str = "") -> List[Finding]:
    out: List[Finding] = []
    for row in csv.DictReader(io.StringIO(text)):
        r = {k.strip().lower(): (v or "").strip() for k, v in row.items() if k}
        risk = r.get("risk") or r.get("severity")
        if risk.lower() in ("none", "") and not r.get("cve"):
            continue
        score = float(r["cvss v3.0 base score"]) if r.get("cvss v3.0 base score") else None
        out.append(_f(title=r.get("name") or r.get("plugin name"), scanner="tenable",
                      severity=normalize_severity(risk, severity_from_cvss(score)),
                      asset=asset or r.get("host") or r.get("ip address") or "", rule_id=r.get("plugin id"),
                      uri=f"tcp://{r.get('host')}:{r.get('port')}" if r.get("port") and r.get("port") != "0" else None,
                      vuln_ids=extract_ids(r.get("cve")), cvss_score=score, description=r.get("synopsis") or r.get("description") or "",
                      mitigation=r.get("solution") or ""))
    return out


# ── SARIF 2.1.0 ──────────────────────────────────────────────────────────────
_SARIF_LEVEL = {"error": "High", "warning": "Medium", "note": "Low", "none": "Info"}


def parse_sarif(data: Any, asset: str = "") -> List[Finding]:
    out: List[Finding] = []
    for run in data.get("runs") or []:
        tool = ((run.get("tool") or {}).get("driver") or {})
        rules = {r.get("id"): r for r in tool.get("rules") or []}
        for res in run.get("results") or []:
            rule = rules.get(res.get("ruleId"), {})
            props = rule.get("properties") or {}
            sec = props.get("security-severity")
            sev = severity_from_cvss(float(sec)) if sec else _SARIF_LEVEL.get(res.get("level") or "warning", "Medium")
            loc = ((res.get("locations") or [{}])[0].get("physicalLocation") or {})
            text = (res.get("message") or {}).get("text") or ""
            out.append(_f(title=(rule.get("shortDescription") or {}).get("text") or text[:200] or res.get("ruleId"),
                          severity=sev, scanner="sarif", asset=asset or tool.get("name") or "repository",
                          file_path=(loc.get("artifactLocation") or {}).get("uri"),
                          line=(loc.get("region") or {}).get("startLine"), rule_id=res.get("ruleId"),
                          cwe=extract_cwe(" ".join(props.get("tags") or [])), description=text,
                          vuln_ids=extract_ids(text) + extract_ids(" ".join(props.get("tags") or []))))
    return out


def parse_generic(data: Any, asset: str = "") -> List[Finding]:
    """DefectDojo *Generic Findings Import* JSON (also produced by our manual-input pipeline)."""
    out: List[Finding] = []
    for d in data.get("findings") or []:
        out.append(_f(title=d.get("title"), severity=normalize_severity(d.get("severity"), "Medium"),
                      scanner=d.get("scanner") or "manual", description=d.get("description") or "",
                      asset=asset or d.get("asset") or d.get("service") or "", file_path=d.get("file_path"),
                      line=d.get("line"), component=d.get("component_name"), component_version=d.get("component_version"),
                      vuln_ids=list(d.get("vulnerability_ids") or []) + ([d["cve"]] if d.get("cve") else []),
                      cwe=d.get("cwe"), mitigation=d.get("mitigation") or "", references=[d["references"]] if d.get("references") else [],
                      cvss_score=d.get("cvssv3_score")))
    return out


JSON_PARSERS: Dict[str, Callable[[Any, str], List[Finding]]] = {
    "zap": parse_zap, "trivy": parse_trivy, "trivy-sbom": parse_cyclonedx, "semgrep": parse_semgrep,
    "wazuh": parse_wazuh, "grype-sbom": parse_grype, "gitleaks": parse_gitleaks, "prowler": parse_prowler,
    "sarif": parse_sarif, "manual": parse_generic,
}


def detect_scanner(name: str, text: str) -> Optional[str]:
    """Guess the scanner from file name + content (used for S3 intake and CI imports)."""
    n = name.lower()
    head = text.lstrip()[:4000]
    if n.endswith(".jsonl") or (head.startswith("{") and '"template-id"' in head and "\n{" in text.strip()):
        return "nuclei"
    if n.endswith(".csv") and ("plugin id" in head.lower() and "risk" in head.lower()):
        return "tenable"
    if not head.startswith(("{", "[")):
        return None
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return "nuclei" if '"template-id"' in head else None
    if isinstance(data, list):
        if data and isinstance(data[0], dict):
            k = data[0]
            if "RuleID" in k and ("Secret" in k or "Match" in k):
                return "gitleaks"
            if "finding_info" in k or "CheckID" in k or "status_code" in k:
                return "prowler"
            if "vulnerability" in k and ("agent" in k or "package" in k):
                return "wazuh"
        return None
    if "site" in data and ("@version" in data or "@programName" in data or isinstance(data.get("site"), list)):
        return "zap"
    if "Results" in data and ("ArtifactName" in data or "SchemaVersion" in data):
        return "trivy"
    if data.get("bomFormat") == "CycloneDX":
        return "trivy-sbom"
    if "matches" in data and ("descriptor" in data and (data["descriptor"] or {}).get("name") == "grype" or "source" in data):
        return "grype-sbom"
    if "results" in data and ("errors" in data or "paths" in data or "version" in data) and "runs" not in data:
        return "semgrep"
    if "runs" in data and str(data.get("version", "")).startswith("2."):
        return "sarif"
    if "data" in data and isinstance(data["data"], dict) and "affected_items" in data["data"]:
        return "wazuh"
    if "hits" in data:
        return "wazuh"
    if "findings" in data:
        return "manual"
    return None


def parse_report(name: str, raw: bytes, scanner: Optional[str] = None, asset: str = "") -> Dict[str, Any]:
    text = raw.decode("utf-8-sig", errors="replace")
    scanner = scanner or detect_scanner(name, text)
    if not scanner:
        raise ValueError(f"could not detect scanner for {name}")
    if scanner == "nuclei":
        findings = parse_nuclei(text, asset)
    elif scanner == "tenable":
        findings = parse_tenable(text, asset)
    else:
        findings = JSON_PARSERS[scanner](json.loads(text), asset)
    return {"scanner": scanner, "findings": findings}
