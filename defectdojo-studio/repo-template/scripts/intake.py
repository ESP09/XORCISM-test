"""Finding intake: S3 intake bucket, CI imports, Pages MR submissions and manual documents.

Pipeline for every report::

    parse (scanner / office) -> resolve ids (GHSA/PYSEC/GO/OSV -> CVE | ZDAY) -> SHA-256 fingerprint
      -> batch + cross-scanner de-dup (vs. batch and vs. active DefectDojo findings)
      -> Generic Findings Import (unique_id_from_tool = fingerprint) via reimport-scan (close-on-fix)

CLI::

    intake.py parse --file F [--scanner S] [--asset A]
    intake.py classify --file F --against current.json
    intake.py import-file --file F --product P [--engagement E] [--platform X] [--scanner S]
    intake.py process --s3            # list s3://<intakeBucket>/<intakePrefix>/<product>/<platform>/<file>
    intake.py process --dir DIR       # same layout on a local directory (dev / simulator)
"""
from __future__ import annotations

import os
import re
import shutil
import sys
import tempfile
from typing import Any, Dict, List, Optional

from common import AutomationError, aws_cli, cfg_get, emit, load_config, log, read_json, state_dir, write_json, utc_now
from external_parsers import UnsafeDocument
from feeds import feed_dir
from fingerprint import annotate, classify, normalize_scanner
from ids import Resolver
from scanner_parsers import SCANNERS, parse_report
from submissions import load_submission, to_generic, validate

OFFICE_EXT = (".csv", ".xlsx", ".xlsm", ".xml", ".ods", ".docx")


def enabled_scanners(cfg: Dict[str, Any]) -> List[str]:
    sc = cfg_get(cfg, "scanners", {}) or {}
    key_map = {"zap": "zap", "trivy": "trivy", "trivySbom": "trivy-sbom", "semgrep": "semgrep", "wazuh": "wazuh",
               "grypeSbom": "grype-sbom", "manual": "manual", "gitleaks": "gitleaks", "prowler": "prowler",
               "nuclei": "nuclei", "tenable": "tenable", "sarif": "sarif"}
    if not sc:
        return [k for k, v in SCANNERS.items() if v["default"]]
    return [v for k, v in key_map.items() if sc.get(k)]


def parse_file(path: str, scanner: Optional[str] = None, asset: str = "", resolver: Optional[Resolver] = None,
               raw: Optional[bytes] = None, name: Optional[str] = None) -> Dict[str, Any]:
    resolver = resolver or Resolver.from_feed_dir(feed_dir())
    raw = raw if raw is not None else open(path, "rb").read()
    name = name or os.path.basename(path)
    low = name.lower()
    is_office = low.endswith(OFFICE_EXT) and not (low.endswith(".csv") and scanner == "tenable")
    if is_office and scanner in (None, "manual"):
        # Tenable CSV exports are scanner reports, not engagement sheets.
        head = raw[:2048].decode("utf-8", errors="ignore").lower()
        if low.endswith(".csv") and "plugin id" in head and "risk" in head:
            rep = parse_report(name, raw, "tenable", asset)
            findings, kind, extra = rep["findings"], "tenable", {}
        else:
            sub = load_submission(name, raw)
            v = validate(sub, resolver)
            return {"scanner": "manual", "kind": "office", "valid": v["valid"], "errors": v["errors"], "warnings": v["warnings"],
                    "engagement": v["engagement"], "detected_ids": v["detected_ids"], "source": v.get("source"),
                    "findings": v["findings"]}
    else:
        rep = parse_report(name, raw, scanner, asset)
        findings, kind, extra = rep["findings"], rep["scanner"], {}
    out = []
    detected: List[str] = []
    for f in findings:
        canonical, aliases = resolver.resolve(f.get("vuln_ids") or [])
        f["canonical_id"] = canonical
        f["vuln_ids"] = aliases or f.get("vuln_ids") or []
        if canonical and canonical not in detected:
            detected.append(canonical)
        out.append(annotate(f))
    return {"scanner": kind, "kind": "scanner", "valid": True, "errors": [], "warnings": [], "detected_ids": detected,
            "findings": out, **extra}


def dojo_finding_to_normalized(d: Dict[str, Any]) -> Dict[str, Any]:
    tags = d.get("tags") or []
    scanner = next((t.split(":", 1)[1] for t in tags if t.startswith("scanner:")), "unknown")
    return {"id": d.get("id"), "title": d.get("title"), "scanner": scanner, "asset": d.get("service") or "",
            "file_path": d.get("file_path"), "line": d.get("line"), "component": d.get("component_name"),
            "component_version": d.get("component_version"), "canonical_id": d.get("vuln_id_from_tool"),
            "vuln_ids": [v.get("vulnerability_id") if isinstance(v, dict) else v for v in d.get("vulnerability_ids") or []],
            "cwe": d.get("cwe"), "severity": d.get("severity")}


def import_findings(cfg: Dict[str, Any], findings: List[Dict[str, Any]], product: str, engagement: str, scanner: str,
                    platform: str = "", dojo: Any = None, test_title: Optional[str] = None) -> Dict[str, Any]:
    from dojo_client import Dojo

    dojo = dojo or Dojo.from_config(cfg)
    dojo.ensure_product(product, cfg_get(cfg, "defectdojo.productType", "GovCloud Applications"), platform)
    existing_raw = dojo.findings(product_name=product, active="true")
    scanner_n = normalize_scanner(scanner)
    eng_tag = "engagement:" + re.sub(r"[^a-z0-9]+", "-", engagement.lower()).strip("-")
    # Findings from the same scanner + engagement (same test) are handled by reimport (close-on-fix),
    # so only compare against *other* tests for cross-source / possible duplicates.
    title = test_title or f"{scanner_n} · {engagement}"
    others = [dojo_finding_to_normalized(d) for d in existing_raw
              if not ({f"scanner:{scanner_n}", eng_tag} <= set(d.get("tags") or []))]
    for f in findings:
        f.setdefault("platform", platform)
    res = classify(findings, others, cfg_get(cfg, "dedup.crossSource", True), cfg_get(cfg, "dedup.possibleDup", True))
    upload = res["to_upload"]
    payload = to_generic(upload)
    for g, f in zip(payload["findings"], upload):
        g["tags"] = sorted(set(g["tags"] + [f"scanner:{scanner_n}", eng_tag]))
        if f["dedup"] == "possible-dup":
            g["tags"].append("possible-dup")
    tags = [f"scanner:{scanner_n}", eng_tag] + ([f"platform:{platform}"] if platform else [])
    stats = dojo.reimport_generic(product, engagement, title, payload, tags=tags,
                                  product_type=cfg_get(cfg, "defectdojo.productType", "GovCloud Applications"))
    _record_fingerprints(cfg, res["findings"], product)
    return {"product": product, "engagement": engagement, "test": title, "counts": res["counts"],
            "uploaded": len(upload), "dojo": stats.get("statistics") or stats,
            "duplicates": [{"title": f["title"], "dedup": f["dedup"], "duplicate_of": f["duplicate_of"], "fingerprint": f["fingerprint"]}
                           for f in res["findings"] if f["dedup"] != "new"]}


def _record_fingerprints(cfg: Dict[str, Any], findings: List[Dict[str, Any]], product: str) -> None:
    path = os.path.join(state_dir(cfg), "fingerprints.json")
    db = read_json(path, {}) or {}
    now = utc_now()
    for f in findings:
        rec = db.setdefault(f["fingerprint"], {"first_seen": now, "product": product, "scanner": f.get("scanner"),
                                               "canonical_id": f.get("canonical_id")})
        rec["last_seen"] = now
        rec["dedup"] = f["dedup"]
    write_json(path, db, indent=None)


def import_file(cfg: Dict[str, Any], path: str, product: str, engagement: Optional[str], platform: str = "",
                scanner: Optional[str] = None, asset: str = "", dojo: Any = None) -> Dict[str, Any]:
    parsed = parse_file(path, scanner, asset or product)
    if not parsed["valid"]:
        raise AutomationError(f"{os.path.basename(path)} invalid: " + "; ".join(parsed["errors"][:5]))
    sc = parsed["scanner"]
    if sc not in enabled_scanners(cfg) and not (sc == "manual" and "manual" in enabled_scanners(cfg)):
        raise AutomationError(f"scanner '{sc}' is disabled in config (scanners.*)")
    if parsed.get("engagement"):
        engagement = engagement or parsed["engagement"].get("name")
        platform = platform or parsed["engagement"].get("platform") or ""
        product = parsed["engagement"].get("product") or product
    eng = engagement or ("Manual Inputs" if sc == "manual" else "Continuous Scanning")
    res = import_findings(cfg, parsed["findings"], product, eng, sc, platform, dojo)
    res["file"] = os.path.basename(path)
    res["scanner"] = sc
    res["detected_ids"] = parsed["detected_ids"]
    return res


def process_dir(cfg: Dict[str, Any], root: str, archive: bool = True) -> Dict[str, Any]:
    """Layout: <root>/<product>/<platform>/<report-file>"""
    results, errors = [], []
    for product in sorted(os.listdir(root)):
        pdir = os.path.join(root, product)
        if not os.path.isdir(pdir) or product.startswith((".", "_")) or product in ("processed", "rejected"):
            continue
        for platform in sorted(os.listdir(pdir)):
            pl = os.path.join(pdir, platform)
            if not os.path.isdir(pl):
                continue
            for fn in sorted(os.listdir(pl)):
                fp = os.path.join(pl, fn)
                if not os.path.isfile(fp):
                    continue
                try:
                    results.append(import_file(cfg, fp, product, None, platform))
                    dest = "processed"
                except (AutomationError, UnsafeDocument, ValueError) as e:
                    errors.append({"file": f"{product}/{platform}/{fn}", "error": str(e)})
                    log("intake.rejected", file=fn, error=str(e))
                    dest = "rejected"
                if archive:
                    target = os.path.join(root, dest, product, platform)
                    os.makedirs(target, exist_ok=True)
                    shutil.move(fp, os.path.join(target, fn))
    return {"imported": results, "rejected": errors}


def process_s3(cfg: Dict[str, Any]) -> Dict[str, Any]:
    bucket = cfg_get(cfg, "aws.intakeBucket")
    prefix = cfg_get(cfg, "aws.intakePrefix", "incoming/").rstrip("/") + "/"
    kms = cfg_get(cfg, "aws.kmsKeyArn") or cfg_get(cfg, "aws.kmsKeyAlias")
    listing = aws_cli(["s3api", "list-objects-v2", "--bucket", bucket, "--prefix", prefix], cfg)
    results, errors = [], []
    tmp = tempfile.mkdtemp(prefix="intake-")
    try:
        for obj in listing.get("Contents") or []:
            key = obj["Key"]
            parts = key[len(prefix):].split("/")
            if len(parts) != 3 or not parts[2]:
                errors.append({"key": key, "error": "expected <product>/<platform>/<file>"})
                continue
            product, platform, fn = parts
            local = os.path.join(tmp, fn)
            aws_cli(["s3", "cp", f"s3://{bucket}/{key}", local, "--only-show-errors"], cfg, capture_json=False)
            try:
                results.append(import_file(cfg, local, product, None, platform))
                dest = "processed/"
            except (AutomationError, UnsafeDocument, ValueError) as e:
                errors.append({"key": key, "error": str(e)})
                dest = "rejected/"
            aws_cli(["s3", "mv", f"s3://{bucket}/{key}", f"s3://{bucket}/{dest}{product}/{platform}/{fn}",
                     "--sse", "aws:kms", "--sse-kms-key-id", kms, "--only-show-errors"], cfg, capture_json=False)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return {"imported": results, "rejected": errors}


def main(argv: Optional[List[str]] = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description="DefectDojo intake")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("parse")
    p.add_argument("--file", required=True)
    p.add_argument("--scanner")
    p.add_argument("--asset", default="")
    c = sub.add_parser("classify")
    c.add_argument("--file", required=True)
    c.add_argument("--against", required=True)
    c.add_argument("--scanner")
    c.add_argument("--asset", default="")
    i = sub.add_parser("import-file")
    i.add_argument("--file", required=True)
    i.add_argument("--product", required=True)
    i.add_argument("--engagement")
    i.add_argument("--platform", default="")
    i.add_argument("--scanner")
    pr = sub.add_parser("process")
    g = pr.add_mutually_exclusive_group(required=True)
    g.add_argument("--s3", action="store_true")
    g.add_argument("--dir")
    a = ap.parse_args(argv)
    if a.cmd == "parse":
        emit(parse_file(a.file, a.scanner, a.asset))
        return 0
    if a.cmd == "classify":
        parsed = parse_file(a.file, a.scanner, a.asset)
        current = read_json(a.against, []) or []
        if isinstance(current, dict):
            current = current.get("findings") or []
        res = classify(parsed["findings"], current)
        res.update({"scanner": parsed["scanner"], "valid": parsed["valid"], "errors": parsed["errors"],
                    "warnings": parsed["warnings"], "detected_ids": parsed["detected_ids"], "engagement": parsed.get("engagement")})
        res.pop("to_upload", None)
        emit(res)
        return 0
    cfg = load_config()
    if a.cmd == "import-file":
        emit(import_file(cfg, a.file, a.product, a.engagement, a.platform, a.scanner))
        return 0
    out = process_s3(cfg) if a.s3 else process_dir(cfg, a.dir)
    emit(out)
    return 1 if out["rejected"] and not out["imported"] else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (AutomationError, UnsafeDocument, ValueError) as e:
        print(f'{{"error": {str(e)!r}}}'.replace("'", '"'), file=sys.stderr)
        sys.exit(2)
