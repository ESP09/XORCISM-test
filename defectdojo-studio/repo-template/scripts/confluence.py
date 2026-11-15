"""Confluence tracking page: renders the GitLab Pages metrics as Confluence *storage format* with
sensitive finding details omitted, and publishes it (Confluence Data Center PAT or Cloud token).

Redaction policy (``confluence.redaction``):
  ``strict`` (default)  counts only - per software / engagement / platform posture, SLA, KEV totals,
                        Jira ticket counts. No CVE ids per application, titles, components,
                        versions, file paths, URLs, hosts, descriptions or evidence.
  ``standard``          additionally lists canonical vulnerability ids with ticket keys
                        (no per-application mapping, no locations).
A leak check verifies that none of the detailed-record titles, paths or ids (strict) appear in the
rendered output before anything is published.

    confluence.py render  --metrics public/data/metrics.json [--out page.xhtml]
    confluence.py publish --metrics public/data/metrics.json
"""
from __future__ import annotations

import base64
import json
import sys
import urllib.parse
from typing import Any, Dict, List, Optional
from xml.sax.saxutils import escape

from common import AutomationError, SEVERITIES, cfg_get, emit, http_json, load_config, read_json, secret_env, utc_now

_COLOURS = {"Critical": "Red", "High": "Red", "Medium": "Yellow", "Low": "Blue", "Info": "Grey"}


def _status(title: str, colour: str) -> str:
    return (f'<ac:structured-macro ac:name="status"><ac:parameter ac:name="colour">{colour}</ac:parameter>'
            f'<ac:parameter ac:name="title">{escape(title)}</ac:parameter></ac:structured-macro>')


def _trend(ent: Dict[str, Any]) -> str:
    d = ent.get("delta") or 0
    if d < -2:
        return _status("Improving", "Green")
    if d > 2:
        return _status("Worsening", "Red")
    return _status("Stable", "Grey")


def _table(headers: List[str], rows: List[List[str]]) -> str:
    h = "".join(f"<th>{escape(x)}</th>" for x in headers)
    body = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>" for r in rows)
    return f"<table><tbody><tr>{h}</tr>{body}</tbody></table>"


def render(metrics: Dict[str, Any], cfg: Dict[str, Any]) -> str:
    redaction = cfg_get(cfg, "confluence.redaction", "strict")
    agg = metrics.get("aggregate") or {}
    cur = agg.get("current") or {}
    pages_url = cfg_get(cfg, "gitlab.pagesUrl", "")
    parts = [
        '<ac:structured-macro ac:name="info"><ac:rich-text-body><p>'
        f'Automatically published from the GitLab Pages vulnerability dashboard on {escape(metrics.get("generated") or utc_now())}. '
        'Sensitive finding details (titles, components, versions, file paths, URLs, hosts, evidence'
        + (', and per-application vulnerability ids' if redaction == "strict" else '') +
        ') are intentionally omitted. Authorised users can view details in DefectDojo or the Pages dashboard.'
        '</p></ac:rich-text-body></ac:structured-macro>',
        f"<h2>Enterprise posture</h2>",
        _table(["Open", *SEVERITIES[:4], "CISA KEV", "Past SLA", "Software tracked"],
               [[str(agg.get("open", 0)), *[_status(str(cur.get(s, 0)), _COLOURS[s]) for s in SEVERITIES[:4]],
                 str(cur.get("kev", 0)), str(cur.get("overdue", 0)), str(agg.get("softwareCount", 0))]]),
        "<h2>Posture by software</h2>",
        _table(["Software", "Platform", "Critical", "High", "Medium", "Low", "KEV", "Past SLA", "Risk score", "Trend"],
               [[escape(e["name"]), escape(e.get("platform") or "-"), *[str(e["current"].get(s, 0)) for s in SEVERITIES[:4]],
                 str(e["current"].get("kev", 0)), str(e["current"].get("overdue", 0)), str(e["current"].get("score", 0)), _trend(e)]
                for e in (metrics.get("dimensions") or {}).get("software", [])]),
        "<h2>Posture by engagement</h2>",
        _table(["Engagement", "Critical", "High", "Medium", "Low", "Closed"],
               [[escape(e["name"]), *[str(e["current"].get(s, 0)) for s in SEVERITIES[:4]], str(e["current"].get("closed", 0))]
                for e in (metrics.get("dimensions") or {}).get("engagement", [])]),
        "<h2>Posture by platform</h2>",
        _table(["Platform", "Critical", "High", "Medium", "Low", "KEV", "Trend"],
               [[escape(e["name"]), *[str(e["current"].get(s, 0)) for s in SEVERITIES[:4]], str(e["current"].get("kev", 0)), _trend(e)]
                for e in (metrics.get("dimensions") or {}).get("platform", [])]),
    ]
    det = metrics.get("detailed") or []
    jira_keys = sorted({d["jira"] for d in det if d.get("jira")})
    parts.append(f"<h2>Remediation tracking</h2><p>{len(jira_keys)} Jira ticket(s) track open vulnerabilities "
                 "(one ticket per canonical vulnerability id across all assets).</p>")
    if redaction == "standard":
        ids = sorted({(d["id"], d.get("jira") or "-") for d in det if d.get("id") and d["status"] == "Active"})
        parts.append(_table(["Vulnerability id", "Jira"], [[escape(i), escape(k)] for i, k in ids]))
    if pages_url:
        parts.append(f'<p>Dashboard: <a href="{escape(pages_url)}">{escape(pages_url)}</a></p>')
    html = "".join(parts)
    leak_check(html, metrics, redaction)
    return html


def leak_check(html: str, metrics: Dict[str, Any], redaction: str) -> None:
    for d in metrics.get("detailed") or []:
        probes = [d.get("title")]
        if redaction == "strict":
            probes.append(d.get("id"))
        for p in probes:
            if p and len(str(p)) > 6 and escape(str(p)) in html:
                raise AutomationError(f"redaction check failed: sensitive value present in Confluence output ({str(p)[:20]}…)")


def _headers(cfg: Dict[str, Any]) -> Dict[str, str]:
    if cfg_get(cfg, "confluence.mode", "datacenter") == "cloud":
        tok = base64.b64encode(f"{cfg_get(cfg, 'confluence.cloudEmail')}:{secret_env('CONFLUENCE_API_TOKEN')}".encode()).decode()
        return {"Authorization": f"Basic {tok}"}
    return {"Authorization": f"Bearer {secret_env('CONFLUENCE_PAT')}"}


def publish(cfg: Dict[str, Any], html: str) -> Dict[str, Any]:
    if not cfg_get(cfg, "confluence.enabled", False):
        return {"published": False, "reason": "confluence.enabled is false"}
    base = cfg_get(cfg, "confluence.url", "").rstrip("/")
    space = cfg_get(cfg, "confluence.spaceKey")
    title = cfg_get(cfg, "confluence.pageTitle", "Vulnerability Posture Tracking")
    h = _headers(cfg)
    q = urllib.parse.urlencode({"spaceKey": space, "title": title, "expand": "version"})
    found = http_json("GET", f"{base}/rest/api/content?{q}", headers=h).get("results") or []
    body = {"type": "page", "title": title, "space": {"key": space}, "body": {"storage": {"value": html, "representation": "storage"}}}
    if found:
        page = found[0]
        body["version"] = {"number": int((page.get("version") or {}).get("number") or 1) + 1, "message": "Automated update"}
        res = http_json("PUT", f"{base}/rest/api/content/{page['id']}", body, headers=h)
        action = "updated"
    else:
        if cfg_get(cfg, "confluence.parentPageId"):
            body["ancestors"] = [{"id": str(cfg_get(cfg, "confluence.parentPageId"))}]
        res = http_json("POST", f"{base}/rest/api/content", body, headers=h)
        action = "created"
    return {"published": True, "action": action, "id": res.get("id"), "version": (res.get("version") or {}).get("number"),
            "url": base + ((res.get("_links") or {}).get("webui") or "")}


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="Confluence tracking page")
    ap.add_argument("cmd", choices=["render", "publish"])
    ap.add_argument("--metrics", default="public/data/metrics.json")
    ap.add_argument("--out")
    a = ap.parse_args()
    cfg = load_config()
    try:
        metrics = read_json(a.metrics)
        if not metrics:
            raise AutomationError(f"metrics file {a.metrics} not found - run metrics.py build first")
        html = render(metrics, cfg)
        if a.cmd == "render":
            if a.out:
                open(a.out, "w", encoding="utf-8").write(html)
            emit({"bytes": len(html), "redaction": cfg_get(cfg, "confluence.redaction", "strict"), "html": html if not a.out else None})
        else:
            emit(publish(cfg, html))
    except AutomationError as e:
        sys.stderr.write(json.dumps({"error": str(e)}) + "\n")
        sys.exit(2)
