"""Jira synchronisation: exactly ONE ticket per canonical vulnerability id across all assets.

* Groups every DefectDojo finding (active and mitigated) by canonical id (CVE > ZDAY > GHSA ...).
* Creates a ticket when a group has an active finding at/above ``jira.minSeverity``.
* Updates the affected-asset table when the set of affected products/components changes.
* Closes the ticket (``jira.closeTransition``) when every finding in the group is mitigated.
* Reopens the same ticket (``jira.reopenTransition``) on recurrence - never a duplicate.

Modes (``jira.mode``):
  ``datacenter`` - Jira Data Center / Server, PAT bearer auth, ``/rest/api/2/search`` (startAt paging)
  ``cloud``      - Jira Cloud, email + API token, ``/rest/api/3/search/jql`` (nextPageToken paging)
  ``disabled``   - no-op
Tickets are found by label ``<labelPrefix><id>`` (lower-case), plus the ``dojo-managed`` label.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
import urllib.parse
from typing import Any, Dict, Iterator, List, Optional, Tuple

from common import AutomationError, SEVERITIES, cfg_get, emit, http_json, load_config, log, read_json, secret_env, state_dir, utc_now, write_json
from dojo_client import Dojo, product_of
from enrich import finding_ids
from ids import Resolver

MANAGED_LABEL = "dojo-managed"
_PRIORITY = {"Critical": "Highest", "High": "High", "Medium": "Medium", "Low": "Low", "Info": "Lowest"}


class Jira:
    def __init__(self, cfg: Dict[str, Any]):
        self.mode = cfg_get(cfg, "jira.mode", "datacenter")
        self.base = cfg_get(cfg, "jira.url", "").rstrip("/")
        if self.mode == "cloud":
            email = cfg_get(cfg, "jira.cloudEmail") or secret_env("JIRA_EMAIL")
            tok = base64.b64encode(f"{email}:{secret_env('JIRA_API_TOKEN')}".encode()).decode()
            self.headers = {"Authorization": f"Basic {tok}"}
        else:
            self.headers = {"Authorization": f"Bearer {secret_env('JIRA_PAT')}"}

    def search(self, jql: str, fields: List[str]) -> Iterator[Dict[str, Any]]:
        if self.mode == "cloud":
            token: Optional[str] = None
            while True:
                body: Dict[str, Any] = {"jql": jql, "maxResults": 100, "fields": fields}
                if token:
                    body["nextPageToken"] = token
                page = http_json("POST", f"{self.base}/rest/api/3/search/jql", body, headers=self.headers)
                for i in page.get("issues") or []:
                    yield i
                token = page.get("nextPageToken")
                if not token or page.get("isLast"):
                    return
        start = 0
        while True:
            q = urllib.parse.urlencode({"jql": jql, "startAt": start, "maxResults": 100, "fields": ",".join(fields)})
            page = http_json("GET", f"{self.base}/rest/api/2/search?{q}", headers=self.headers)
            issues = page.get("issues") or []
            for i in issues:
                yield i
            start += len(issues)
            if not issues or start >= int(page.get("total") or 0):
                return

    def create(self, fields: Dict[str, Any]) -> Dict[str, Any]:
        return http_json("POST", f"{self.base}/rest/api/2/issue", {"fields": fields}, headers=self.headers)

    def update(self, key: str, fields: Dict[str, Any]) -> None:
        http_json("PUT", f"{self.base}/rest/api/2/issue/{key}", {"fields": fields}, headers=self.headers)

    def comment(self, key: str, body: str) -> None:
        http_json("POST", f"{self.base}/rest/api/2/issue/{key}/comment", {"body": body}, headers=self.headers)

    def transition(self, key: str, name: str) -> bool:
        tr = http_json("GET", f"{self.base}/rest/api/2/issue/{key}/transitions", headers=self.headers)
        for t in tr.get("transitions") or []:
            if t.get("name", "").lower() == name.lower() or (t.get("to") or {}).get("name", "").lower() == name.lower():
                http_json("POST", f"{self.base}/rest/api/2/issue/{key}/transitions", {"transition": {"id": t["id"]}}, headers=self.headers)
                return True
        log("jira.transition_missing", key=key, wanted=name)
        return False


def group_findings(findings: List[Dict[str, Any]], resolver: Resolver) -> Tuple[Dict[str, List[Dict[str, Any]]], int]:
    groups: Dict[str, List[Dict[str, Any]]] = {}
    unidentified = 0
    for d in findings:
        canonical, _ = resolver.resolve(finding_ids(d))
        if not canonical:
            unidentified += 1
            continue
        groups.setdefault(canonical, []).append(d)
    return groups, unidentified


def _max_sev(fs: List[Dict[str, Any]]) -> str:
    return min((d.get("severity") or "Info" for d in fs), key=lambda s: SEVERITIES.index(s) if s in SEVERITIES else 9)


def _affected(fs: List[Dict[str, Any]]) -> List[Tuple[str, str, int]]:
    agg: Dict[Tuple[str, str], int] = {}
    for d in fs:
        key = (product_of(d),
               f"{d.get('component_name') or '-'} {d.get('component_version') or ''}".strip())
        agg[key] = agg.get(key, 0) + 1
    return sorted([(p, c, n) for (p, c), n in agg.items()])


def description(vid: str, active: List[Dict[str, Any]], cfg: Dict[str, Any]) -> str:
    f0 = active[0]
    rows = "\n".join(f"| {p} | {c} | {n} |" for p, c, n in _affected(active))
    kev = next((d for d in active if d.get("known_exploited")), None)
    dojo = cfg_get(cfg, "defectdojo.url", "").rstrip("/")
    return (f"h2. {vid}\n\n*Severity:* {_max_sev(active)}   *CVSS v3:* {f0.get('cvssv3_score') or 'n/a'}   "
            f"*EPSS:* {f0.get('epss_score') if f0.get('epss_score') is not None else 'n/a'}   "
            f"*CISA KEV:* {'YES (added ' + str(kev.get('kev_date')) + ')' if kev else 'no'}\n\n"
            f"This ticket tracks *every* affected asset for {vid}; it is closed automatically when all findings are "
            f"mitigated and reopened on recurrence. Do not create duplicates.\n\n"
            f"h3. Affected assets ({len(active)} active finding(s))\n||Product||Component||Findings||\n{rows}\n\n"
            f"[DefectDojo findings|{dojo}/finding?vulnerability_id={vid}]\n")


def sync(cfg: Dict[str, Any], dojo: Optional[Dojo] = None, jira: Optional[Jira] = None, resolver: Optional[Resolver] = None) -> Dict[str, Any]:
    if cfg_get(cfg, "jira.mode", "datacenter") == "disabled":
        return {"mode": "disabled"}
    dojo = dojo or Dojo.from_config(cfg)
    jira = jira or Jira(cfg)
    if resolver is None:
        from feeds import feed_dir
        resolver = Resolver.from_feed_dir(feed_dir(cfg))
    project = cfg_get(cfg, "jira.projectKey", "VULN")
    prefix = cfg_get(cfg, "jira.labelPrefix", "vuln-")
    min_sev = cfg_get(cfg, "jira.minSeverity", "High")
    findings = dojo.findings()
    groups, unidentified = group_findings(findings, resolver)
    existing: Dict[str, Dict[str, Any]] = {}
    for issue in jira.search(f'project = "{project}" AND labels = "{MANAGED_LABEL}"', ["status", "labels", "summary"]):
        for lb in (issue.get("fields") or {}).get("labels") or []:
            if lb.startswith(prefix):
                existing[lb] = issue
    state_path = os.path.join(state_dir(cfg), "jira.json")
    state = read_json(state_path, {}) or {}
    actions = {"created": [], "updated": [], "closed": [], "reopened": [], "unchanged": 0}
    for vid, fs in sorted(groups.items()):
        active = [d for d in fs if d.get("active") and not d.get("is_mitigated") and not d.get("false_p") and not d.get("risk_accepted")]
        label = prefix + vid.lower()
        issue = existing.get(label)
        status_cat = (((issue or {}).get("fields") or {}).get("status") or {}).get("statusCategory", {}).get("key")
        is_done = status_cat == "done"
        if active and SEVERITIES.index(_max_sev(active)) > SEVERITIES.index(min_sev) and not issue:
            continue
        assets_hash = hashlib.sha256(json.dumps(_affected(active)).encode()).hexdigest()[:16]
        if active and not issue:
            sev = _max_sev(active)
            created = jira.create({
                "project": {"key": project}, "issuetype": {"name": cfg_get(cfg, "jira.issueType", "Bug")},
                "summary": f"[{vid}] {active[0].get('title', '')[:180]} ({len({p for p, _, _ in _affected(active)})} product(s))",
                "description": description(vid, active, cfg), "labels": [MANAGED_LABEL, label, f"severity-{sev.lower()}"],
                "priority": {"name": _PRIORITY.get(sev, "Medium")},
            })
            key = created.get("key")
            state[vid] = {"key": key, "assetsHash": assets_hash, "status": "open", "updated": utc_now()}
            actions["created"].append({"id": vid, "key": key, "findings": len(active)})
        elif active and issue and is_done:
            key = issue["key"]
            jira.transition(key, cfg_get(cfg, "jira.reopenTransition", "Reopen"))
            jira.comment(key, f"Recurrence detected on {utc_now()}: {len(active)} active finding(s) for {vid}. Ticket reopened by automation.")
            jira.update(key, {"description": description(vid, active, cfg)})
            state[vid] = {"key": key, "assetsHash": assets_hash, "status": "open", "updated": utc_now()}
            actions["reopened"].append({"id": vid, "key": key, "findings": len(active)})
        elif active and issue:
            key = issue["key"]
            if (state.get(vid) or {}).get("assetsHash") != assets_hash:
                jira.update(key, {"description": description(vid, active, cfg)})
                state[vid] = {"key": key, "assetsHash": assets_hash, "status": "open", "updated": utc_now()}
                actions["updated"].append({"id": vid, "key": key, "findings": len(active)})
            else:
                actions["unchanged"] += 1
        elif not active and issue and not is_done:
            key = issue["key"]
            jira.comment(key, f"All {len(fs)} finding(s) for {vid} are mitigated in DefectDojo as of {utc_now()}. Closed by automation.")
            jira.transition(key, cfg_get(cfg, "jira.closeTransition", "Done"))
            state[vid] = {"key": key, "assetsHash": assets_hash, "status": "closed", "updated": utc_now()}
            actions["closed"].append({"id": vid, "key": key})
        else:
            actions["unchanged"] += 1
    write_json(state_path, state)
    res = {"mode": jira.mode, "groups": len(groups), "unidentified": unidentified, "tickets": len(state),
           **{k: v for k, v in actions.items()}}
    log("jira.sync", created=len(actions["created"]), closed=len(actions["closed"]), reopened=len(actions["reopened"]))
    return res


if __name__ == "__main__":
    try:
        emit(sync(load_config()))
    except AutomationError as e:
        sys.stderr.write(json.dumps({"error": str(e)}) + "\n")
        sys.exit(2)
