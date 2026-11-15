"""Posture metrics for the GitLab Pages dashboard - per software / engagement / platform, over time.

    metrics.py snapshot                 # collect current posture from DefectDojo -> history.jsonl
    metrics.py build --out public       # pages/ assets + public/data/metrics.json (aggregate + detailed)
    metrics.py demo-history --apps 14 --weeks 26   # deterministic sample history (preview / training)

History lines: {"date","dimension":"software|engagement|platform","name","platform",
                "Critical","High","Medium","Low","Info","kev","overdue","closed","score"}
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import random
import shutil
import sys
from typing import Any, Dict, Iterable, List, Optional

from common import AutomationError, REPO_ROOT, SEVERITIES, cfg_get, emit, load_config, parse_ts, read_json, state_dir, utc_now, write_json
from dojo_client import Dojo, engagement_of, platform_of, product_of

WEIGHTS = {"Critical": 10.0, "High": 5.0, "Medium": 2.0, "Low": 0.5, "Info": 0.0}
DEFAULT_SLA = {"Critical": 15, "High": 30, "Medium": 90, "Low": 180, "Info": 365}
DIMENSIONS = ("software", "engagement", "platform")


def history_path(cfg: Dict[str, Any]) -> str:
    return os.environ.get("DOJO_METRICS_HISTORY") or os.path.join(state_dir(cfg), "metrics", "history.jsonl")


def _empty() -> Dict[str, Any]:
    return {**{s: 0 for s in SEVERITIES}, "kev": 0, "overdue": 0, "closed": 0, "score": 0.0}


def _age_days(d: Dict[str, Any], now: _dt.datetime) -> int:
    ts = d.get("date") or d.get("created")
    if not ts:
        return 0
    try:
        return max(0, (now - parse_ts(str(ts) if "T" in str(ts) else f"{ts}T00:00:00Z")).days)
    except ValueError:
        return 0


def collect(cfg: Dict[str, Any], findings: List[Dict[str, Any]], today: Optional[str] = None) -> Dict[str, Any]:
    now = _dt.datetime.now(_dt.timezone.utc)
    today = today or now.date().isoformat()
    sla = dict(DEFAULT_SLA, **(cfg_get(cfg, "sla", {}) or {}))
    buckets: Dict[str, Dict[str, Dict[str, Any]]] = {d: {} for d in DIMENSIONS}
    detailed: List[Dict[str, Any]] = []
    jira_state = read_json(os.path.join(state_dir(cfg), "jira.json"), {}) or {}
    for d in findings:
        prod, eng, plat = product_of(d), engagement_of(d), platform_of(d)
        active = bool(d.get("active")) and not d.get("is_mitigated")
        sev = d.get("severity") if d.get("severity") in SEVERITIES else "Info"
        age = _age_days(d, now)
        overdue = active and age > int(sla.get(sev, 365))
        for dim, name in (("software", prod), ("engagement", eng), ("platform", plat)):
            b = buckets[dim].setdefault(name, dict(_empty(), platform=plat if dim == "software" else None))
            if active:
                b[sev] += 1
                b["kev"] += int(bool(d.get("known_exploited")))
                b["overdue"] += int(overdue)
                b["score"] += WEIGHTS[sev] + (5.0 if d.get("known_exploited") else 0.0)
            else:
                b["closed"] += 1
        vid = d.get("vuln_id_from_tool") or ""
        detailed.append({"product": prod, "engagement": eng, "platform": plat, "id": vid, "severity": sev,
                         "title": str(d.get("title") or "")[:160], "status": "Active" if active else "Mitigated",
                         "ageDays": age, "overdue": overdue, "kev": bool(d.get("known_exploited")),
                         "epss": d.get("epss_score"), "cvss": d.get("cvssv3_score"),
                         "jira": (jira_state.get(vid) or {}).get("key")})
    rows = []
    for dim, items in buckets.items():
        for name, b in items.items():
            rows.append(dict(b, date=today, dimension=dim, name=name, score=round(b["score"], 1)))
    detailed.sort(key=lambda r: (r["status"] != "Active", SEVERITIES.index(r["severity"]), -r["ageDays"]))
    return {"rows": rows, "detailed": detailed}


def snapshot(cfg: Dict[str, Any], dojo: Optional[Dojo] = None) -> Dict[str, Any]:
    dojo = dojo or Dojo.from_config(cfg)
    res = collect(cfg, dojo.findings())
    path = history_path(cfg)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    today = res["rows"][0]["date"] if res["rows"] else _dt.date.today().isoformat()
    kept = [r for r in _read_history(path) if r.get("date") != today]  # idempotent per day
    with open(path, "w", encoding="utf-8") as fh:
        for r in kept + res["rows"]:
            fh.write(json.dumps(r, sort_keys=True) + "\n")
    write_json(os.path.join(os.path.dirname(path), "detailed.json"), res["detailed"])
    return {"date": today, "rows": len(res["rows"]), "findings": len(res["detailed"]), "history": path}


def _read_history(path: str) -> List[Dict[str, Any]]:
    out = []
    if os.path.isfile(path):
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    out.append(json.loads(line))
    return out


def build(cfg: Dict[str, Any], out_dir: str, pages_src: Optional[str] = None) -> Dict[str, Any]:
    hist = _read_history(history_path(cfg))
    detailed = read_json(os.path.join(os.path.dirname(history_path(cfg)), "detailed.json"), []) or []
    dates = sorted({r["date"] for r in hist})
    dims: Dict[str, List[Dict[str, Any]]] = {}
    for dim in DIMENSIONS:
        names = sorted({r["name"] for r in hist if r["dimension"] == dim})
        ents = []
        for n in names:
            series = sorted([r for r in hist if r["dimension"] == dim and r["name"] == n], key=lambda r: r["date"])
            pts = [{k: r.get(k) for k in ("date", *SEVERITIES, "kev", "overdue", "closed", "score")} for r in series]
            cur = pts[-1] if pts else _empty()
            first = pts[0] if pts else cur
            ents.append({"name": n, "platform": series[-1].get("platform") if series else None, "series": pts, "current": cur,
                         "delta": round((cur.get("score") or 0) - (first.get("score") or 0), 1)})
        ents.sort(key=lambda e: -(e["current"].get("score") or 0))
        dims[dim] = ents
    trend = []
    for dt in dates:
        rows = [r for r in hist if r["date"] == dt and r["dimension"] == "software"]
        agg = {s: sum(r.get(s, 0) for r in rows) for s in SEVERITIES}
        agg.update({"date": dt, "kev": sum(r.get("kev", 0) for r in rows), "overdue": sum(r.get("overdue", 0) for r in rows),
                    "closed": sum(r.get("closed", 0) for r in rows), "score": round(sum(r.get("score", 0) for r in rows), 1)})
        trend.append(agg)
    current = trend[-1] if trend else dict(_empty(), date=None)
    data = {
        "schema": "dojo-pages-metrics/v2", "generated": utc_now(),
        "organization": cfg_get(cfg, "project.organization", ""), "environment": cfg_get(cfg, "project.name", ""),
        "aggregate": {"current": current, "open": sum(current.get(s, 0) for s in SEVERITIES), "trend": trend,
                      "softwareCount": len(dims.get("software", [])), "sla": dict(DEFAULT_SLA, **(cfg_get(cfg, "sla", {}) or {}))},
        "dimensions": dims, "detailed": detailed[:1000],
    }
    pages_src = pages_src or os.path.join(REPO_ROOT, "pages")
    os.makedirs(out_dir, exist_ok=True)
    if os.path.isdir(pages_src):
        for fn in os.listdir(pages_src):
            src = os.path.join(pages_src, fn)
            if os.path.isfile(src):
                shutil.copy2(src, os.path.join(out_dir, fn))
    write_json(os.path.join(out_dir, "data", "metrics.json"), data, indent=None)
    return {"out": out_dir, "dates": len(dates), "software": len(dims.get("software", [])),
            "engagements": len(dims.get("engagement", [])), "platforms": len(dims.get("platform", []))}


DEMO_APPS = [
    ("payments-api", "EKS"), ("identity-gateway", "EKS"), ("case-management", "EKS"), ("hr-portal", "EC2 RHEL 9"),
    ("records-archive", "EC2 RHEL 9"), ("grants-tracker", "Lambda"), ("geo-analytics", "EKS"), ("field-mobile", "Mobile"),
    ("procurement-erp", "Windows Server 2022"), ("secure-messaging", "EKS"), ("data-lake-etl", "Lambda"),
    ("logistics-planner", "EC2 RHEL 9"), ("public-web", "EKS"), ("training-lms", "Windows Server 2022"),
]
DEMO_ENGAGEMENTS = ["Continuous Scanning", "Q3 Penetration Test", "Annual CMMC Assessment", "Red Team 2026", "Manual Inputs"]


def demo_history(cfg: Dict[str, Any], apps: int = 14, weeks: int = 26, seed: int = 800171) -> Dict[str, Any]:
    rnd = random.Random(seed)
    end = _dt.date.today()
    rows: List[Dict[str, Any]] = []
    sel = DEMO_APPS[: max(12, min(apps, len(DEMO_APPS)))]
    profiles = {a: (rnd.uniform(0.6, 1.6), rnd.choice([-1, -1, -1, 0, 1])) for a, _ in sel}
    for w in range(weeks, -1, -1):
        day = (end - _dt.timedelta(weeks=w)).isoformat()
        plat_acc: Dict[str, Dict[str, Any]] = {}
        eng_acc: Dict[str, Dict[str, Any]] = {}
        for app, plat in sel:
            scale, trend = profiles[app]
            t = (weeks - w) / max(weeks, 1)
            drift = 1 + trend * 0.45 * t
            r = _empty()
            r.update({"Critical": max(0, int(rnd.gauss(1.5, 1) * scale * drift)), "High": max(0, int(rnd.gauss(6, 2) * scale * drift)),
                      "Medium": max(0, int(rnd.gauss(14, 4) * scale * drift)), "Low": max(0, int(rnd.gauss(20, 5) * scale)),
                      "Info": max(0, int(rnd.gauss(8, 3)))})
            r["kev"] = min(r["Critical"] + r["High"], max(0, int(rnd.gauss(0.8, 0.8) * scale * drift)))
            r["overdue"] = max(0, int((r["Critical"] + r["High"]) * rnd.uniform(0.05, 0.4)))
            r["closed"] = max(0, int(rnd.gauss(9, 3)))
            r["score"] = round(sum(WEIGHTS[s] * r[s] for s in SEVERITIES) + 5 * r["kev"], 1)
            rows.append(dict(r, date=day, dimension="software", name=app, platform=plat))
            pa = plat_acc.setdefault(plat, _empty())
            for k in list(_empty().keys()):
                pa[k] += r[k]
            for i, eng in enumerate(DEMO_ENGAGEMENTS):
                share = [0.6, 0.12, 0.1, 0.08, 0.1][i]
                ea = eng_acc.setdefault(eng, _empty())
                for k in list(_empty().keys()):
                    ea[k] += r[k] * share
        for plat, v in plat_acc.items():
            rows.append(dict({k: (round(x, 1) if isinstance(x, float) else x) for k, x in v.items()}, date=day, dimension="platform", name=plat, platform=None))
        for eng, v in eng_acc.items():
            rows.append(dict({k: (round(x, 1) if k == "score" else int(round(x))) for k, x in v.items()}, date=day, dimension="engagement", name=eng, platform=None))
    path = history_path(cfg)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    existing = [r for r in _read_history(path) if r.get("date") == end.isoformat() and r.get("dimension") == "software"
                and r.get("name") not in {a for a, _ in sel}]
    with open(path, "w", encoding="utf-8") as fh:
        for r in rows + existing:
            fh.write(json.dumps(r, sort_keys=True) + "\n")
    return {"history": path, "rows": len(rows), "apps": len(sel), "weeks": weeks}


def main(argv: Optional[List[str]] = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description="Posture metrics for GitLab Pages")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("snapshot")
    b = sub.add_parser("build")
    b.add_argument("--out", default="public")
    b.add_argument("--pages-src")
    dh = sub.add_parser("demo-history")
    dh.add_argument("--apps", type=int, default=14)
    dh.add_argument("--weeks", type=int, default=26)
    a = ap.parse_args(argv)
    cfg = load_config()
    if a.cmd == "snapshot":
        emit(snapshot(cfg))
    elif a.cmd == "build":
        emit(build(cfg, a.out, a.pages_src))
    else:
        emit(demo_history(cfg, a.apps, a.weeks))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AutomationError as e:
        sys.stderr.write(json.dumps({"error": str(e)}) + "\n")
        sys.exit(2)
