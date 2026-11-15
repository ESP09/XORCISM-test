"""Threat-intelligence feed synchronisation: CISA KEV, NVD CVE 2.0, GitHub Security Advisories,
FIRST EPSS, OSV and internal zero-day (ZDAY-*) bulletins.

Two verifiable modes:

**Online (proxy allowlist)** – ``sync_feeds.py sync``
    Fetches every enabled source through ``HTTPS_PROXY`` (the egress proxy only allowlists the
    feed hosts), validates each payload's schema, writes a new snapshot directory with a
    ``manifest.sha256`` (``sha256sum -c`` compatible) and ``state.json``, atomically promotes it to
    ``feeds/current`` and archives ``<ts>.tar.gz`` + manifest to the SSE-KMS S3 state bucket.

**Offline (air-gapped bundle)** – ``sync_feeds.py bundle create|import``
    ``create`` packages the current snapshot into a ``.tar.gz`` with a detached ``.sha256``;
    ``import`` verifies the bundle digest, safely extracts it (no links / absolute / ``..`` paths,
    size caps), re-verifies every file against the manifest and schema, then promotes it with
    ``offline: true`` – all consumers then perform lookups against the snapshot only.

``sync_feeds.py status`` / ``check-staleness`` report record counts, digests and age; staleness
beyond ``feeds.feedMaxStalenessHours`` exits 3 and (with ``--notify``) sends an alert.
"""
from __future__ import annotations

import datetime as _dt
import glob
import io
import json
import os
import re
import shutil
import sys
import tarfile
import tempfile
import time
import urllib.parse
from typing import Any, Callable, Dict, List, Optional, Tuple

from common import (AutomationError, cfg_get, emit, http_request, load_config, log, parse_ts, read_json,
                    s3_put, sha256_bytes, sha256_file, state_dir, utc_now, write_json)
from feeds import read_manifest, verify_manifest
from ids import CVE_RE, normalize_id

DEFAULT_URLS = {
    "kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "nvd": "https://services.nvd.nist.gov/rest/json/cves/2.0",
    "ghsa": "https://api.github.com/advisories",
    "epss": "https://api.first.org/data/v1/epss",
    "osv": "https://api.osv.dev/v1",
}
SOURCES = ["kev", "nvd", "ghsa", "epss", "osv", "zeroday"]
SOURCE_FILES = {"kev": ["kev.json"], "nvd": ["nvd.json"], "ghsa": ["ghsa.json"], "epss": ["epss.json"], "osv": ["osv.json"]}
ZDAY_ID = re.compile(r"^ZDAY-\d{4}-\d{3,6}$")
MAX_BUNDLE_BYTES = 2 * 1024 ** 3
MAX_MEMBER_BYTES = 1024 ** 3


# ── schema validation ────────────────────────────────────────────────────────
def validate_kev(d: Any) -> List[str]:
    p: List[str] = []
    if not isinstance(d, dict) or not isinstance(d.get("vulnerabilities"), list):
        return ["kev: expected object with 'vulnerabilities' list"]
    for k in ("catalogVersion", "dateReleased"):
        if k not in d:
            p.append(f"kev: missing {k}")
    if "count" in d and d["count"] != len(d["vulnerabilities"]):
        p.append(f"kev: count {d['count']} != {len(d['vulnerabilities'])} entries")
    for i, v in enumerate(d["vulnerabilities"]):
        if not CVE_RE.fullmatch(str(v.get("cveID") or "")):
            p.append(f"kev[{i}]: invalid cveID {v.get('cveID')!r}")
        for k in ("dateAdded", "dueDate", "requiredAction"):
            if not v.get(k):
                p.append(f"kev[{i}] {v.get('cveID')}: missing {k}")
        if len(p) > 20:
            break
    return p


def validate_nvd(d: Any) -> List[str]:
    if not isinstance(d, dict) or not isinstance(d.get("vulnerabilities"), list):
        return ["nvd: expected object with 'vulnerabilities' list"]
    p = []
    if d.get("format") not in (None, "NVD_CVE"):
        p.append(f"nvd: unexpected format {d.get('format')}")
    if str(d.get("version", "2.0")) != "2.0":
        p.append(f"nvd: unexpected version {d.get('version')}")
    for i, v in enumerate(d["vulnerabilities"]):
        cid = ((v or {}).get("cve") or {}).get("id")
        if not CVE_RE.fullmatch(str(cid or "")):
            p.append(f"nvd[{i}]: invalid cve.id {cid!r}")
            if len(p) > 20:
                break
    return p


def validate_ghsa(d: Any) -> List[str]:
    if not isinstance(d, list):
        return ["ghsa: expected list"]
    return [f"ghsa[{i}]: invalid ghsa_id" for i, a in enumerate(d)
            if not normalize_id((a or {}).get("ghsa_id") or "") or not str(a.get("ghsa_id")).upper().startswith("GHSA-")][:20]


def validate_epss(d: Any) -> List[str]:
    if not isinstance(d, dict) or not isinstance(d.get("data"), list):
        return ["epss: expected object with 'data' list"]
    p = []
    for i, e in enumerate(d["data"]):
        try:
            ok = CVE_RE.fullmatch(e["cve"]) and 0 <= float(e["epss"]) <= 1 and 0 <= float(e["percentile"]) <= 1
        except (KeyError, TypeError, ValueError):
            ok = False
        if not ok:
            p.append(f"epss[{i}]: invalid record")
            if len(p) > 20:
                break
    return p


def validate_osv(d: Any) -> List[str]:
    if not isinstance(d, list):
        return ["osv: expected list"]
    return [f"osv[{i}]: missing id/modified" for i, o in enumerate(d) if not (o or {}).get("id") or not o.get("modified")][:20]


def validate_zday(d: Any) -> List[str]:
    p = []
    if not isinstance(d, dict) or not ZDAY_ID.match(str(d.get("id") or "")):
        return [f"zeroday: invalid id {d.get('id') if isinstance(d, dict) else d!r}"]
    for k in ("title", "published", "severity", "summary"):
        if not d.get(k):
            p.append(f"{d['id']}: missing {k}")
    for a in d.get("aliases") or []:
        if not normalize_id(a):
            p.append(f"{d['id']}: invalid alias {a}")
    return p


VALIDATORS: Dict[str, Callable[[Any], List[str]]] = {"kev": validate_kev, "nvd": validate_nvd, "ghsa": validate_ghsa,
                                                     "epss": validate_epss, "osv": validate_osv}


# ── fetchers ─────────────────────────────────────────────────────────────────
def _urls(cfg: Dict[str, Any]) -> Dict[str, str]:
    u = dict(DEFAULT_URLS)
    u.update({k: v for k, v in (cfg_get(cfg, "feeds.urls", {}) or {}).items() if v})
    return u


def _get_json(url: str, headers: Optional[Dict[str, str]] = None) -> Tuple[Any, Dict[str, str]]:
    r = http_request("GET", url, headers=headers, timeout=120)
    return r.json(), r.headers


def fetch_kev(cfg: Dict[str, Any]) -> Dict[str, Any]:
    data, _ = _get_json(_urls(cfg)["kev"])
    return data


def fetch_nvd(cfg: Dict[str, Any], previous: Optional[Dict[str, Any]], since: Optional[str], must_have: List[str]) -> Dict[str, Any]:
    base = _urls(cfg)["nvd"]
    key = os.environ.get("NVD_API_KEY", "")
    headers = {"apiKey": key} if key else {}
    delay = float(os.environ.get("DOJO_NVD_DELAY", "0.7" if key else "6.5"))
    end = _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0)
    lookback = int(cfg_get(cfg, "feeds.nvdLookbackDays", 8))
    start = parse_ts(since) if since else end - _dt.timedelta(days=lookback)
    start = max(start, end - _dt.timedelta(days=119))  # NVD: max 120-day window
    merged: Dict[str, Any] = {}
    for v in (previous or {}).get("vulnerabilities") or []:
        merged[v["cve"]["id"]] = v
    # First run (no previous snapshot) bootstraps the full corpus when feeds.nvdFullBootstrap is true;
    # later runs are incremental on lastModified (NVD caps a window at 120 days).
    bootstrap = not merged and bool(cfg_get(cfg, "feeds.nvdFullBootstrap", True))
    idx, total = 0, None
    while total is None or idx < total:
        q: Dict[str, Any] = {"startIndex": idx, "resultsPerPage": 2000}
        if not bootstrap:
            q.update({"lastModStartDate": start.isoformat().replace("+00:00", "Z"),
                      "lastModEndDate": end.isoformat().replace("+00:00", "Z")})
        page, _ = _get_json(base + "?" + urllib.parse.urlencode(q), headers)
        total = int(page.get("totalResults") or 0)
        for v in page.get("vulnerabilities") or []:
            merged[v["cve"]["id"]] = v
        idx += int(page.get("resultsPerPage") or 2000)
        if idx < total:
            time.sleep(delay)
    missing = [c for c in must_have if c not in merged][: int(cfg_get(cfg, "feeds.nvdMaxDirectLookups", 200))]
    for cve in missing:
        page, _ = _get_json(base + "?" + urllib.parse.urlencode({"cveId": cve}), headers)
        for v in page.get("vulnerabilities") or []:
            merged[v["cve"]["id"]] = v
        time.sleep(delay)
    return {"format": "NVD_CVE", "version": "2.0", "timestamp": utc_now(), "totalResults": len(merged),
            "vulnerabilities": [merged[k] for k in sorted(merged)]}


def fetch_ghsa(cfg: Dict[str, Any], previous: Optional[List[Dict[str, Any]]], since: Optional[str], must_have: List[str]) -> List[Dict[str, Any]]:
    base = _urls(cfg)["ghsa"]
    tok = os.environ.get("GITHUB_TOKEN", "")
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if tok:
        headers["Authorization"] = f"Bearer {tok}"
    merged = {a["ghsa_id"]: a for a in previous or []}
    params = {"per_page": 100, "type": "reviewed"}
    if since:
        params["updated"] = ">=" + since[:10]
    url: Optional[str] = base + "?" + urllib.parse.urlencode(params)
    pages = 0
    while url and pages < int(cfg_get(cfg, "feeds.ghsaMaxPages", 50)):
        data, hdrs = _get_json(url, headers)
        for a in data or []:
            merged[a["ghsa_id"]] = a
        url = _next_link(hdrs.get("link", ""))
        pages += 1
    for gid in must_have:
        if gid not in merged:
            r = http_request("GET", f"{base}/{gid}", headers=headers, expect_ok=False)
            if r.ok:
                a = r.json()
                merged[a["ghsa_id"]] = a
    return [merged[k] for k in sorted(merged)]


def _next_link(link: str) -> Optional[str]:
    for part in link.split(","):
        m = re.search(r'<([^>]+)>\s*;\s*rel="next"', part)
        if m:
            return m.group(1)
    return None


def fetch_epss(cfg: Dict[str, Any], cves: List[str]) -> Dict[str, Any]:
    base = _urls(cfg)["epss"]
    data: Dict[str, Any] = {}
    model, score_date = None, None
    for i in range(0, len(cves), 100):
        batch = cves[i:i + 100]
        page, _ = _get_json(base + "?" + urllib.parse.urlencode({"cve": ",".join(batch), "limit": 100}))
        if page.get("status") not in (None, "OK"):
            raise AutomationError(f"epss: status {page.get('status')}")
        model = page.get("model_version") or model
        for e in page.get("data") or []:
            data[e["cve"]] = e
            score_date = e.get("date") or score_date
    return {"status": "OK", "model_version": model, "score_date": score_date, "total": len(data),
            "data": [data[k] for k in sorted(data)]}


def fetch_osv(cfg: Dict[str, Any], previous: Optional[List[Dict[str, Any]]], ids: List[str]) -> List[Dict[str, Any]]:
    base = _urls(cfg)["osv"].rstrip("/")
    merged = {o["id"]: o for o in previous or []}
    for vid in ids:
        r = http_request("GET", f"{base}/vulns/{urllib.parse.quote(vid)}", expect_ok=False)
        if r.ok:
            o = r.json()
            merged[o["id"]] = o
            for alias in o.get("aliases") or []:
                merged.setdefault("__alias__" + alias, None)
    return [merged[k] for k in sorted(merged) if merged[k]]


def load_zeroday(cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    d = cfg_get(cfg, "feeds.zerodayDir") or os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "threat-intel", "zeroday")
    out = []
    for p in sorted(glob.glob(os.path.join(d, "ZDAY-*.json"))):
        with open(p, "r", encoding="utf-8") as fh:
            z = json.load(fh)
        probs = validate_zday(z)
        if probs:
            raise AutomationError("zero-day bulletin invalid: " + "; ".join(probs))
        out.append(z)
    return out


def watchlist(cfg: Dict[str, Any], extra: Optional[str]) -> List[str]:
    ids: List[str] = []
    for src in [os.path.join(state_dir(cfg), "watchlist.json"), extra]:
        if src and os.path.isfile(src):
            for i in read_json(src, []) or []:
                n = normalize_id(i)
                if n and n not in ids:
                    ids.append(n)
    return ids


# ── snapshot handling ────────────────────────────────────────────────────────
def feeds_root(cfg: Dict[str, Any]) -> str:
    d = os.path.join(state_dir(cfg), "feeds")
    os.makedirs(d, exist_ok=True)
    return d


def current_dir(cfg: Dict[str, Any]) -> str:
    return os.environ.get("DOJO_FEED_DIR") or os.path.join(feeds_root(cfg), "current")


def write_manifest(d: str) -> Dict[str, str]:
    entries: Dict[str, str] = {}
    for root, _, files in os.walk(d):
        for fn in files:
            if fn in ("manifest.sha256", "state.json"):
                continue
            rel = os.path.relpath(os.path.join(root, fn), d).replace(os.sep, "/")
            entries[rel] = sha256_file(os.path.join(root, fn))
    with open(os.path.join(d, "manifest.sha256"), "w", encoding="utf-8") as fh:
        for rel in sorted(entries):
            fh.write(f"{entries[rel]}  {rel}\n")
    return entries


def _count(source: str, data: Any) -> int:
    if source == "kev":
        return len(data.get("vulnerabilities") or [])
    if source == "nvd":
        return len(data.get("vulnerabilities") or [])
    if source == "epss":
        return len(data.get("data") or [])
    return len(data or [])


def promote(cfg: Dict[str, Any], new_dir: str) -> str:
    cur = current_dir(cfg)
    prev = cur + ".previous"
    if os.path.isdir(prev):
        shutil.rmtree(prev)
    if os.path.isdir(cur):
        os.replace(cur, prev)
    os.replace(new_dir, cur)
    return cur


def sync_online(cfg: Dict[str, Any], sources: List[str], watch_file: Optional[str] = None, archive: bool = True) -> Dict[str, Any]:
    if cfg_get(cfg, "feeds.mode", "online") == "offline":
        raise AutomationError("feeds.mode is 'offline': import an air-gapped bundle instead (sync_feeds.py bundle import)")
    cur = current_dir(cfg)
    prev_state = read_json(os.path.join(cur, "state.json"), {}) or {}
    stamp = utc_now().replace(":", "").replace("-", "")
    work = os.path.join(feeds_root(cfg), f".staging-{stamp}")
    if os.path.isdir(cur):
        shutil.copytree(cur, work)
        for fn in ("manifest.sha256", "state.json"):
            if os.path.exists(os.path.join(work, fn)):
                os.remove(os.path.join(work, fn))
    else:
        os.makedirs(work)
    watch = watchlist(cfg, watch_file)
    watch_cves = [i for i in watch if i.startswith("CVE-")]
    watch_other = [i for i in watch if not i.startswith(("CVE-", "ZDAY-"))]
    state: Dict[str, Any] = {"generated": utc_now(), "mode": "online", "offline": False, "sources": dict(prev_state.get("sources") or {}),
                             "proxy": _proxy_desc()}
    enabled = {k for k, v in (cfg_get(cfg, "feeds.sources", {}) or {}).items() if v} or set(SOURCES)
    errors: List[str] = []

    def put(source: str, name: str, data: Any) -> None:
        problems = VALIDATORS[source](data)
        if problems:
            raise AutomationError(f"{source} schema validation failed: " + "; ".join(problems[:5]))
        raw = json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        with open(os.path.join(work, name), "wb") as fh:
            fh.write(raw)
        state["sources"][source] = {"lastSync": utc_now(), "records": _count(source, data), "sha256": sha256_bytes(raw),
                                    "file": name, "url": _urls(cfg).get(source), "status": "ok"}
        log("feeds.synced", source=source, records=state["sources"][source]["records"], sha256=state["sources"][source]["sha256"][:16])

    kev = None
    for source in [s for s in sources if s in enabled]:
        try:
            last = ((prev_state.get("sources") or {}).get(source) or {}).get("lastSync")
            if source == "kev":
                kev = fetch_kev(cfg)
                put("kev", "kev.json", kev)
            elif source == "nvd":
                must = sorted(set(watch_cves + [v["cveID"] for v in (kev or {}).get("vulnerabilities") or []]))
                put("nvd", "nvd.json", fetch_nvd(cfg, read_json(os.path.join(work, "nvd.json")), last, must))
            elif source == "ghsa":
                put("ghsa", "ghsa.json", fetch_ghsa(cfg, read_json(os.path.join(work, "ghsa.json")), last,
                                                    [i for i in watch_other if i.startswith("GHSA-")]))
            elif source == "epss":
                kev_ids = [v["cveID"] for v in (kev or read_json(os.path.join(work, "kev.json"), {}) or {}).get("vulnerabilities") or []]
                nvd_ids = [v["cve"]["id"] for v in (read_json(os.path.join(work, "nvd.json"), {}) or {}).get("vulnerabilities") or []]
                put("epss", "epss.json", fetch_epss(cfg, sorted(set(watch_cves + kev_ids + nvd_ids))))
            elif source == "osv":
                put("osv", "osv.json", fetch_osv(cfg, read_json(os.path.join(work, "osv.json")), watch_other + watch_cves))
            elif source == "zeroday":
                zdir = os.path.join(work, "zeroday")
                shutil.rmtree(zdir, ignore_errors=True)
                os.makedirs(zdir)
                zd = load_zeroday(cfg)
                for z in zd:
                    write_json(os.path.join(zdir, f"{z['id']}.json"), z)
                state["sources"]["zeroday"] = {"lastSync": utc_now(), "records": len(zd), "status": "ok",
                                               "sha256": sha256_bytes(json.dumps(zd, sort_keys=True).encode()), "file": "zeroday/"}
        except AutomationError as e:
            errors.append(f"{source}: {e}")
            state["sources"].setdefault(source, {})["status"] = "error"
            state["sources"][source]["error"] = str(e)[:300]
            log("feeds.error", source=source, error=str(e))
    entries = write_manifest(work)
    state["manifestSha256"] = sha256_file(os.path.join(work, "manifest.sha256"))
    state["files"] = len(entries)
    write_json(os.path.join(work, "state.json"), state)
    promote(cfg, work)
    archived = None
    if archive and cfg_get(cfg, "aws.stateBucket"):
        archived = archive_snapshot(cfg, stamp)
    return {"ok": not errors, "errors": errors, "state": state, "archived": archived, "dir": current_dir(cfg)}


def _proxy_desc() -> Dict[str, str]:
    p = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy") or ""
    u = urllib.parse.urlsplit(p) if p else None
    return {"httpsProxy": f"{u.scheme}://{u.hostname}:{u.port}" if u else "", "noProxy": os.environ.get("NO_PROXY", "")}


def _tar_dir(src: str, out: str) -> None:
    with tarfile.open(out, "w:gz") as tf:
        for root, _, files in os.walk(src):
            for fn in sorted(files):
                full = os.path.join(root, fn)
                tf.add(full, arcname=os.path.relpath(full, src).replace(os.sep, "/"), recursive=False)


def archive_snapshot(cfg: Dict[str, Any], stamp: str) -> Dict[str, str]:
    bucket = cfg_get(cfg, "aws.stateBucket")
    kms = cfg_get(cfg, "aws.kmsKeyArn") or cfg_get(cfg, "aws.kmsKeyAlias")
    tmp = tempfile.mkdtemp()
    try:
        out = os.path.join(tmp, f"{stamp}.tar.gz")
        _tar_dir(current_dir(cfg), out)
        digest = sha256_file(out)
        s3_put(out, bucket, f"feeds/snapshots/{stamp}.tar.gz", kms, cfg)
        s3_put(os.path.join(current_dir(cfg), "manifest.sha256"), bucket, f"feeds/snapshots/{stamp}.manifest.sha256", kms, cfg)
        return {"uri": f"s3://{bucket}/feeds/snapshots/{stamp}.tar.gz", "sha256": digest}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def bundle_create(cfg: Dict[str, Any], out: str) -> Dict[str, Any]:
    cur = current_dir(cfg)
    problems = verify_manifest(cur)
    if problems:
        raise AutomationError("current snapshot does not verify: " + "; ".join(problems[:5]))
    st = read_json(os.path.join(cur, "state.json"), {}) or {}
    meta = {"bundle": "defectdojo-threat-intel/v1", "created": utc_now(), "sources": st.get("sources"),
            "manifestSha256": sha256_file(os.path.join(cur, "manifest.sha256"))}
    with tempfile.TemporaryDirectory() as tmp:
        stage = os.path.join(tmp, "b")
        shutil.copytree(cur, stage)
        write_json(os.path.join(stage, "bundle.json"), meta)
        os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
        _tar_dir(stage, out)
    digest = sha256_file(out)
    with open(out + ".sha256", "w", encoding="utf-8") as fh:
        fh.write(f"{digest}  {os.path.basename(out)}\n")
    return {"bundle": out, "sha256": digest, "manifestSha256": meta["manifestSha256"], "sources": list((st.get("sources") or {}).keys())}


def _safe_extract(tf: tarfile.TarFile, dest: str) -> None:
    total = 0
    for m in tf.getmembers():
        name = m.name
        if name.startswith("/") or ".." in name.split("/") or re.match(r"^[A-Za-z]:", name):
            raise AutomationError(f"bundle: unsafe member path {name!r}")
        if not (m.isfile() or m.isdir()):
            raise AutomationError(f"bundle: links/devices not allowed ({name})")
        if m.size > MAX_MEMBER_BYTES:
            raise AutomationError(f"bundle: member {name} too large")
        total += m.size
        if total > MAX_BUNDLE_BYTES:
            raise AutomationError("bundle: expanded size exceeds limit")
    for m in tf.getmembers():
        target = os.path.join(dest, m.name)
        if m.isdir():
            os.makedirs(target, exist_ok=True)
            continue
        os.makedirs(os.path.dirname(target), exist_ok=True)
        src = tf.extractfile(m)
        with open(target, "wb") as fh:
            shutil.copyfileobj(src, fh)


def bundle_import(cfg: Dict[str, Any], bundle: str, expect_sha256: Optional[str] = None) -> Dict[str, Any]:
    digest = sha256_file(bundle)
    expected = expect_sha256
    side = bundle + ".sha256"
    if not expected and os.path.isfile(side):
        expected = open(side, encoding="utf-8").read().split()[0]
    if not expected:
        raise AutomationError("bundle import requires --sha256 or a detached <bundle>.sha256 file")
    if digest.lower() != expected.lower():
        raise AutomationError(f"bundle SHA-256 mismatch: got {digest}, expected {expected}")
    stage = os.path.join(feeds_root(cfg), ".import-" + utc_now().replace(":", "").replace("-", ""))
    os.makedirs(stage)
    try:
        with tarfile.open(bundle, "r:gz") as tf:
            _safe_extract(tf, stage)
        problems = verify_manifest(stage)
        man = read_manifest(stage)
        for source, files in SOURCE_FILES.items():
            for fn in files:
                if fn in man:
                    with open(os.path.join(stage, fn), "r", encoding="utf-8") as fh:
                        problems += VALIDATORS[source](json.load(fh))
        for p in glob.glob(os.path.join(stage, "zeroday", "ZDAY-*.json")):
            with open(p, encoding="utf-8") as fh:
                problems += validate_zday(json.load(fh))
        if problems:
            raise AutomationError("bundle verification failed: " + "; ".join(problems[:5]))
        meta = read_json(os.path.join(stage, "bundle.json"), {}) or {}
        st = read_json(os.path.join(stage, "state.json"), {}) or {}
        st.update({"mode": "offline", "offline": True, "importedAt": utc_now(), "bundleSha256": digest,
                   "bundleCreated": meta.get("created"), "manifestSha256": sha256_file(os.path.join(stage, "manifest.sha256"))})
        write_json(os.path.join(stage, "state.json"), st)
        promote(cfg, stage)
    except Exception:
        shutil.rmtree(stage, ignore_errors=True)
        raise
    return {"imported": bundle, "sha256": digest, "offline": True, "manifestSha256": st["manifestSha256"],
            "sources": {k: v.get("records") for k, v in (st.get("sources") or {}).items()}}


def status(cfg: Dict[str, Any]) -> Dict[str, Any]:
    cur = current_dir(cfg)
    st = read_json(os.path.join(cur, "state.json"), {}) or {}
    max_h = float(cfg_get(cfg, "feeds.feedMaxStalenessHours", 48))
    now = _dt.datetime.now(_dt.timezone.utc)
    srcs = {}
    stale = []
    ref_time = st.get("bundleCreated") if st.get("offline") else None
    for name in SOURCES:
        s = dict((st.get("sources") or {}).get(name) or {})
        ts = ref_time or s.get("lastSync")
        age = (now - parse_ts(ts)).total_seconds() / 3600 if ts else None
        s["ageHours"] = round(age, 2) if age is not None else None
        s["stale"] = age is None or age > max_h
        if s["stale"]:
            stale.append(name)
        srcs[name] = s
    problems = verify_manifest(cur) if os.path.isdir(cur) else ["no snapshot"]
    return {"dir": cur, "mode": st.get("mode") or cfg_get(cfg, "feeds.mode", "online"), "offline": bool(st.get("offline")),
            "generated": st.get("generated"), "importedAt": st.get("importedAt"), "manifestSha256": st.get("manifestSha256"),
            "bundleSha256": st.get("bundleSha256"), "verified": not problems, "problems": problems[:10],
            "feedMaxStalenessHours": max_h, "stale": stale, "sources": srcs}


def main(argv: Optional[List[str]] = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description="Threat feed sync (KEV, NVD, GHSA, EPSS, OSV, ZDAY)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("sync")
    s.add_argument("--sources", default=",".join(SOURCES))
    s.add_argument("--watch", help="JSON list of vulnerability ids to always resolve (e.g. ids present in findings)")
    s.add_argument("--no-archive", action="store_true")
    b = sub.add_parser("bundle")
    bs = b.add_subparsers(dest="bcmd", required=True)
    bc = bs.add_parser("create")
    bc.add_argument("--out", required=True)
    bi = bs.add_parser("import")
    bi.add_argument("--bundle", required=True)
    bi.add_argument("--sha256")
    sub.add_parser("status")
    cs = sub.add_parser("check-staleness")
    cs.add_argument("--notify", action="store_true")
    sub.add_parser("verify")
    a = ap.parse_args(argv)
    cfg = load_config()
    if a.cmd == "sync":
        res = sync_online(cfg, [x.strip() for x in a.sources.split(",") if x.strip()], a.watch, not a.no_archive)
        emit(res)
        return 0 if res["ok"] else 1
    if a.cmd == "bundle":
        emit(bundle_create(cfg, a.out) if a.bcmd == "create" else bundle_import(cfg, a.bundle, a.sha256))
        return 0
    if a.cmd == "verify":
        problems = verify_manifest(current_dir(cfg))
        emit({"verified": not problems, "problems": problems})
        return 0 if not problems else 1
    st = status(cfg)
    if a.cmd == "check-staleness":
        if st["stale"] and a.notify:
            from notify import send
            send(cfg, f"[DefectDojo] Threat feeds stale: {', '.join(st['stale'])}",
                 "The following threat-intelligence feeds exceed feedMaxStalenessHours="
                 f"{st['feedMaxStalenessHours']}: {', '.join(st['stale'])}.\nMode: {st['mode']} (offline={st['offline']}).\n"
                 "Online: check the egress proxy allowlist. Offline: import a fresh SHA-256 verified bundle.")
        emit(st)
        return 3 if st["stale"] or not st["verified"] else 0
    emit(st)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AutomationError as e:
        sys.stderr.write(json.dumps({"error": str(e)}) + "\n")
        sys.exit(2)
