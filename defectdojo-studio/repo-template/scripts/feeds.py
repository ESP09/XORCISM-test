"""Read-side access to a verified threat-intelligence snapshot (KEV, NVD 2.0, GHSA, EPSS, OSV, ZDAY).

The snapshot directory is produced by ``sync_feeds.py`` (online mode) or imported from an
air-gapped bundle (offline mode). Every consumer opens it through :func:`open_store`, which
refuses to load a snapshot whose ``manifest.sha256`` does not verify.
"""
from __future__ import annotations

import glob
import json
import os
from typing import Any, Dict, List, Optional

from common import AutomationError, cfg_get, sha256_file, state_dir
from ids import Resolver, normalize_id

FEED_FILES = {"kev": "kev.json", "nvd": "nvd.json", "ghsa": "ghsa.json", "epss": "epss.json", "osv": "osv.json"}


def feed_dir(cfg: Optional[Dict[str, Any]] = None) -> str:
    return os.environ.get("DOJO_FEED_DIR") or os.path.join(state_dir(cfg), "feeds", "current")


def read_manifest(d: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    p = os.path.join(d, "manifest.sha256")
    if not os.path.isfile(p):
        return out
    with open(p, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line.strip():
                continue
            digest, _, name = line.partition("  ")
            out[name.strip()] = digest.strip().lower()
    return out


def verify_manifest(d: str) -> List[str]:
    """Return a list of problems (empty == verified)."""
    problems: List[str] = []
    man = read_manifest(d)
    if not man:
        return ["manifest.sha256 missing or empty"]
    for name, digest in man.items():
        if name.startswith("/") or ".." in name.split("/"):
            problems.append(f"unsafe path in manifest: {name}")
            continue
        p = os.path.join(d, name)
        if not os.path.isfile(p):
            problems.append(f"missing file: {name}")
        elif sha256_file(p) != digest:
            problems.append(f"digest mismatch: {name}")
    return problems


class FeedStore:
    def __init__(self, d: str):
        self.dir = d
        self.kev: Dict[str, Dict[str, Any]] = {}
        self.nvd: Dict[str, Dict[str, Any]] = {}
        self.epss: Dict[str, Dict[str, Any]] = {}
        self.ghsa: Dict[str, Dict[str, Any]] = {}
        self.osv: Dict[str, Dict[str, Any]] = {}
        self.zday: Dict[str, Dict[str, Any]] = {}
        self.state: Dict[str, Any] = {}
        self._load()
        self.resolver = Resolver()
        self.resolver.load_osv(self.osv.values())
        self.resolver.load_ghsa(self.ghsa.values())
        self.resolver.load_zeroday(self.zday.values())

    def _read(self, name: str) -> Any:
        p = os.path.join(self.dir, name)
        if not os.path.isfile(p):
            return None
        with open(p, "r", encoding="utf-8") as fh:
            return json.load(fh)

    def _load(self) -> None:
        kev = self._read("kev.json") or {}
        for v in kev.get("vulnerabilities") or []:
            if v.get("cveID"):
                self.kev[v["cveID"].upper()] = v
        nvd = self._read("nvd.json") or {}
        for item in nvd.get("vulnerabilities") or []:
            c = item.get("cve") or {}
            if c.get("id"):
                self.nvd[c["id"].upper()] = c
        epss = self._read("epss.json") or {}
        for e in epss.get("data") or []:
            if e.get("cve"):
                self.epss[e["cve"].upper()] = e
        for g in self._read("ghsa.json") or []:
            if g.get("ghsa_id"):
                self.ghsa[normalize_id(g["ghsa_id"]) or g["ghsa_id"]] = g
        osv = self._read("osv.json") or []
        if isinstance(osv, dict):
            osv = osv.get("vulns") or []
        for o in osv:
            if o.get("id"):
                self.osv[o["id"]] = o
        for p in sorted(glob.glob(os.path.join(self.dir, "zeroday", "ZDAY-*.json"))):
            with open(p, "r", encoding="utf-8") as fh:
                z = json.load(fh)
            if z.get("id"):
                self.zday[z["id"].upper()] = z
        self.state = self._read("state.json") or {}

    # ── lookups ──
    def cvss(self, cve: str) -> Dict[str, Any]:
        c = self.nvd.get(cve.upper()) or {}
        metrics = c.get("metrics") or {}
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            arr = metrics.get(key) or []
            if arr:
                primary = next((m for m in arr if m.get("type") == "Primary"), arr[0])
                d = primary.get("cvssData") or {}
                return {"version": d.get("version"), "score": d.get("baseScore"), "vector": d.get("vectorString"),
                        "severity": d.get("baseSeverity") or primary.get("baseSeverity")}
        return {}

    def description(self, cve: str) -> str:
        c = self.nvd.get(cve.upper()) or {}
        for d in c.get("descriptions") or []:
            if d.get("lang") == "en":
                return d.get("value") or ""
        return ""

    def cwes(self, cve: str) -> List[str]:
        c = self.nvd.get(cve.upper()) or {}
        out: List[str] = []
        for w in c.get("weaknesses") or []:
            for d in w.get("description") or []:
                v = d.get("value") or ""
                if v.startswith("CWE-") and v not in out:
                    out.append(v)
        return out

    def references(self, cve: str) -> List[Dict[str, Any]]:
        c = self.nvd.get(cve.upper()) or {}
        return [{"url": r.get("url"), "tags": r.get("tags") or []} for r in c.get("references") or [] if r.get("url")]

    def advisories_for(self, vid: str) -> Dict[str, List[Dict[str, Any]]]:
        group = set(self.resolver.group(vid))
        ghsa = [g for k, g in self.ghsa.items() if k in group or (g.get("cve_id") or "").upper() in group]
        osv = [o for k, o in self.osv.items() if k in group or group.intersection(o.get("aliases") or [])]
        zd = [z for k, z in self.zday.items() if k in group or group.intersection(a.upper() for a in z.get("aliases") or [])]
        return {"ghsa": ghsa, "osv": osv, "zeroday": zd}


def open_store(cfg: Optional[Dict[str, Any]] = None, d: Optional[str] = None, verify: bool = True) -> FeedStore:
    d = d or feed_dir(cfg)
    if not os.path.isdir(d):
        raise AutomationError(f"no threat-feed snapshot at {d}; run scripts/sync_feeds.py first")
    if verify:
        problems = verify_manifest(d)
        if problems:
            raise AutomationError("feed snapshot failed SHA-256 verification: " + "; ".join(problems[:5]))
    return FeedStore(d)


def posture(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Lookup posture: offline snapshots never trigger live lookups."""
    mode = cfg_get(cfg, "feeds.mode", "online")
    st_path = os.path.join(feed_dir(cfg), "state.json")
    st: Dict[str, Any] = {}
    if os.path.isfile(st_path):
        with open(st_path, "r", encoding="utf-8") as fh:
            st = json.load(fh)
    return {"offline": bool(st.get("offline")) or mode == "offline", "mode": mode}
