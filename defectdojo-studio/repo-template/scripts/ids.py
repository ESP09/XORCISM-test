"""Vulnerability identifier normalisation and canonical resolution.

Canonical precedence:  CVE  >  ZDAY (internal zero-day bulletin)  >  GHSA  >  other (PYSEC/GO/OSV/RUSTSEC/...)

``GHSA-xxxx``, ``PYSEC-…``, ``GO-…``, ``OSV-…`` identifiers are mapped to a CVE through the alias
graph built from the synced OSV / GHSA snapshots and the zero-day bulletins. A finding that only
has a ZDAY bulletin keeps the ZDAY id until the bulletin's ``aliases`` gains a CVE, at which point
every finding (and its single Jira ticket) re-keys to the CVE.
"""
from __future__ import annotations

import glob
import json
import os
import re
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

_DASHES = dict.fromkeys(map(ord, "‐‑‒–—−－"), "-")

CVE_RE = re.compile(r"\bCVE[-_ ](\d{4})[-_ ](\d{4,7})\b", re.I)
GHSA_RE = re.compile(r"\bGHSA(-[23456789cfghjmpqrvwx]{4}){3}\b", re.I)
PYSEC_RE = re.compile(r"\bPYSEC-\d{4}-\d+\b", re.I)
GO_RE = re.compile(r"\bGO-\d{4}-\d{4,}\b", re.I)
OSV_RE = re.compile(r"\bOSV-\d{4}-\d+\b", re.I)
RUSTSEC_RE = re.compile(r"\bRUSTSEC-\d{4}-\d{4}\b", re.I)
ZDAY_RE = re.compile(r"\bZDAY-\d{4}-\d{3,6}\b", re.I)
CWE_RE = re.compile(r"\bCWE[-_ ]?(\d{1,5})\b", re.I)

_ALL = [CVE_RE, GHSA_RE, PYSEC_RE, GO_RE, OSV_RE, RUSTSEC_RE, ZDAY_RE]


def normalize_id(raw: Any) -> Optional[str]:
    if raw is None:
        return None
    s = str(raw).translate(_DASHES).strip().strip("[](){}<>.,;:'\"")
    if not s:
        return None
    m = CVE_RE.fullmatch(s)
    if m:
        return f"CVE-{m.group(1)}-{m.group(2)}"
    up = s.upper()
    if GHSA_RE.fullmatch(s):
        return "GHSA-" + s[5:].lower()
    for rx in (PYSEC_RE, GO_RE, OSV_RE, RUSTSEC_RE, ZDAY_RE):
        if rx.fullmatch(s):
            return up
    m = CWE_RE.fullmatch(s)
    if m:
        return f"CWE-{int(m.group(1))}"
    return None


def kind(vid: str) -> str:
    return vid.split("-", 1)[0].upper() if vid else ""


def extract_ids(text: Any) -> List[str]:
    """Every vulnerability id mentioned in free text (deduplicated, ordered by first appearance)."""
    if not text:
        return []
    t = str(text).translate(_DASHES)
    found: List[str] = []
    for rx in _ALL:
        for m in rx.finditer(t):
            n = normalize_id(m.group(0))
            if n and n not in found:
                found.append(n)
    return found


def extract_cwe(text: Any) -> Optional[int]:
    if not text:
        return None
    m = CWE_RE.search(str(text))
    return int(m.group(1)) if m else None


_PRIORITY = {"CVE": 0, "ZDAY": 1, "GHSA": 2}


def _rank(vid: str) -> Tuple[int, str]:
    return (_PRIORITY.get(kind(vid), 3), vid)


class Resolver:
    """Alias graph over OSV + GHSA + zero-day bulletins (union-find)."""

    def __init__(self) -> None:
        self._parent: Dict[str, str] = {}

    def _find(self, x: str) -> str:
        self._parent.setdefault(x, x)
        while self._parent[x] != x:
            self._parent[x] = self._parent[self._parent[x]]
            x = self._parent[x]
        return x

    def link(self, ids: Iterable[str]) -> None:
        norm = [n for n in (normalize_id(i) for i in ids) if n and kind(n) != "CWE"]
        if not norm:
            return
        root = self._find(norm[0])
        for other in norm[1:]:
            r2 = self._find(other)
            if r2 != root:
                self._parent[r2] = root

    def group(self, vid: str) -> List[str]:
        n = normalize_id(vid)
        if not n:
            return []
        if n not in self._parent:
            return [n]
        root = self._find(n)
        return sorted([k for k in self._parent if self._find(k) == root], key=_rank)

    def resolve(self, ids: Iterable[str]) -> Tuple[Optional[str], List[str]]:
        """Return (canonical_id, all_aliases). Input may contain several ids for the same issue."""
        members: Set[str] = set()
        for i in ids:
            n = normalize_id(i)
            if n and kind(n) != "CWE":
                members.update(self.group(n))
        if not members:
            return None, []
        ordered = sorted(members, key=_rank)
        return ordered[0], ordered

    # ── loaders ──
    def load_osv(self, records: Iterable[Dict[str, Any]]) -> None:
        for r in records:
            if isinstance(r, dict) and r.get("id"):
                self.link([r["id"], *(r.get("aliases") or [])])

    def load_ghsa(self, records: Iterable[Dict[str, Any]]) -> None:
        for r in records:
            if not isinstance(r, dict):
                continue
            ids = [r.get("ghsa_id"), r.get("cve_id")]
            ids += [i.get("value") for i in (r.get("identifiers") or []) if isinstance(i, dict)]
            self.link([i for i in ids if i])

    def load_zeroday(self, records: Iterable[Dict[str, Any]]) -> None:
        for r in records:
            if isinstance(r, dict) and r.get("id"):
                self.link([r["id"], *(r.get("aliases") or [])])

    @classmethod
    def from_feed_dir(cls, feed_dir: Optional[str]) -> "Resolver":
        res = cls()
        if not feed_dir or not os.path.isdir(feed_dir):
            return res
        osv = _read(os.path.join(feed_dir, "osv.json"))
        if isinstance(osv, dict):
            osv = osv.get("vulns") or []
        res.load_osv(osv or [])
        ghsa = _read(os.path.join(feed_dir, "ghsa.json"))
        res.load_ghsa(ghsa or [])
        zd = []
        for p in sorted(glob.glob(os.path.join(feed_dir, "zeroday", "ZDAY-*.json"))):
            rec = _read(p)
            if rec:
                zd.append(rec)
        res.load_zeroday(zd)
        return res


def _read(path: str) -> Any:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError):
        return None


if __name__ == "__main__":
    import argparse
    import sys

    ap = argparse.ArgumentParser(description="Resolve vulnerability identifiers to their canonical id")
    ap.add_argument("ids", nargs="+")
    ap.add_argument("--feeds", default=os.environ.get("DOJO_FEED_DIR"))
    a = ap.parse_args()
    r = Resolver.from_feed_dir(a.feeds)
    canonical, aliases = r.resolve(a.ids)
    json.dump({"input": a.ids, "canonical": canonical, "aliases": aliases}, sys.stdout, indent=2)
    print()
