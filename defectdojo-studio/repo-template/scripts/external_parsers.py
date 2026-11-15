"""Office-productivity engagement parsers: CSV, XLSX (multi-sheet), SpreadsheetML 2003 XML, ODS, DOCX.

Security controls (all formats):
  * XXE: any XML part containing ``<!DOCTYPE`` or ``<!ENTITY`` (any case, UTF-8/UTF-16) is rejected
    before it reaches the parser. ``xml.etree`` never resolves external entities, but rejecting the
    declarations also blocks billion-laughs style internal entity expansion.
  * Zip containers (XLSX/ODS/DOCX): entry-count limit, per-entry and total expanded-size limits,
    compression-ratio limit, no absolute/parent paths, and no encrypted entries.
  * Raw upload size limit (``max_upload_bytes``).
Only the standard library is used (``zipfile`` + ``xml.etree.ElementTree`` + ``csv``).
"""
from __future__ import annotations

import csv
import io
import re
import zipfile
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional, Tuple

LIMITS = {
    "max_upload_bytes": 25 * 1024 * 1024,
    "max_zip_entries": 2000,
    "max_entry_bytes": 50 * 1024 * 1024,
    "max_expanded_bytes": 100 * 1024 * 1024,
    "max_ratio": 100,
    "max_rows": 50000,
}

_DTD_RE = re.compile(rb"<!\s*(DOCTYPE|ENTITY)", re.I)

NS = {
    "s": "http://schemas.openxmlformats.org/spreadsheetml/2006/main",
    "r": "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
    "rel": "http://schemas.openxmlformats.org/package/2006/relationships",
    "w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main",
    "ss": "urn:schemas-microsoft-com:office:spreadsheet",
    "office": "urn:oasis:names:tc:opendocument:xmlns:office:1.0",
    "table": "urn:oasis:names:tc:opendocument:xmlns:table:1.0",
    "text": "urn:oasis:names:tc:opendocument:xmlns:text:1.0",
}

# Sheets whose names match this are executive cover / instruction sheets and are skipped.
COVER_SHEET_RE = re.compile(r"(cover|summary|executive|exec|instructions?|read ?me|about|title|legend|toc|contents)", re.I)


class UnsafeDocument(ValueError):
    """Raised when a document violates the XXE / zip-bomb policy."""


def assert_no_dtd(data: bytes, part: str = "document") -> None:
    probe = data
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        try:
            probe = data.decode("utf-16").encode("utf-8")
        except UnicodeDecodeError:
            raise UnsafeDocument(f"{part}: undecodable UTF-16 XML") from None
    if _DTD_RE.search(probe):
        raise UnsafeDocument(f"{part}: XML DOCTYPE/ENTITY declarations are not allowed (XXE protection)")


def safe_xml(data: bytes, part: str = "document") -> ET.Element:
    assert_no_dtd(data, part)
    try:
        return ET.fromstring(data)
    except ET.ParseError as e:
        raise ValueError(f"{part}: malformed XML ({e})") from None


def open_zip(raw: bytes, limits: Optional[Dict[str, int]] = None) -> zipfile.ZipFile:
    lim = dict(LIMITS, **(limits or {}))
    if len(raw) > lim["max_upload_bytes"]:
        raise UnsafeDocument(f"upload exceeds {lim['max_upload_bytes']} bytes")
    try:
        zf = zipfile.ZipFile(io.BytesIO(raw))
    except zipfile.BadZipFile:
        raise ValueError("not a valid OOXML/ODF zip container") from None
    infos = zf.infolist()
    if len(infos) > lim["max_zip_entries"]:
        raise UnsafeDocument(f"zip has {len(infos)} entries (limit {lim['max_zip_entries']})")
    total = 0
    for i in infos:
        name = i.filename
        if name.startswith(("/", "\\")) or ".." in re.split(r"[\\/]", name) or re.match(r"^[A-Za-z]:", name):
            raise UnsafeDocument(f"unsafe zip entry path: {name!r}")
        if i.flag_bits & 0x1:
            raise UnsafeDocument("encrypted zip entries are not allowed")
        if i.file_size > lim["max_entry_bytes"]:
            raise UnsafeDocument(f"zip entry {name} expands to {i.file_size} bytes (limit {lim['max_entry_bytes']})")
        if i.compress_size and i.file_size / max(i.compress_size, 1) > lim["max_ratio"] and i.file_size > 1024 * 1024:
            raise UnsafeDocument(f"zip entry {name} compression ratio exceeds {lim['max_ratio']}:1")
        total += i.file_size
        if total > lim["max_expanded_bytes"]:
            raise UnsafeDocument(f"zip expands beyond {lim['max_expanded_bytes']} bytes")
    return zf


def _read_part(zf: zipfile.ZipFile, name: str) -> bytes:
    """Read with a hard cap (declared sizes can lie)."""
    with zf.open(name) as fh:
        data = fh.read(LIMITS["max_entry_bytes"] + 1)
    if len(data) > LIMITS["max_entry_bytes"]:
        raise UnsafeDocument(f"zip entry {name} exceeds size limit")
    return data


Sheet = Tuple[str, List[List[str]]]


# ── CSV ──────────────────────────────────────────────────────────────────────
def read_csv(raw: bytes) -> List[Sheet]:
    if len(raw) > LIMITS["max_upload_bytes"]:
        raise UnsafeDocument("upload too large")
    text = raw.decode("utf-8-sig", errors="replace")
    try:
        dialect = csv.Sniffer().sniff(text[:4096], delimiters=",;\t|")
    except csv.Error:
        dialect = csv.excel
    rows = [[c.strip() for c in r] for r in csv.reader(io.StringIO(text), dialect)]
    return [("csv", rows[: LIMITS["max_rows"]])]


# ── XLSX ─────────────────────────────────────────────────────────────────────
def _col_index(ref: str) -> int:
    m = re.match(r"([A-Z]+)", ref.upper())
    n = 0
    for ch in m.group(1) if m else "A":
        n = n * 26 + (ord(ch) - 64)
    return n - 1


def read_xlsx(raw: bytes) -> List[Sheet]:
    zf = open_zip(raw)
    names = set(zf.namelist())
    for n in names:
        if n.endswith((".xml", ".rels")):
            assert_no_dtd(_read_part(zf, n), n)
    shared: List[str] = []
    if "xl/sharedStrings.xml" in names:
        root = safe_xml(_read_part(zf, "xl/sharedStrings.xml"), "sharedStrings")
        for si in root.findall("s:si", NS):
            shared.append("".join(t.text or "" for t in si.iter(f"{{{NS['s']}}}t")))
    wb = safe_xml(_read_part(zf, "xl/workbook.xml"), "workbook")
    rels_root = safe_xml(_read_part(zf, "xl/_rels/workbook.xml.rels"), "workbook.rels")
    rels = {r.get("Id"): r.get("Target") for r in rels_root.findall("rel:Relationship", NS)}
    sheets: List[Sheet] = []
    for sh in wb.findall("s:sheets/s:sheet", NS):
        if sh.get("state") in ("hidden", "veryHidden"):
            continue
        target = rels.get(sh.get(f"{{{NS['r']}}}id") or "", "")
        target = target.lstrip("/")
        path = target if target.startswith("xl/") else "xl/" + target
        if path not in names:
            continue
        root = safe_xml(_read_part(zf, path), path)
        rows: List[List[str]] = []
        for row in root.iter(f"{{{NS['s']}}}row"):
            cells: Dict[int, str] = {}
            for c in row.findall("s:c", NS):
                t = c.get("t")
                v = c.find("s:v", NS)
                if t == "s" and v is not None and v.text is not None:
                    val = shared[int(v.text)] if int(v.text) < len(shared) else ""
                elif t == "inlineStr":
                    val = "".join(x.text or "" for x in c.iter(f"{{{NS['s']}}}t"))
                elif t == "b" and v is not None:
                    val = "TRUE" if v.text == "1" else "FALSE"
                else:
                    val = v.text if v is not None and v.text is not None else ""
                cells[_col_index(c.get("r") or "A")] = val.strip()
            if cells:
                width = max(cells) + 1
                rows.append([cells.get(i, "") for i in range(width)])
            if len(rows) >= LIMITS["max_rows"]:
                break
        sheets.append((sh.get("name") or path, rows))
    return sheets


# ── SpreadsheetML 2003 (.xml) ────────────────────────────────────────────────
def read_spreadsheetml(raw: bytes) -> List[Sheet]:
    if len(raw) > LIMITS["max_upload_bytes"]:
        raise UnsafeDocument("upload too large")
    root = safe_xml(raw, "SpreadsheetML")
    sheets: List[Sheet] = []
    for ws in root.findall("ss:Worksheet", NS):
        rows: List[List[str]] = []
        for r in ws.iter(f"{{{NS['ss']}}}Row"):
            vals: List[str] = []
            for c in r.findall("ss:Cell", NS):
                idx = c.get(f"{{{NS['ss']}}}Index")
                if idx and idx.isdigit():
                    while len(vals) < int(idx) - 1:
                        vals.append("")
                d = c.find("ss:Data", NS)
                vals.append("".join(d.itertext()).strip() if d is not None else "")
            rows.append(vals)
        sheets.append((ws.get(f"{{{NS['ss']}}}Name") or "Sheet", rows))
    return sheets


# ── ODS ──────────────────────────────────────────────────────────────────────
def read_ods(raw: bytes) -> List[Sheet]:
    zf = open_zip(raw)
    if "content.xml" not in zf.namelist():
        raise ValueError("ODS: content.xml missing")
    for n in zf.namelist():
        if n.endswith(".xml"):
            assert_no_dtd(_read_part(zf, n), n)
    root = safe_xml(_read_part(zf, "content.xml"), "content.xml")
    T = NS["table"]
    sheets: List[Sheet] = []
    for tbl in root.iter(f"{{{T}}}table"):
        rows: List[List[str]] = []
        for r in tbl.iter(f"{{{T}}}table-row"):
            rep_r = min(int(r.get(f"{{{T}}}number-rows-repeated") or 1), 1000)
            vals: List[str] = []
            for c in r:
                if c.tag not in (f"{{{T}}}table-cell", f"{{{T}}}covered-table-cell"):
                    continue
                rep = min(int(c.get(f"{{{T}}}number-columns-repeated") or 1), 256)
                text = "\n".join("".join(p.itertext()) for p in c.findall("text:p", NS)).strip()
                vals.extend([text] * rep)
            while vals and vals[-1] == "":
                vals.pop()
            if vals:
                rows.extend([vals] * rep_r)
            if len(rows) >= LIMITS["max_rows"]:
                break
        sheets.append((tbl.get(f"{{{T}}}name") or "Sheet", rows))
    return sheets


# ── DOCX (tables + "Key: Value" paragraphs) ──────────────────────────────────
def read_docx(raw: bytes) -> Dict[str, Any]:
    zf = open_zip(raw)
    for n in zf.namelist():
        if n.endswith((".xml", ".rels")):
            assert_no_dtd(_read_part(zf, n), n)
    if "word/document.xml" not in zf.namelist():
        raise ValueError("DOCX: word/document.xml missing")
    root = safe_xml(_read_part(zf, "word/document.xml"), "document.xml")
    W = NS["w"]
    tables: List[Sheet] = []
    for i, tbl in enumerate(root.iter(f"{{{W}}}tbl")):
        rows = []
        for tr in tbl.findall("w:tr", NS):
            rows.append(["".join(t.text or "" for t in tc.iter(f"{{{W}}}t")).strip() for tc in tr.findall("w:tc", NS)])
        tables.append((f"table{i + 1}", rows))
    paragraphs: List[str] = []
    body = root.find("w:body", NS)
    for p in (body.findall("w:p", NS) if body is not None else []):
        txt = "".join(t.text or "" for t in p.iter(f"{{{W}}}t")).strip()
        if txt:
            paragraphs.append(txt)
    return {"tables": tables, "paragraphs": paragraphs}


def read_any(name: str, raw: bytes) -> Dict[str, Any]:
    """Dispatch on extension *and* magic bytes. Returns {"format", "sheets", "paragraphs"}."""
    n = name.lower()
    is_zip = raw[:4] == b"PK\x03\x04"
    if n.endswith(".csv") or n.endswith(".tsv"):
        return {"format": "csv", "sheets": read_csv(raw), "paragraphs": []}
    if n.endswith((".xlsx", ".xlsm")) and is_zip:
        return {"format": "xlsx", "sheets": read_xlsx(raw), "paragraphs": []}
    if n.endswith(".ods") and is_zip:
        return {"format": "ods", "sheets": read_ods(raw), "paragraphs": []}
    if n.endswith(".docx") and is_zip:
        d = read_docx(raw)
        return {"format": "docx", "sheets": d["tables"], "paragraphs": d["paragraphs"]}
    if n.endswith(".xml"):
        return {"format": "spreadsheetml", "sheets": read_spreadsheetml(raw), "paragraphs": []}
    if is_zip:
        raise ValueError(f"{name}: zip container with unsupported extension")
    raise ValueError(f"{name}: unsupported format (csv, xlsx, xml, ods, docx)")


def is_cover_sheet(name: str, rows: List[List[str]]) -> bool:
    """Executive cover sheets: named like one, or with no row that looks like a findings header."""
    if COVER_SHEET_RE.search(name or "") and not _find_header(rows):
        return True
    return _find_header(rows) is None


HEADER_ALIASES = {
    "title": ["title", "finding", "finding title", "name", "vulnerability", "issue", "summary"],
    "severity": ["severity", "risk", "risk rating", "priority", "criticality", "impact"],
    "cve": ["cve", "cve id", "cve(s)", "vulnerability id", "vuln id", "advisory", "identifier", "ghsa", "id"],
    "asset": ["asset", "host", "hostname", "system", "application", "software", "target", "service", "product"],
    "component": ["component", "package", "library", "software component"],
    "component_version": ["version", "component version", "package version", "installed version"],
    "file_path": ["file", "file path", "path", "location", "source file"],
    "line": ["line", "line number", "lineno"],
    "uri": ["url", "uri", "endpoint"],
    "cwe": ["cwe", "cwe id", "weakness"],
    "description": ["description", "details", "observation", "finding description"],
    "mitigation": ["mitigation", "remediation", "recommendation", "fix", "solution"],
    "cvss_score": ["cvss", "cvss score", "cvss v3", "cvss3", "base score"],
    "scanner": ["scanner", "tool", "source"],
    "platform": ["platform", "environment", "os"],
    "engagement": ["engagement", "assessment", "test"],
    "references": ["references", "reference", "links"],
}


def _canon_header(h: str) -> Optional[str]:
    k = re.sub(r"\s+", " ", h.strip().lower().replace("_", " "))
    for field, aliases in HEADER_ALIASES.items():
        if k in aliases:
            return field
    return None


def _find_header(rows: List[List[str]]) -> Optional[int]:
    for i, r in enumerate(rows[:25]):
        mapped = {_canon_header(c) for c in r if c}
        if "title" in mapped and ("severity" in mapped or "cve" in mapped):
            return i
    return None


def rows_to_records(rows: List[List[str]]) -> List[Dict[str, str]]:
    hi = _find_header(rows)
    if hi is None:
        return []
    header = [_canon_header(c) or ("x_" + re.sub(r"\W+", "_", c.strip().lower())) for c in rows[hi]]
    out: List[Dict[str, str]] = []
    for r in rows[hi + 1:]:
        if not any(c.strip() for c in r):
            continue
        rec: Dict[str, str] = {}
        for j, h in enumerate(header):
            if j < len(r) and r[j].strip():
                rec[h] = r[j].strip()
        if rec.get("title") or rec.get("cve"):
            out.append(rec)
    return out


def _engagement_sheet(rows: List[List[str]]) -> Optional[Dict[str, str]]:
    """A two-row 'Engagement | Product | Platform | ...' sheet carries engagement metadata."""
    for i, r in enumerate(rows[:5]):
        keys = [c.strip().lower() for c in r]
        if keys and keys[0] == "engagement" and "product" in keys and i + 1 < len(rows):
            vals = rows[i + 1]
            return {k.split(" ")[0]: vals[j].strip() for j, k in enumerate(keys) if j < len(vals) and vals[j].strip()}
    return None


def extract_records(name: str, raw: bytes) -> Dict[str, Any]:
    doc = read_any(name, raw)
    records: List[Dict[str, str]] = []
    used, skipped = [], []
    meta: Dict[str, str] = {}
    for sheet_name, rows in doc["sheets"]:
        eng = _engagement_sheet(rows)
        if eng:
            meta.update(eng)
            skipped.append(sheet_name)
            continue
        if is_cover_sheet(sheet_name, rows):
            skipped.append(sheet_name)
            continue
        recs = rows_to_records(rows)
        for r in recs:
            r.setdefault("_sheet", sheet_name)
        records.extend(recs)
        used.append(sheet_name)
    for p in doc.get("paragraphs") or []:
        m = re.match(r"^\s*(Engagement|Product|Application|Software|Platform|Lead|Tester|Start(?: date)?|End(?: date)?|Assessment type)\s*[:\-]\s*(.+)$", p, re.I)
        if m:
            meta[m.group(1).lower().split(" ")[0]] = m.group(2).strip()
    return {"format": doc["format"], "records": records, "sheets_used": used, "sheets_skipped": skipped, "metadata": meta}
