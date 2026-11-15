"""Generate downloadable engagement templates (.xlsx via hand-written OOXML, and .csv) - stdlib only.

    python3 scripts/office_templates.py --format xlsx --out engagement-template.xlsx
    python3 scripts/office_templates.py --format csv  > engagement-template.csv
"""
from __future__ import annotations

import csv
import io
import sys
import zipfile
from typing import List, Sequence
from xml.sax.saxutils import escape

COLUMNS = ["Title", "Severity", "CVE", "Asset", "Platform", "Component", "Version", "File Path", "Line",
           "URL", "CWE", "CVSS Score", "Description", "Mitigation", "Scanner", "References"]

EXAMPLES = [
    ["Apache Log4j2 JNDI remote code execution", "Critical", "CVE-2021-44228", "payments-api", "EKS",
     "org.apache.logging.log4j:log4j-core", "2.14.1", "", "", "", "CWE-502", "10.0",
     "Log4Shell identified during the manual review of the payments service.",
     "Upgrade log4j-core to 2.17.1 or later.", "manual", "https://logging.apache.org/log4j/2.x/security.html"],
    ["Hard-coded credential in deployment script", "High", "", "hr-portal", "EC2 RHEL 9", "", "",
     "deploy/scripts/bootstrap.sh", "42", "", "CWE-798", "", "Static AWS access key in script.",
     "Remove the key, rotate it and load credentials via IRSA/instance profile.", "manual", ""],
]

INSTRUCTIONS = [
    ["DefectDojo engagement submission template"],
    ["This cover sheet is skipped automatically by the intake parser."],
    [""],
    ["1. Fill in the 'Engagement' sheet (one row)."],
    ["2. Add one row per finding on the 'Findings' sheet. Title and Severity are required."],
    ["3. CVE accepts CVE / GHSA / PYSEC / GO / OSV / ZDAY ids; they are resolved to a canonical CVE."],
    ["4. Severity: Critical, High, Medium, Low or Info."],
    ["5. Submit through the GitLab Pages form or a merge request under submissions/."],
    ["Do not include passwords, keys, or CUI beyond what the finding requires."],
]

ENGAGEMENT = [["Engagement", "Product", "Platform", "Lead", "Start Date", "End Date", "Assessment Type"],
              ["Q4 manual penetration test", "payments-api", "EKS", "security-team", "2026-11-01", "2026-11-14", "Penetration Test"]]


def _col(n: int) -> str:
    s = ""
    n += 1
    while n:
        n, r = divmod(n - 1, 26)
        s = chr(65 + r) + s
    return s


def _sheet_xml(rows: Sequence[Sequence[str]], header: bool = True) -> str:
    out = ['<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
           '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">',
           '<sheetViews><sheetView workbookViewId="0">'
           + ('<pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/>' if header else '')
           + '</sheetView></sheetViews>', '<sheetData>']
    for ri, row in enumerate(rows, start=1):
        cells = []
        for ci, val in enumerate(row):
            style = ' s="1"' if header and ri == 1 else ''
            cells.append(f'<c r="{_col(ci)}{ri}" t="inlineStr"{style}><is><t xml:space="preserve">{escape(str(val))}</t></is></c>')
        out.append(f'<row r="{ri}">' + "".join(cells) + '</row>')
    out.append('</sheetData></worksheet>')
    return "".join(out)


def build_xlsx(sheets: List[tuple]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml",
                   '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                   '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                   '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
                   '<Default Extension="xml" ContentType="application/xml"/>'
                   '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
                   '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
                   + "".join(f'<Override PartName="/xl/worksheets/sheet{i + 1}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>' for i in range(len(sheets)))
                   + '</Types>')
        z.writestr("_rels/.rels",
                   '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                   '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                   '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
                   '</Relationships>')
        z.writestr("xl/workbook.xml",
                   '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                   '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>'
                   + "".join(f'<sheet name="{escape(name)}" sheetId="{i + 1}" r:id="rId{i + 1}"/>' for i, (name, _, _) in enumerate(sheets))
                   + '</sheets></workbook>')
        z.writestr("xl/_rels/workbook.xml.rels",
                   '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                   '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                   + "".join(f'<Relationship Id="rId{i + 1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet{i + 1}.xml"/>' for i in range(len(sheets)))
                   + f'<Relationship Id="rId{len(sheets) + 1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>'
                   '</Relationships>')
        z.writestr("xl/styles.xml",
                   '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                   '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
                   '<fonts count="2"><font><sz val="11"/><name val="Calibri"/></font><font><b/><sz val="11"/><name val="Calibri"/></font></fonts>'
                   '<fills count="2"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill></fills>'
                   '<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>'
                   '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
                   '<cellXfs count="2"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>'
                   '<xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/></cellXfs>'
                   '</styleSheet>')
        for i, (_, rows, header) in enumerate(sheets):
            z.writestr(f"xl/worksheets/sheet{i + 1}.xml", _sheet_xml(rows, header))
    return buf.getvalue()


def template_xlsx() -> bytes:
    return build_xlsx([("Instructions", INSTRUCTIONS, False), ("Engagement", ENGAGEMENT, True),
                       ("Findings", [COLUMNS] + EXAMPLES, True)])


def findings_xlsx(findings: List[dict]) -> bytes:
    rows = [COLUMNS] + [[str(f.get(k, "")) for k in ("title", "severity", "canonical_id", "asset", "platform", "component",
                                                      "component_version", "file_path", "line", "uri", "cwe", "cvss_score",
                                                      "description", "mitigation", "scanner", "references")] for f in findings]
    return build_xlsx([("Findings", rows, True)])


def template_csv() -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(COLUMNS)
    w.writerows(EXAMPLES)
    return buf.getvalue()


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="Generate engagement submission templates")
    ap.add_argument("--format", choices=["xlsx", "csv"], default="xlsx")
    ap.add_argument("--out", default="-")
    a = ap.parse_args()
    data = template_xlsx() if a.format == "xlsx" else template_csv().encode("utf-8")
    if a.out == "-":
        sys.stdout.buffer.write(data)
    else:
        with open(a.out, "wb") as fh:
            fh.write(data)
