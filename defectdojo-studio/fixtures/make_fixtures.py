"""Write the simulator's S3-intake tree: <out>/<product>/<platform>/<report>.

Round 1: baseline reports from all default scanners + an Excel engagement workbook.
Round 2: payments-api rescanned after upgrading spring-beans (Spring4Shell fixed -> Jira closes).
Round 3: spring-beans regresses (recurrence -> the same Jira ticket reopens).

    python3 make_fixtures.py --round 1 --out DIR [--xorcism-trivy ../../connectors/trivy/sample.json]
"""
import argparse
import json
import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "repo-template", "scripts"))
from office_templates import COLUMNS, build_xlsx  # noqa: E402


def w(out, rel, data):
    p = os.path.join(out, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "wb" if isinstance(data, bytes) else "w", encoding=None if isinstance(data, bytes) else "utf-8") as fh:
        fh.write(data if isinstance(data, (bytes, str)) else json.dumps(data, indent=2))


def trivy_payments(spring_version):
    vulns = [
        {"VulnerabilityID": "CVE-2021-44228", "PkgName": "org.apache.logging.log4j:log4j-core", "InstalledVersion": "2.14.1", "FixedVersion": "2.15.0",
         "Severity": "CRITICAL", "Title": "log4j-core: Remote code execution in Log4j 2.x (Log4Shell)", "PkgPath": "app/lib/log4j-core-2.14.1.jar"},
        {"VulnerabilityID": "CVE-2023-4863", "PkgName": "libwebp7", "InstalledVersion": "1.2.4-0.2+deb12u0", "FixedVersion": "1.2.4-0.2+deb12u1",
         "Severity": "HIGH", "Title": "libwebp: Heap buffer overflow in WebP Codec"},
        {"VulnerabilityID": "CVE-2023-38545", "PkgName": "curl", "InstalledVersion": "7.88.1-10", "FixedVersion": "8.4.0",
         "Severity": "CRITICAL", "Title": "curl: heap based buffer overflow in the SOCKS5 proxy handshake"},
        {"VulnerabilityID": "GHSA-qppj-fm5r-hxr3", "PkgName": "golang.org/x/net", "InstalledVersion": "v0.15.0", "FixedVersion": "0.17.0",
         "Severity": "HIGH", "Title": "HTTP/2 Stream Cancellation Attack", "PkgPath": "usr/local/bin/sidecar"},
    ]
    if spring_version == "5.3.15":
        vulns.append({"VulnerabilityID": "CVE-2022-22965", "PkgName": "org.springframework:spring-beans", "InstalledVersion": "5.3.15",
                      "FixedVersion": "5.3.18", "Severity": "CRITICAL", "Title": "spring-framework: RCE via Data Binding on JDK 9+ (Spring4Shell)",
                      "PkgPath": "app/lib/spring-beans-5.3.15.jar"})
    return {"SchemaVersion": 2, "ArtifactName": "registry.sim/payments-api:2026.11", "ArtifactType": "container_image",
            "Results": [{"Target": "payments-api (debian 12.4)", "Class": "os-pkgs", "Type": "debian", "Vulnerabilities": vulns},
                        {"Target": "Dockerfile", "Class": "config", "Type": "dockerfile", "Misconfigurations": [
                            {"ID": "DS002", "AVDID": "AVD-DS-0002", "Title": "Image user should not be 'root'", "Severity": "HIGH",
                             "Message": "Specify at least 1 USER command in Dockerfile with non-root user as argument",
                             "Resolution": "Add 'USER 65532' to the Dockerfile", "CauseMetadata": {"StartLine": 1}}]}]}


def grype_payments():
    return {"descriptor": {"name": "grype", "version": "0.100.0"}, "source": {"type": "sbom", "target": {"userInput": "sbom:payments-api.cdx.json"}},
            "matches": [
                {"vulnerability": {"id": "GHSA-jfh8-c2jp-5v3q", "severity": "Critical", "fix": {"versions": ["2.15.0"], "state": "fixed"},
                                   "urls": ["https://github.com/advisories/GHSA-jfh8-c2jp-5v3q"], "cvss": [{"metrics": {"baseScore": 10.0}}]},
                 "relatedVulnerabilities": [{"id": "CVE-2021-44228"}],
                 "artifact": {"name": "log4j-core", "version": "2.14.1", "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}},
                {"vulnerability": {"id": "GHSA-599f-7c49-w659", "severity": "Critical", "fix": {"versions": ["1.10.0"], "state": "fixed"}},
                 "relatedVulnerabilities": [{"id": "CVE-2022-42889"}],
                 "artifact": {"name": "commons-text", "version": "1.9", "purl": "pkg:maven/org.apache.commons/commons-text@1.9"}},
            ]}


def cdx_payments():
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "metadata": {"component": {"name": "payments-api", "type": "container"}},
            "components": [{"bom-ref": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", "name": "log4j-core", "group": "org.apache.logging.log4j",
                            "version": "2.14.1", "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"},
                           {"bom-ref": "pkg:maven/org.apache.activemq/activemq-client@5.18.2", "name": "activemq-client", "version": "5.18.2",
                            "purl": "pkg:maven/org.apache.activemq/activemq-client@5.18.2"}],
            "vulnerabilities": [
                {"id": "CVE-2021-44228", "ratings": [{"score": 10.0, "severity": "critical", "method": "CVSSv31"}],
                 "affects": [{"ref": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}]},
                {"id": "CVE-2023-46604", "ratings": [{"score": 9.8, "severity": "critical", "method": "CVSSv31"}], "cwes": [502],
                 "affects": [{"ref": "pkg:maven/org.apache.activemq/activemq-client@5.18.2"}]}]}


def semgrep_identity():
    return {"version": "1.140.0", "errors": [], "paths": {"scanned": ["src"]}, "results": [
        {"check_id": "python.lang.security.audit.formatted-sql-query.formatted-sql-query", "path": "./src/idgw/db/users.py",
         "start": {"line": 88, "col": 9}, "end": {"line": 88, "col": 70},
         "extra": {"message": "Detected possible formatted SQL query. Use parameterized queries instead.", "severity": "ERROR",
                   "metadata": {"cwe": ["CWE-89: Improper Neutralization of Special Elements used in an SQL Command"], "references": ["https://owasp.org/Top10/A03_2021-Injection/"]}}},
        {"check_id": "generic.secrets.security.detected-generic-secret", "path": "src\\idgw\\settings\\local.py",
         "start": {"line": 12, "col": 1}, "end": {"line": 12, "col": 40},
         "extra": {"message": "Generic secret detected in source", "severity": "ERROR", "metadata": {"cwe": ["CWE-798: Use of Hard-coded Credentials"]}}},
        {"check_id": "python.flask.security.audit.debug-enabled", "path": "src/idgw/app.py",
         "start": {"line": 41, "col": 5}, "end": {"line": 41, "col": 30},
         "extra": {"message": "Detected Flask app with debug=True.", "severity": "WARNING", "metadata": {"cwe": ["CWE-489: Active Debug Code"]}}},
    ]}


def zap_identity():
    return {"@programName": "ZAP", "@version": "2.16.1", "site": [{"@name": "https://idgw.internal.sim", "@host": "idgw.internal.sim", "alerts": [
        {"pluginid": "10038", "alert": "Content Security Policy (CSP) Header Not Set", "riskcode": "2", "confidence": "3", "cweid": "693",
         "desc": "<p>Content Security Policy (CSP) is an added layer of security.</p>", "solution": "<p>Set the Content-Security-Policy header.</p>",
         "reference": "<p>https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP</p>",
         "instances": [{"uri": "https://idgw.internal.sim/login?next=%2F", "method": "GET"}, {"uri": "https://idgw.internal.sim/login/", "method": "GET"}]},
        {"pluginid": "10003", "alert": "Vulnerable JS Library", "riskcode": "2", "confidence": "2", "cweid": "1395",
         "desc": "<p>The identified library lodash, version 4.17.15 is vulnerable.</p>", "solution": "<p>Upgrade to the latest version of lodash.</p>",
         "otherinfo": "CVE-2021-23337", "reference": "<p>https://github.com/advisories/GHSA-35jh-r3h4-6jhm</p>",
         "instances": [{"uri": "https://idgw.internal.sim/static/js/lodash.min.js", "method": "GET"}]},
        {"pluginid": "10010", "alert": "Cookie No HttpOnly Flag", "riskcode": "1", "confidence": "2", "cweid": "1004",
         "desc": "<p>A cookie has been set without the HttpOnly flag.</p>", "solution": "<p>Ensure that the HttpOnly flag is set.</p>",
         "instances": [{"uri": "https://idgw.internal.sim/", "method": "GET"}]}]}]}


def wazuh(agent, extra=None):
    items = [{"agent": {"name": agent, "id": "003"}, "package": {"name": "openssh", "version": "8.7p1-34.el9"},
              "vulnerability": {"id": "CVE-2024-6387", "severity": "High", "score": {"base": 8.1}, "description": "regreSSHion race condition in sshd",
                                "reference": "https://access.redhat.com/security/cve/cve-2024-6387"}}]
    return {"data": {"affected_items": items + (extra or []), "total_affected_items": len(items) + len(extra or [])}, "error": 0}


def trivy_grants():
    return {"SchemaVersion": 2, "ArtifactName": "grants-tracker-lambda.zip", "ArtifactType": "filesystem", "Results": [
        {"Target": "requirements.txt", "Class": "lang-pkgs", "Type": "pip", "Vulnerabilities": [
            {"VulnerabilityID": "PYSEC-2023-74", "PkgName": "requests", "InstalledVersion": "2.28.2", "FixedVersion": "2.31.0", "Severity": "MEDIUM",
             "Title": "requests: Unintended leak of Proxy-Authorization header"}]},
        {"Target": "bootstrap", "Class": "lang-pkgs", "Type": "gobinary", "Vulnerabilities": [
            {"VulnerabilityID": "GO-2024-2887", "PkgName": "stdlib", "InstalledVersion": "1.22.2", "FixedVersion": "1.22.4", "Severity": "CRITICAL",
             "Title": "net/netip: Unexpected behavior from Is methods for IPv4-mapped IPv6 addresses"}]}]}


def workbook():
    eng = [["Engagement", "Product", "Platform", "Lead", "Start Date", "End Date", "Assessment Type"],
           ["Q4 Penetration Test", "case-management", "EKS", "red-team", "2026-11-03", "2026-11-12", "Penetration Test"]]
    cover = [["Case Management — Q4 Penetration Test"], ["Executive summary"], ["Overall risk: HIGH"], ["Prepared for the CISO"]]
    rows = [COLUMNS,
            ["Log4Shell in legacy reporting module", "Critical", "CVE-2021-44228", "case-management", "EKS", "org.apache.logging.log4j:log4j-core", "2.14.1", "", "", "", "CWE-502", "10.0", "JNDI lookup reachable from report title field", "Upgrade log4j-core to 2.17.1", "manual", ""],
            ["Token audience not validated by govsso-client", "Critical", "ZDAY-2026-0001", "case-management", "EKS", "govsso-client", "3.1.0", "", "", "", "CWE-287", "", "Cross-application token replay possible", "Apply interim gateway audience check", "manual", ""],
            ["Prototype pollution in @agency/forms", "High", "GHSA-2222-3333-4444", "case-management", "EKS", "@agency/forms", "2.3.0", "", "", "", "CWE-1321", "", "Form schema merge allows __proto__", "Upgrade to 2.4.1", "manual", ""],
            ["Outdated jQuery library", "Medium", "", "case-management", "EKS", "jquery", "3.4.1", "", "", "https://cases.internal.sim/static/jquery.js", "CWE-79", "", "jQuery 3.4.1 served on the case search page", "Upgrade jQuery", "manual", ""],
            ["Missing account lockout", "Medium", "", "case-management", "EKS", "", "", "src/auth/login.ts", "57", "", "CWE-307", "", "No lockout after repeated failures", "Implement lockout + MFA", "manual", ""]]
    return build_xlsx([("Executive Cover", cover, False), ("Engagement", eng, True), ("Findings", rows, True)])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--round", type=int, default=1)
    ap.add_argument("--out", required=True)
    ap.add_argument("--xorcism-trivy")
    a = ap.parse_args()
    out = a.out
    if a.round == 1:
        w(out, "payments-api/EKS/trivy-image.json", trivy_payments("5.3.15"))
        w(out, "payments-api/EKS/grype-sbom.json", grype_payments())
        w(out, "payments-api/EKS/trivy-sbom.cdx.json", cdx_payments())
        w(out, "identity-gateway/EKS/semgrep.json", semgrep_identity())
        w(out, "identity-gateway/EKS/zap.json", zap_identity())
        w(out, "hr-portal/EC2 RHEL 9/wazuh-vulns.json", wazuh("hr-portal-01", [
            {"agent": {"name": "hr-portal-01"}, "package": {"name": "xz", "version": "5.6.0-1"},
             "vulnerability": {"id": "ZDAY-2024-0001", "severity": "Critical", "description": "Backdoored xz upstream tarball (internal bulletin)"}}]))
        w(out, "records-archive/EC2 RHEL 9/wazuh-vulns.json", wazuh("records-archive-02"))
        w(out, "grants-tracker/Lambda/trivy-fs.json", trivy_grants())
        w(out, "case-management/EKS/q4-pentest.xlsx", workbook())
        if a.xorcism_trivy and os.path.isfile(a.xorcism_trivy):
            # Reuse the XORCISM connector sample report (connectors/trivy/sample.json) as another product.
            os.makedirs(os.path.join(out, "public-web", "EKS"), exist_ok=True)
            shutil.copy(a.xorcism_trivy, os.path.join(out, "public-web", "EKS", "xorcism-trivy-sample.json"))
    elif a.round == 2:
        w(out, "payments-api/EKS/trivy-image.json", trivy_payments("5.3.18"))
    elif a.round == 3:
        w(out, "payments-api/EKS/trivy-image.json", trivy_payments("5.3.15"))
    print(json.dumps({"round": a.round, "out": out}))


if __name__ == "__main__":
    main()
