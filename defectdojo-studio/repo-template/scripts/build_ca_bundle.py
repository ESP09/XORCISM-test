"""Build the combined CA bundle (system trust store + internal enterprise CA chain).

The same PEM is used by Helm/kubectl (``--ca-file`` / ``SSL_CERT_FILE``), Python (``SSL_CERT_FILE``),
the AWS CLI (``AWS_CA_BUNDLE``), Git (``GIT_SSL_CAINFO``), Node (``NODE_EXTRA_CA_CERTS``) and GitLab
runners; ``--pkcs12`` additionally emits a Java/Gradle trust store via ``keytool``. TLS verification
is never disabled anywhere - an untrusted endpoint means its CA belongs in this bundle.

    build_ca_bundle.py --internal certs/internal-ca.pem --out /etc/pki/defectdojo/ca-bundle.pem [--pkcs12 truststore.p12]
    eval "$(build_ca_bundle.py --internal certs/internal-ca.pem --out "$CI_PROJECT_DIR/.ca/ca-bundle.pem" --print-env)"
"""
from __future__ import annotations

import os
import re
import shutil
import ssl
import subprocess
import sys
import tempfile
from typing import List

PEM_RE = re.compile(r"-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\s]+?-----END CERTIFICATE-----", re.S)
SYSTEM_CANDIDATES = ["/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt",
                     "/etc/ssl/ca-bundle.pem", "/etc/ssl/cert.pem", "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem"]


def system_bundle() -> str:
    paths = ssl.get_default_verify_paths()
    for p in [os.environ.get("SYSTEM_CA_BUNDLE"), paths.cafile, paths.openssl_cafile, *SYSTEM_CANDIDATES]:
        if p and os.path.isfile(p):
            return p
    raise SystemExit("no system CA bundle found; set SYSTEM_CA_BUNDLE")


def certs(path: str) -> List[str]:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return [m.group(0).strip() for m in PEM_RE.finditer(fh.read())]


def build(internal: List[str], out: str) -> int:
    seen, blocks = set(), []
    for src in [system_bundle(), *internal]:
        found = certs(src)
        if src in internal and not found:
            raise SystemExit(f"{src}: no PEM certificates found")
        for c in found:
            norm = re.sub(r"\s+", "", c)
            if norm not in seen:
                seen.add(norm)
                blocks.append(c)
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        fh.write("\n".join(blocks) + "\n")
    ssl.create_default_context(cafile=out)  # proves the bundle loads
    return len(blocks)


def pkcs12(pem: str, out: str, password: str = "changeit") -> None:
    if not shutil.which("keytool"):
        raise SystemExit("keytool not found (needed for the Gradle/Java trust store)")
    if os.path.exists(out):
        os.remove(out)
    with tempfile.TemporaryDirectory() as tmp:
        for i, c in enumerate(certs(pem)):
            p = os.path.join(tmp, f"{i}.pem")
            open(p, "w").write(c + "\n")
            subprocess.run(["keytool", "-importcert", "-noprompt", "-storetype", "PKCS12", "-keystore", out,
                            "-storepass", password, "-alias", f"ca-{i}", "-file", p], check=True, capture_output=True)


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--internal", action="append", default=[], help="internal CA PEM file(s)")
    ap.add_argument("--out", required=True)
    ap.add_argument("--pkcs12")
    ap.add_argument("--print-env", action="store_true")
    a = ap.parse_args()
    n = build(a.internal, a.out)
    if a.pkcs12:
        pkcs12(a.out, a.pkcs12)
    if a.print_env:
        p = os.path.abspath(a.out)
        for var in ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "AWS_CA_BUNDLE", "GIT_SSL_CAINFO", "NODE_EXTRA_CA_CERTS", "DOJO_CA_BUNDLE", "CURL_CA_BUNDLE"):
            print(f"export {var}='{p}'")
    else:
        print(f"wrote {n} certificates to {a.out}", file=sys.stderr)
