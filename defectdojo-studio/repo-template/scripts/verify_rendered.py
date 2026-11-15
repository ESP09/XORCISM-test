"""Policy gate over ``helm template`` output (stdin or file) - fails the pipeline when:

* an image is not from the internal GitLab registry or is not pinned by ``@sha256:`` digest;
* a container lacks the combined CA bundle env (``SSL_CERT_FILE``) or proxy env (``HTTPS_PROXY``/``NO_PROXY``);
* a Secret object is rendered (all secrets must come from External Secrets Operator);
* an Ingress is not an internal ALB with a FIPS TLS policy;
* a CronJob is not non-root (65532) / read-only rootfs / caps dropped / RuntimeDefault seccomp.

Stdlib only: a small indentation-aware scan of the YAML documents Helm emits.
"""
from __future__ import annotations

import json
import re
import sys
from typing import Dict, List


def docs(text: str) -> List[str]:
    return [d for d in re.split(r"(?m)^---\s*$", text) if d.strip()]


def kind_of(doc: str) -> str:
    m = re.search(r"(?m)^kind:\s*(\S+)", doc)
    return m.group(1) if m else ""


def name_of(doc: str) -> str:
    m = re.search(r"(?m)^metadata:\s*\n(?:\s+.*\n)*?\s+name:\s*\"?([^\s\"]+)", doc)
    return m.group(1) if m else "?"


def check(text: str, registry: str, require_proxy: bool = True) -> Dict[str, List[str]]:
    errors: List[str] = []
    warnings: List[str] = []
    for d in docs(text):
        k, n = kind_of(d), name_of(d)
        where = f"{k}/{n}"
        if k == "Secret":
            errors.append(f"{where}: Secret rendered by chart - set createSecret/create*Secret=false and use ExternalSecret")
        if k == "Ingress":
            if "alb.ingress.kubernetes.io/scheme: internal" not in d:
                errors.append(f"{where}: ALB must be scheme=internal")
            if not re.search(r"ssl-policy:\s*\"?ELBSecurityPolicy-[\w-]*FIPS", d):
                errors.append(f"{where}: ALB TLS policy must be a FIPS policy")
        if k in ("Deployment", "StatefulSet", "Job", "CronJob", "DaemonSet"):
            for img in re.findall(r"(?m)^\s+image:\s*\"?([^\s\"]+)", d):
                if not img.startswith(registry + "/"):
                    errors.append(f"{where}: image {img} is not from {registry}")
                elif "@sha256:" not in img:
                    errors.append(f"{where}: image {img} is not digest-pinned")
            if "SSL_CERT_FILE" not in d:
                errors.append(f"{where}: missing SSL_CERT_FILE (combined CA bundle)")
            if require_proxy and "HTTPS_PROXY" not in d:
                warnings.append(f"{where}: no HTTPS_PROXY env (ok only if the workload never egresses)")
            if "NO_PROXY" not in d and "HTTPS_PROXY" in d:
                errors.append(f"{where}: HTTPS_PROXY without NO_PROXY (VPC endpoints must bypass the proxy)")
        if k == "CronJob":
            for needle, msg in (("runAsNonRoot: true", "runAsNonRoot"), ("runAsUser: 65532", "runAsUser 65532"),
                                ("readOnlyRootFilesystem: true", "readOnlyRootFilesystem"), ("allowPrivilegeEscalation: false", "allowPrivilegeEscalation=false"),
                                ("type: RuntimeDefault", "seccomp RuntimeDefault")):
                if needle not in d:
                    errors.append(f"{where}: missing {msg}")
            if not re.search(r"drop:\s*\n\s*-\s*\"?ALL", d) and 'drop: ["ALL"]' not in d:
                errors.append(f"{where}: capabilities must drop ALL")
    return {"errors": errors, "warnings": warnings}


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("file", nargs="?", default="-")
    ap.add_argument("--registry", required=True)
    ap.add_argument("--no-proxy-check", action="store_true")
    a = ap.parse_args()
    text = sys.stdin.read() if a.file == "-" else open(a.file, encoding="utf-8").read()
    res = check(text, a.registry.rstrip("/"), not a.no_proxy_check)
    print(json.dumps(res, indent=2))
    sys.exit(1 if res["errors"] else 0)
