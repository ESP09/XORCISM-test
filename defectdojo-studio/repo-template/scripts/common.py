"""Shared helpers for the DefectDojo GovCloud automation (Python standard library only).

Design rules enforced here:
  * TLS verification is never disabled. Every HTTPS call uses an ``ssl.SSLContext``
    built from the combined system + internal CA bundle (``DOJO_CA_BUNDLE`` /
    ``SSL_CERT_FILE``) with TLS >= 1.2.
  * Outbound traffic honours ``HTTPS_PROXY`` / ``HTTP_PROXY`` / ``NO_PROXY`` (the
    allowlisted forward proxy); AWS VPC endpoints (``.amazonaws.com``) and internal
    domains are listed in ``NO_PROXY`` so they bypass it.
  * AWS access goes through the AWS CLI via ``subprocess`` (no boto3) with
    ``AWS_USE_FIPS_ENDPOINT=true`` and the ``aws-us-gov`` partition region.
  * Secrets are read from the environment (injected by External Secrets Operator in
    Kubernetes, or fetched from AWS Secrets Manager at job start in CI) - never from Git.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import shutil
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Iterable, List, Optional, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(HERE)
DEFAULT_CONFIG = os.path.join(REPO_ROOT, "config", "defectdojo-automation.json")

SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"]
_SEV_ALIASES = {
    "critical": "Critical", "crit": "Critical", "4": "Critical", "very high": "Critical",
    "high": "High", "3": "High", "error": "High",
    "medium": "Medium", "moderate": "Medium", "med": "Medium", "2": "Medium", "warning": "Medium",
    "low": "Low", "1": "Low", "note": "Low", "minor": "Low",
    "info": "Info", "informational": "Info", "information": "Info", "none": "Info", "0": "Info", "unknown": "Info",
    "negligible": "Info",
}


class AutomationError(RuntimeError):
    """Raised for unrecoverable automation failures (non-zero exit)."""


# ── config ───────────────────────────────────────────────────────────────────
def load_config(path: Optional[str] = None) -> Dict[str, Any]:
    path = path or os.environ.get("DOJO_AUTOMATION_CONFIG") or DEFAULT_CONFIG
    with open(path, "r", encoding="utf-8") as fh:
        cfg = json.load(fh)
    if not isinstance(cfg, dict):
        raise AutomationError(f"config {path} must be a JSON object")
    return cfg


def cfg_get(cfg: Dict[str, Any], dotted: str, default: Any = None) -> Any:
    cur: Any = cfg
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]
    return cur


def state_dir(cfg: Optional[Dict[str, Any]] = None) -> str:
    d = os.environ.get("DOJO_STATE_DIR") or cfg_get(cfg or {}, "paths.stateDir") or os.path.join(REPO_ROOT, ".state")
    os.makedirs(d, exist_ok=True)
    return d


# ── logging ──────────────────────────────────────────────────────────────────
def log(event: str, **fields: Any) -> None:
    rec = {"ts": utc_now(), "event": event}
    rec.update(fields)
    sys.stderr.write(json.dumps(rec, default=str, sort_keys=False) + "\n")
    sys.stderr.flush()


def utc_now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_ts(value: str) -> _dt.datetime:
    v = value.strip().replace("Z", "+00:00")
    d = _dt.datetime.fromisoformat(v)
    if d.tzinfo is None:
        d = d.replace(tzinfo=_dt.timezone.utc)
    return d


def normalize_severity(value: Any, default: str = "Info") -> str:
    if value is None:
        return default
    s = str(value).strip()
    if s in SEVERITIES:
        return s
    return _SEV_ALIASES.get(s.lower(), default)


def severity_from_cvss(score: Optional[float]) -> str:
    if score is None:
        return "Info"
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0:
        return "Low"
    return "Info"


# ── files / hashing ──────────────────────────────────────────────────────────
def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def write_json(path: str, data: Any, indent: Optional[int] = 2) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=indent, ensure_ascii=False, sort_keys=False, default=str)
        fh.write("\n")
    os.replace(tmp, path)


def read_json(path: str, default: Any = None) -> Any:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        return default


def emit(data: Any) -> None:
    """Write a machine-readable JSON result to stdout (consumed by CI and the Studio)."""
    sys.stdout.write(json.dumps(data, indent=2, ensure_ascii=False, default=str) + "\n")
    sys.stdout.flush()


# ── TLS / HTTP ───────────────────────────────────────────────────────────────
def ca_bundle_path() -> Optional[str]:
    for var in ("DOJO_CA_BUNDLE", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "AWS_CA_BUNDLE"):
        p = os.environ.get(var)
        if p and os.path.isfile(p):
            return p
    return None


def ssl_context() -> ssl.SSLContext:
    """Verified TLS context. There is deliberately no option to disable verification."""
    ctx = ssl.create_default_context(cafile=ca_bundle_path())
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


_OPENER: Optional[urllib.request.OpenerDirector] = None


def _opener() -> urllib.request.OpenerDirector:
    global _OPENER
    if _OPENER is None:
        # ProxyHandler() with no args reads HTTP(S)_PROXY and honours NO_PROXY.
        _OPENER = urllib.request.build_opener(
            urllib.request.ProxyHandler(),
            urllib.request.HTTPSHandler(context=ssl_context()),
        )
    return _OPENER


class HttpResponse:
    def __init__(self, status: int, headers: Dict[str, str], body: bytes, url: str):
        self.status = status
        self.headers = headers
        self.body = body
        self.url = url

    def json(self) -> Any:
        return json.loads(self.body.decode("utf-8") or "null")

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300


def http_request(method: str, url: str, headers: Optional[Dict[str, str]] = None, body: Optional[bytes] = None,
                 timeout: float = 30.0, retries: int = 3, expect_ok: bool = True) -> HttpResponse:
    hdrs = {"User-Agent": "defectdojo-govcloud-automation/1.0", "Accept": "application/json"}
    hdrs.update(headers or {})
    last_err: Optional[Exception] = None
    for attempt in range(retries):
        req = urllib.request.Request(url, data=body, method=method.upper(), headers=hdrs)
        try:
            with _opener().open(req, timeout=timeout) as resp:
                data = resp.read()
                r = HttpResponse(resp.status, {k.lower(): v for k, v in resp.headers.items()}, data, url)
                return r
        except urllib.error.HTTPError as e:
            data = e.read() if hasattr(e, "read") else b""
            r = HttpResponse(e.code, {k.lower(): v for k, v in (e.headers or {}).items()}, data, url)
            if e.code in (429, 502, 503, 504) and attempt < retries - 1:
                time.sleep(min(2 ** attempt, 8))
                last_err = e
                continue
            if expect_ok:
                raise AutomationError(f"{method} {redact_url(url)} -> HTTP {e.code}: {data[:300]!r}") from None
            return r
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
            last_err = e
            if isinstance(getattr(e, "reason", None), ssl.SSLError):
                raise AutomationError(f"TLS verification failed for {redact_url(url)}: {e.reason}. "
                                      "Add the issuing CA to the combined CA bundle; verification is never disabled.") from None
            if attempt < retries - 1:
                time.sleep(min(2 ** attempt, 8))
                continue
    raise AutomationError(f"{method} {redact_url(url)} failed: {last_err}")


def http_json(method: str, url: str, payload: Any = None, headers: Optional[Dict[str, str]] = None,
              **kw: Any) -> Any:
    h = dict(headers or {})
    body = None
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        h.setdefault("Content-Type", "application/json")
    r = http_request(method, url, headers=h, body=body, **kw)
    return r.json() if r.body else None


def redact_url(url: str) -> str:
    p = urllib.parse.urlsplit(url)
    q = urllib.parse.parse_qsl(p.query, keep_blank_values=True)
    q = [(k, "REDACTED" if k.lower() in ("apikey", "api_key", "token", "key") else v) for k, v in q]
    return urllib.parse.urlunsplit((p.scheme, p.hostname or "", p.path, urllib.parse.urlencode(q), ""))


def multipart(fields: Dict[str, str], files: Dict[str, Tuple[str, bytes, str]]) -> Tuple[bytes, str]:
    boundary = "----dojo" + hashlib.sha256(os.urandom(16)).hexdigest()[:24]
    out: List[bytes] = []
    for k, v in fields.items():
        out.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n".encode())
    for k, (fname, data, ctype) in files.items():
        out.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"; filename=\"{fname}\"\r\n"
                   f"Content-Type: {ctype}\r\n\r\n".encode() + data + b"\r\n")
    out.append(f"--{boundary}--\r\n".encode())
    return b"".join(out), f"multipart/form-data; boundary={boundary}"


# ── AWS CLI (subprocess, FIPS endpoints, no boto3) ───────────────────────────
def aws_env(cfg: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
    env = dict(os.environ)
    env["AWS_USE_FIPS_ENDPOINT"] = "true"
    env.setdefault("AWS_DEFAULT_REGION", cfg_get(cfg or {}, "aws.region", "us-gov-west-1"))
    env.setdefault("AWS_REGION", env["AWS_DEFAULT_REGION"])
    env["AWS_PAGER"] = ""
    ca = ca_bundle_path()
    if ca:
        env["AWS_CA_BUNDLE"] = ca
    return env


def aws_cli(args: List[str], cfg: Optional[Dict[str, Any]] = None, capture_json: bool = True,
            input_bytes: Optional[bytes] = None) -> Any:
    """Run ``aws <args>``. With DOJO_AWS_DRYRUN=1 (Studio simulator / local dev) the command is
    recorded to ``$DOJO_STATE_DIR/aws-cli.log`` instead of executed."""
    env = aws_env(cfg)
    cmd = ["aws"] + list(args) + ["--region", env["AWS_DEFAULT_REGION"]]
    if capture_json and "--output" not in args:
        cmd += ["--output", "json"]
    if os.environ.get("DOJO_AWS_DRYRUN") == "1":
        with open(os.path.join(state_dir(cfg), "aws-cli.log"), "a", encoding="utf-8") as fh:
            fh.write(json.dumps({"ts": utc_now(), "cmd": cmd, "AWS_USE_FIPS_ENDPOINT": env["AWS_USE_FIPS_ENDPOINT"]}) + "\n")
        log("aws.dryrun", cmd=" ".join(cmd))
        return {} if capture_json else ""
    if not shutil.which("aws"):
        raise AutomationError("AWS CLI v2 not found on PATH")
    proc = subprocess.run(cmd, env=env, input=input_bytes, capture_output=True, check=False, timeout=600)
    if proc.returncode != 0:
        raise AutomationError(f"aws {' '.join(args[:3])} failed ({proc.returncode}): {proc.stderr.decode(errors='replace')[:500]}")
    out = proc.stdout.decode("utf-8", errors="replace")
    if capture_json:
        return json.loads(out) if out.strip() else {}
    return out


def s3_put(local: str, bucket: str, key: str, kms_key: str, cfg: Optional[Dict[str, Any]] = None) -> None:
    aws_cli(["s3", "cp", local, f"s3://{bucket}/{key}", "--sse", "aws:kms", "--sse-kms-key-id", kms_key,
             "--only-show-errors"], cfg, capture_json=False)


def secret_env(name: str, required: bool = True) -> str:
    """Secrets arrive as env vars from an ESO-managed Kubernetes Secret (or CI job bootstrap)."""
    v = os.environ.get(name, "")
    if required and not v:
        raise AutomationError(f"missing secret env {name} (provided by External Secrets Operator / Secrets Manager)")
    return v


def chunked(items: List[Any], n: int) -> Iterable[List[Any]]:
    for i in range(0, len(items), n):
        yield items[i:i + n]
