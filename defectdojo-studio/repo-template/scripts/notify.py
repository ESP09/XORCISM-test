"""Notifications: internal SMTP relay (STARTTLS enforced) by default, Amazon SES with one setting.

    notifications.transport = "smtp" | "ses"

SMTP: connects to ``smtpHost:smtpPort`` (587), issues EHLO and *requires* the server to advertise
STARTTLS - the message is never sent in clear text. The relay certificate is verified with the
combined CA bundle. Optional AUTH uses ``SMTP_USERNAME`` / ``SMTP_PASSWORD`` (ESO secret).
SES: ``aws sesv2 send-email`` through the FIPS endpoint (``AWS_USE_FIPS_ENDPOINT=true``).
"""
from __future__ import annotations

import json
import os
import smtplib
import sys
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from typing import Any, Dict, List, Optional

from common import AutomationError, aws_cli, cfg_get, emit, load_config, log, ssl_context


def _recipients(cfg: Dict[str, Any], to: Optional[List[str]]) -> List[str]:
    r = to or cfg_get(cfg, "notifications.to", []) or []
    if isinstance(r, str):
        r = [x.strip() for x in r.split(",") if x.strip()]
    if not r:
        raise AutomationError("notifications.to is empty")
    return r


def send_smtp(cfg: Dict[str, Any], subject: str, body: str, to: List[str], html: Optional[str] = None) -> Dict[str, Any]:
    host = cfg_get(cfg, "notifications.smtpHost")
    port = int(cfg_get(cfg, "notifications.smtpPort", 587))
    sender = cfg_get(cfg, "notifications.from")
    msg = EmailMessage()
    msg["Subject"], msg["From"], msg["To"] = subject, sender, ", ".join(to)
    msg["Date"], msg["Message-ID"] = formatdate(localtime=False), make_msgid(domain=(sender or "x@local").split("@")[-1])
    msg.set_content(body)
    if html:
        msg.add_alternative(html, subtype="html")
    ctx = ssl_context()
    require = bool(cfg_get(cfg, "notifications.requireStartTls", True))
    with smtplib.SMTP(host, port, timeout=30) as s:
        s.ehlo()
        if s.has_extn("starttls"):
            s.starttls(context=ctx)
            s.ehlo()
            tls = True
        elif require:
            raise AutomationError(f"SMTP relay {host}:{port} does not offer STARTTLS; refusing to send in clear text")
        else:
            tls = False
        user, pw = os.environ.get("SMTP_USERNAME"), os.environ.get("SMTP_PASSWORD")
        if user and pw:
            if not tls:
                raise AutomationError("refusing SMTP AUTH without TLS")
            s.login(user, pw)
        refused = s.send_message(msg)
    log("notify.smtp", host=host, port=port, starttls=tls, to=len(to))
    return {"transport": "smtp", "host": host, "port": port, "starttls": tls, "refused": list(refused or {}), "to": to}


def send_ses(cfg: Dict[str, Any], subject: str, body: str, to: List[str], html: Optional[str] = None) -> Dict[str, Any]:
    content: Dict[str, Any] = {"Simple": {"Subject": {"Data": subject}, "Body": {"Text": {"Data": body}}}}
    if html:
        content["Simple"]["Body"]["Html"] = {"Data": html}
    args = ["sesv2", "send-email", "--from-email-address", cfg_get(cfg, "notifications.from"),
            "--destination", json.dumps({"ToAddresses": to}), "--content", json.dumps(content)]
    if cfg_get(cfg, "notifications.sesConfigurationSet"):
        args += ["--configuration-set-name", cfg_get(cfg, "notifications.sesConfigurationSet")]
    res = aws_cli(args, cfg)
    return {"transport": "ses", "messageId": (res or {}).get("MessageId"), "to": to}


def send(cfg: Dict[str, Any], subject: str, body: str, to: Optional[List[str]] = None, html: Optional[str] = None) -> Dict[str, Any]:
    transport = cfg_get(cfg, "notifications.transport", "smtp")
    rcpt = _recipients(cfg, to)
    if transport == "ses":
        return send_ses(cfg, subject, body, rcpt, html)
    if transport == "smtp":
        return send_smtp(cfg, subject, body, rcpt, html)
    if transport == "disabled":
        return {"transport": "disabled"}
    raise AutomationError(f"unknown notifications.transport {transport}")


def digest_body(summary: Dict[str, Any]) -> str:
    lines = ["DefectDojo vulnerability digest", "=" * 34, ""]
    for k, v in summary.items():
        lines.append(f"{k}: {v}")
    lines += ["", "Details are available in DefectDojo (internal ALB) and the GitLab Pages dashboard.",
              "Sensitive finding details are intentionally omitted from email."]
    return "\n".join(lines)


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="Send a notification via SMTP relay (STARTTLS) or SES")
    ap.add_argument("--subject", required=True)
    ap.add_argument("--body", default="")
    ap.add_argument("--body-file")
    ap.add_argument("--to", action="append")
    a = ap.parse_args()
    body = open(a.body_file, encoding="utf-8").read() if a.body_file else a.body
    try:
        emit(send(load_config(), a.subject, body, a.to))
    except (AutomationError, smtplib.SMTPException, OSError) as e:
        sys.stderr.write(json.dumps({"error": str(e)}) + "\n")
        sys.exit(2)
