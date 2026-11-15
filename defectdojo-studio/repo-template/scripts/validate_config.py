"""Validate config/defectdojo-automation.json (structure + GovCloud/CMMC guardrails). Exit 1 on error."""
from __future__ import annotations

import json
import sys

from common import cfg_get, load_config

REQUIRED = ["aws.region", "aws.intakeBucket", "aws.stateBucket", "aws.kmsKeyAlias", "defectdojo.url",
            "notifications.transport", "feeds.mode", "feeds.feedMaxStalenessHours", "jira.mode"]


def validate(cfg) -> list:
    errs = [f"missing {k}" for k in REQUIRED if cfg_get(cfg, k) in (None, "")]
    if not str(cfg_get(cfg, "aws.region", "")).startswith("us-gov-"):
        errs.append("aws.region must be a GovCloud region")
    if cfg_get(cfg, "aws.useFipsEndpoint") is not True:
        errs.append("aws.useFipsEndpoint must be true")
    if cfg_get(cfg, "notifications.transport") == "smtp" and cfg_get(cfg, "notifications.requireStartTls") is not True:
        errs.append("notifications.requireStartTls must be true")
    if cfg_get(cfg, "jira.mode") not in ("datacenter", "cloud", "disabled"):
        errs.append("jira.mode must be datacenter|cloud|disabled")
    if cfg_get(cfg, "feeds.mode") not in ("online", "offline"):
        errs.append("feeds.mode must be online|offline")
    for k in ("defectdojo.url", "jira.url", "confluence.url"):
        v = str(cfg_get(cfg, k, "") or "")
        if v and not v.startswith("https://"):
            errs.append(f"{k} must use https://")
    return errs


if __name__ == "__main__":
    e = validate(load_config(sys.argv[1] if len(sys.argv) > 1 else None))
    print(json.dumps({"valid": not e, "errors": e}, indent=2))
    sys.exit(1 if e else 0)
