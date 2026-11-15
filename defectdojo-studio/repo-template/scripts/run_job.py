"""Ephemeral CronJob wrapper: restore automation state from the SSE-KMS S3 state bucket, run one
automation module, then persist state back. Pods keep nothing locally (read-only root FS; /work is
an emptyDir), so every run is reproducible and auditable.

    run_job.py <module> [args...]        e.g. run_job.py jira_sync    |  run_job.py sync_feeds sync
"""
from __future__ import annotations

import os
import runpy
import sys

from common import AutomationError, aws_cli, cfg_get, load_config, log, state_dir

ALLOWED = {"sync_feeds", "intake", "enrich", "jira_sync", "nvd_backfill", "metrics", "confluence", "notify"}


def main() -> int:
    if len(sys.argv) < 2 or sys.argv[1] not in ALLOWED:
        sys.stderr.write(f"usage: run_job.py <{'|'.join(sorted(ALLOWED))}> [args...]\n")
        return 64
    cfg = load_config()
    bucket = cfg_get(cfg, "aws.stateBucket")
    kms = cfg_get(cfg, "aws.kmsKeyArn") or cfg_get(cfg, "aws.kmsKeyAlias")
    sd = state_dir(cfg)
    remote = f"s3://{bucket}/automation-state/"
    if bucket:
        aws_cli(["s3", "sync", remote, sd, "--only-show-errors"], cfg, capture_json=False)
    module = sys.argv[1]
    sys.argv = [module + ".py"] + sys.argv[2:]
    code = 0
    try:
        runpy.run_module(module, run_name="__main__")
    except SystemExit as e:
        code = int(e.code or 0)
    finally:
        if bucket:
            aws_cli(["s3", "sync", sd, remote, "--sse", "aws:kms", "--sse-kms-key-id", kms, "--only-show-errors",
                     "--exclude", "*.tmp"], cfg, capture_json=False)
    log("job.done", module=module, exit=code)
    return code


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AutomationError as e:
        sys.stderr.write(f"run_job: {e}\n")
        sys.exit(2)
