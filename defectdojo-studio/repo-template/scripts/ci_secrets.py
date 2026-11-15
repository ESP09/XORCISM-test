"""Fetch job secrets from AWS Secrets Manager at job start (nothing stored in GitLab CI/CD variables).

The job authenticates with GitLab OIDC (``id_tokens``) -> ``aws sts assume-role-with-web-identity``
(see ci/defectdojo-jobs.gitlab-ci.yml), then::

    eval "$(python3 scripts/ci_secrets.py DD_API_TOKEN=defectdojo/automation:DD_API_TOKEN JIRA_PAT=defectdojo/jira:pat)"

Each mapping is ``ENV=secret-id[:json-key]``. Values are emitted as shell ``export`` lines, quoted
with ``shlex.quote``; they live only in the job's process environment.
"""
from __future__ import annotations

import json
import shlex
import sys

from common import AutomationError, aws_cli


def fetch(mapping: str) -> str:
    env, _, ref = mapping.partition("=")
    secret_id, _, key = ref.partition(":")
    res = aws_cli(["secretsmanager", "get-secret-value", "--secret-id", secret_id, "--query", "SecretString"], None)
    value = res if isinstance(res, str) else json.dumps(res)
    if key:
        value = json.loads(value)[key]
    return f"export {env}={shlex.quote(str(value))}"


if __name__ == "__main__":
    try:
        for m in sys.argv[1:]:
            print(fetch(m))
    except (AutomationError, KeyError, json.JSONDecodeError) as e:
        sys.stderr.write(f"ci_secrets: {e}\n")
        sys.exit(2)
