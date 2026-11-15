# DefectDojo

`defectdojo` · **import** connector · category **Vulnerability Management**

Imports findings from an open-source DefectDojo instance (https://github.com/DefectDojo/django-DefectDojo), e.g. the AWS GovCloud deployment produced by the DefectDojo Pro IaC Studio (ESP09/vuln-mgmt-comp1-IaC). Each DefectDojo Product (software) becomes an ASSET tagged with its Product Type (platform); each finding becomes a vulnerability mapped by its canonical CVE (CVE > ZDAY > GHSA), with severity, CVSS v3, EPSS and CISA KEV flags preserved, and affected components recorded. Live mode: read-only GET /api/v2/findings/ (paginated, related_fields) with an API token from the DD_API_TOKEN worker env; HTTPS only with full TLS verification (SSL_CERT_FILE / REQUESTS_CA_BUNDLE for an internal CA) and the standard HTTPS_PROXY / NO_PROXY variables. Offline mode: parse a saved findings JSON export. Duplicates, false positives and out-of-scope findings are skipped. Stdlib only; no DB access in run.py (worker-safe).

**Upstream:** https://github.com/DefectDojo/django-DefectDojo

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `url` | string | no | — | DefectDojo base URL, e.g. https://dojo.example.gov (or DD_URL in the worker env). HTTPS only. |
| `file` | file | no | — | Offline mode: a saved findings export (GET /api/v2/findings/?related_fields=true JSON, a single page or a list of findings). |
| `product` | string | no | — | Only import findings of this DefectDojo Product (software) name. |
| `include_mitigated` | bool | no | `False` | Also import mitigated/inactive findings (default: active only). |
| `min_severity` | string | no | `Info` | Minimum severity to import: Critical, High, Medium, Low or Info. |
| `limit` | int | no | `5000` | Maximum number of findings to read in live mode. |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *DefectDojo*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:defectdojo`.
- **Self-test** — parse **and import** the bundled `sample.json` (no live tool):

  ```bash
  python connectors/runner.py --selftest connectors/defectdojo/sample.json --connector defectdojo
  ```
  > Note: `--selftest` writes to the database. Use a throwaway `XORCISM_DB_DIR` to avoid touching live data.

## Secrets & configuration

API keys and other secrets are read from the **worker environment** — never entered in the XORCISM UI. See the description above for the exact variable names.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
