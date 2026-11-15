"""Minimal DefectDojo v2 REST client (stdlib only).

Auth: ``Authorization: Token <DD_API_TOKEN>`` - the token comes from the ESO-synced secret.
"""
from __future__ import annotations

import json
import urllib.parse
from typing import Any, Dict, Iterator, List, Optional

from common import AutomationError, cfg_get, http_json, http_request, log, multipart, secret_env


class Dojo:
    def __init__(self, base_url: str, token: str, page_size: int = 250):
        self.base = base_url.rstrip("/")
        self.token = token
        self.page_size = page_size

    @classmethod
    def from_config(cls, cfg: Dict[str, Any]) -> "Dojo":
        url = cfg_get(cfg, "defectdojo.apiUrl") or cfg_get(cfg, "defectdojo.url")
        if not url:
            raise AutomationError("defectdojo.url is not configured")
        return cls(url, secret_env("DD_API_TOKEN"))

    def _h(self) -> Dict[str, str]:
        return {"Authorization": f"Token {self.token}"}

    def url(self, path: str, params: Optional[Dict[str, Any]] = None) -> str:
        u = f"{self.base}/api/v2/{path.strip('/')}/"
        if params:
            u += "?" + urllib.parse.urlencode({k: v for k, v in params.items() if v is not None}, doseq=True)
        return u

    def get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Any:
        return http_json("GET", self.url(path, params), headers=self._h())

    def paginate(self, path: str, params: Optional[Dict[str, Any]] = None) -> Iterator[Dict[str, Any]]:
        p = dict(params or {})
        p.setdefault("limit", self.page_size)
        url: Optional[str] = self.url(path, p)
        while url:
            page = http_json("GET", url, headers=self._h())
            for r in page.get("results") or []:
                yield r
            url = page.get("next")

    def post(self, path: str, payload: Dict[str, Any]) -> Any:
        return http_json("POST", self.url(path), payload, headers=self._h())

    def patch(self, path: str, payload: Dict[str, Any]) -> Any:
        return http_json("PATCH", self.url(path), payload, headers=self._h())

    # ── context ──
    def _first(self, path: str, **params: Any) -> Optional[Dict[str, Any]]:
        res = self.get(path, dict(params, limit=1)).get("results") or []
        return res[0] if res else None

    def ensure_product(self, name: str, product_type: str = "GovCloud Applications", platform: str = "") -> Dict[str, Any]:
        pt = self._first("product_types", name=product_type) or self.post("product_types", {"name": product_type})
        p = self._first("products", name=name)
        if p:
            return p
        tags = [f"platform:{platform}"] if platform else []
        return self.post("products", {"name": name, "description": f"{name} (managed by automation)", "prod_type": pt["id"], "tags": tags})

    # ── imports ──
    def reimport_generic(self, product: str, engagement: str, test_title: str, findings_payload: Dict[str, Any],
                         product_type: str = "GovCloud Applications", close_old: bool = True,
                         tags: Optional[List[str]] = None, scan_type: str = "Generic Findings Import") -> Dict[str, Any]:
        fields = {
            "scan_type": scan_type, "product_type_name": product_type, "product_name": product,
            "engagement_name": engagement, "test_title": test_title, "auto_create_context": "true",
            "close_old_findings": "true" if close_old else "false", "do_not_reactivate": "false",
            "active": "true", "verified": "false", "minimum_severity": "Info",
            "deduplication_on_engagement": "false", "tags": ",".join(tags or []), "apply_tags_to_findings": "true",
        }
        body, ctype = multipart(fields, {"file": ("findings.json", json.dumps(findings_payload).encode(), "application/json")})
        r = http_request("POST", self.url("reimport-scan"), headers=dict(self._h(), **{"Content-Type": ctype}), body=body, timeout=300)
        res = r.json()
        log("dojo.reimport", product=product, engagement=engagement, test=test_title, findings=len(findings_payload.get("findings") or []),
            stats=res.get("statistics"))
        return res

    def findings(self, **filters: Any) -> List[Dict[str, Any]]:
        filters.setdefault("related_fields", "true")
        return list(self.paginate("findings", filters))


def product_of(d: Dict[str, Any]) -> str:
    rf = ((d.get("related_fields") or {}).get("test") or {}).get("engagement") or {}
    return str((rf.get("product") or {}).get("name") or d.get("product_name") or d.get("service") or "unknown")


def engagement_of(d: Dict[str, Any]) -> str:
    rf = ((d.get("related_fields") or {}).get("test") or {}).get("engagement") or {}
    return str(rf.get("name") or d.get("engagement_name") or "unknown")


def platform_of(d: Dict[str, Any]) -> str:
    for t in d.get("tags") or []:
        if t.startswith("platform:"):
            return t.split(":", 1)[1]
    return "unspecified"
