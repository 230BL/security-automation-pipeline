"""DefectDojo API v2 client for import/reimport workflows.

Key pattern: use reimport-scan with auto_create_context so the same code path
handles both first imports and recurring uploads.
"""

from __future__ import annotations

import json
import logging
import mimetypes
from pathlib import Path
from typing import Any

import requests

from src.orchestrator.exceptions import DefectDojoError

LOG = logging.getLogger(__name__)

SCAN_TYPE_MAP: dict[str, str] = {
    "nmap": "Nmap Scan",
    "greenbone": "OpenVAS CSV",
    "zap": "ZAP Scan",
    "nikto": "Nikto Scan",
    "wazuh": "Wazuh",
    "wazuh_sca": "Wazuh",
    "prowler": "Prowler",
    "nuclei": "Nuclei Scan",
    "lynis": "Generic Findings Import",
    "generic": "Generic Findings Import",
}


class DefectDojoClient:
    """DefectDojo API v2 client."""

    def __init__(
        self,
        base_url: str,
        api_token: str,
        timeout: int = 60,
        verify_ssl: bool = True,
        default_product_type_name: str = "Security Automation",
    ):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.default_product_type_name = default_product_type_name

        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Token {api_token}",
                "Accept": "application/json",
            }
        )

    def _url(self, path: str) -> str:
        return f"{self.base_url}/api/v2/{path.lstrip('/')}"

    @staticmethod
    def _stringify_bool(value: bool) -> str:
        return "true" if value else "false"

    @staticmethod
    def _coerce_scalar(value: Any) -> str:
        if isinstance(value, bool):
            return "true" if value else "false"
        return str(value)

    def _extract_error_detail(self, resp: requests.Response) -> str:
        try:
            payload = resp.json()
            detail = json.dumps(payload, ensure_ascii=False)
        except ValueError:
            detail = resp.text

        detail = (detail or "").strip()
        if len(detail) > 2000:
            detail = detail[:2000] + "...[truncated]"
        return detail or "<empty response body>"

    def _raise_for_status_with_detail(self, resp: requests.Response, context: str) -> None:
        try:
            resp.raise_for_status()
        except requests.HTTPError as exc:
            detail = self._extract_error_detail(resp)
            raise DefectDojoError(
                f"{context} failed: HTTP {resp.status_code} {resp.reason}; response={detail}"
            ) from exc

    def _get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        try:
            resp = self.session.get(
                self._url(path),
                params=params,
                timeout=self.timeout,
                verify=self.verify_ssl,
            )
            self._raise_for_status_with_detail(resp, f"GET {path}")
            data = resp.json()
            if not isinstance(data, dict):
                raise DefectDojoError(f"GET {path} returned non-object JSON")
            return data
        except requests.RequestException as exc:
            raise DefectDojoError(f"GET {path} failed: {exc}") from exc

    def _post_json(self, path: str, data: dict[str, Any]) -> dict[str, Any]:
        try:
            resp = self.session.post(
                self._url(path),
                json=data,
                timeout=self.timeout,
                verify=self.verify_ssl,
            )
            self._raise_for_status_with_detail(resp, f"POST {path}")
            out = resp.json()
            if not isinstance(out, dict):
                raise DefectDojoError(f"POST {path} returned non-object JSON")
            return out
        except requests.RequestException as exc:
            raise DefectDojoError(f"POST {path} failed: {exc}") from exc

    def _post_multipart(
        self,
        path: str,
        data: dict[str, Any],
        files: dict[str, Any],
    ) -> dict[str, Any]:
        form_data = {k: self._coerce_scalar(v) for k, v in data.items() if v is not None}
        try:
            resp = self.session.post(
                self._url(path),
                data=form_data,
                files=files,
                timeout=self.timeout * 3,
                verify=self.verify_ssl,
            )
            self._raise_for_status_with_detail(resp, f"POST multipart {path}")
            out = resp.json()
            if not isinstance(out, dict):
                raise DefectDojoError(f"POST multipart {path} returned non-object JSON")
            return out
        except requests.RequestException as exc:
            raise DefectDojoError(f"POST multipart {path} failed: {exc}") from exc

    def get_or_create_product(self, name: str, prod_type_id: int = 1) -> int:
        result = self._get("products/", params={"name": name, "limit": 1})
        results = result.get("results", [])
        if isinstance(results, list) and results:
            product_id = int(results[0]["id"])
            LOG.info("Found existing product '%s' (id=%d)", name, product_id)
            return product_id

        created = self._post_json(
            "products/",
            {
                "name": name,
                "prod_type": prod_type_id,
                "description": f"Auto-created by security-automation pipeline for {name}",
            },
        )
        product_id = int(created["id"])
        LOG.info("Created product '%s' (id=%d)", name, product_id)
        return product_id

    def get_or_create_engagement(
        self,
        product_id: int,
        name: str,
        target_start: str = "2025-01-01",
        target_end: str = "2030-12-31",
    ) -> int:
        result = self._get(
            "engagements/",
            params={"product": product_id, "name": name, "limit": 1},
        )
        results = result.get("results", [])
        if isinstance(results, list) and results:
            eng_id = int(results[0]["id"])
            LOG.info("Found existing engagement '%s' (id=%d)", name, eng_id)
            return eng_id

        created = self._post_json(
            "engagements/",
            {
                "name": name,
                "product": product_id,
                "target_start": target_start,
                "target_end": target_end,
                "engagement_type": "CI/CD",
                "status": "In Progress",
            },
        )
        eng_id = int(created["id"])
        LOG.info("Created engagement '%s' (id=%d)", name, eng_id)
        return eng_id

    def find_test(self, engagement_id: int, title: str, scan_type: str) -> int | None:
        result = self._get(
            "tests/",
            params={
                "engagement": engagement_id,
                "title": title,
                "scan_type": scan_type,
                "limit": 1,
            },
        )
        results = result.get("results", [])
        if isinstance(results, list) and results:
            return int(results[0]["id"])
        return None

    def import_scan(
        self,
        product_name: str,
        engagement_name: str,
        scan_type: str,
        file_path: Path,
        test_title: str,
        environment: str = "Development",
        close_old_findings: bool = True,
        minimum_severity: str = "Info",
        active: bool = True,
        verified: bool = True,
        do_not_reactivate: bool = False,
        product_type_name: str | None = None,
    ) -> dict[str, Any]:
        """
        Use reimport-scan with name-based auto_create_context.

        Per DefectDojo docs, this path handles both first uploads and recurring
        uploads without the caller needing to know whether a Test already exists.
        """
        if not file_path.exists():
            raise DefectDojoError(f"Import file does not exist: {file_path}")

        product_type = product_type_name or self.default_product_type_name
        content_type = mimetypes.guess_type(file_path.name)[0] or "application/octet-stream"

        data = {
            "scan_type": scan_type,
            "test_title": test_title,
            "product_type_name": product_type,
            "product_name": product_name,
            "engagement_name": engagement_name,
            "auto_create_context": True,
            "environment": environment,
            "minimum_severity": minimum_severity,
            "active": active,
            "verified": verified,
            "close_old_findings": close_old_findings,
            "do_not_reactivate": do_not_reactivate,
        }

        with file_path.open("rb") as f:
            LOG.info(
                "Import/reimport via reimport-scan: product='%s' engagement='%s' test='%s' scan_type='%s'",
                product_name,
                engagement_name,
                test_title,
                scan_type,
            )
            result = self._post_multipart(
                "reimport-scan/",
                data=data,
                files={"file": (file_path.name, f, content_type)},
            )

        affected: dict[str, Any] = {}
        if isinstance(result, dict):
            test_import = result.get("test_import", {})
            if isinstance(test_import, dict):
                findings_affected = test_import.get("findings_affected", {})
                if isinstance(findings_affected, dict):
                    affected = findings_affected

        LOG.info(
            "Import complete: created=%d closed=%d reactivated=%d untouched=%d",
            int(affected.get("created", 0) or 0),
            int(affected.get("closed", 0) or 0),
            int(affected.get("reactivated", 0) or 0),
            int(affected.get("untouched", 0) or 0),
        )
        return result

    def import_tool_results(
        self,
        product_name: str,
        engagement_name: str,
        tool: str,
        file_path: Path,
        environment: str = "Development",
    ) -> dict[str, Any]:
        scan_type = SCAN_TYPE_MAP.get(tool)
        if not scan_type:
            raise DefectDojoError(f"No DefectDojo scan_type mapping for tool: {tool}")

        return self.import_scan(
            product_name=product_name,
            engagement_name=engagement_name,
            scan_type=scan_type,
            file_path=file_path,
            test_title=f"{tool} - recurring",
            environment=environment,
        )
