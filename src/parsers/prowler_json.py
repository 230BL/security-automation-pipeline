"""Parse Prowler JSON/OCSF output into normalized Finding objects."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from src.parsers.models import Finding

LOG = logging.getLogger(__name__)

PROWLER_SEVERITY_MAP: dict[str, str] = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "informational": "Info",
    "info": "Info",
}


def parse_prowler_json(path: Path) -> list[Finding]:
    """Parse Prowler JSON output."""
    if not path.exists():
        LOG.warning("Prowler JSON file not found: %s", path)
        return []

    content = path.read_text(encoding="utf-8").strip()
    if not content:
        LOG.warning("Prowler JSON file is empty: %s", path)
        return []

    items: list[dict[str, object]] = []
    try:
        data = json.loads(content)
        if isinstance(data, list):
            items = [x for x in data if isinstance(x, dict)]
        elif isinstance(data, dict):
            items = [data]
    except json.JSONDecodeError:
        for line_num, line in enumerate(content.splitlines(), start=1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    items.append(obj)
            except json.JSONDecodeError as exc:
                LOG.warning("Skipping malformed JSONL line %d in %s: %s", line_num, path.name, exc)

    findings: list[Finding] = []

    for item in items:
        try:
            status = str(
                item.get("StatusExtended", item.get("status", item.get("Status", "")))
            ).upper()
            if status in ("PASS", "PASSED", "MANUAL"):
                continue

            severity_raw = str(item.get("Severity", item.get("severity", "info"))).lower()
            severity = PROWLER_SEVERITY_MAP.get(severity_raw, "Info")

            finding_info = item.get("finding_info")
            finding_info_dict = finding_info if isinstance(finding_info, dict) else {}

            check_id = str(
                item.get("CheckID", item.get("check_id", finding_info_dict.get("uid", "")))
            )
            title = str(
                item.get(
                    "CheckTitle",
                    item.get("check_title", finding_info_dict.get("title", "")),
                )
            )
            description = str(
                item.get("Description", item.get("description", item.get("StatusExtended", "")))
            )

            remediation_obj = item.get("Remediation", {})
            remediation = ""
            if isinstance(remediation_obj, dict):
                rec = remediation_obj.get(
                    "Recommendation", remediation_obj.get("recommendation", {})
                )
                if isinstance(rec, dict):
                    remediation = str(rec.get("Text", rec.get("text", "")))
                else:
                    remediation = str(rec) if rec else ""
            elif remediation_obj:
                remediation = str(remediation_obj)

            resource_id = str(
                item.get("ResourceId", item.get("resource_uid", item.get("ResourceArn", "unknown")))
            )
            region = str(item.get("Region", item.get("region", "")))
            provider = str(item.get("Provider", item.get("provider", "")))
            account_id = str(item.get("AccountId", item.get("account_uid", "")))
            service = str(item.get("ServiceName", item.get("service_name", "")))

            asset_id = account_id or resource_id

            findings.append(
                Finding(
                    tool="prowler",
                    asset_id=asset_id,
                    endpoint=resource_id,
                    title=f"{check_id}: {title}" if check_id else (title or "Prowler finding"),
                    severity=severity,
                    description=description,
                    evidence=(
                        f"Resource: {resource_id}, Region: {region}, Provider: {provider}, "
                        f"Service: {service}"
                    ),
                    vuln_id=check_id or None,
                    remediation=remediation or None,
                    tags=["cloud-posture", provider.lower()] if provider else ["cloud-posture"],
                )
            )
        except Exception as exc:
            LOG.warning("Skipping malformed Prowler entry in %s: %s", path.name, exc)
            continue

    LOG.info("Parsed %d findings from Prowler: %s", len(findings), path.name)
    return findings
