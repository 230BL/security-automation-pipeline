"""Parse Nuclei JSONL output into normalized Finding objects."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from src.parsers.models import Finding

LOG = logging.getLogger(__name__)

NUCLEI_SEVERITY_MAP: dict[str, str] = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
    "unknown": "Info",
}


def _as_string_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    if isinstance(value, list):
        return [str(item) for item in value if item is not None]
    return []


def _extract_cve(info: dict[str, Any]) -> str | None:
    references = info.get("reference", [])
    for ref in _as_string_list(references):
        if ref.upper().startswith("CVE-"):
            return ref

    classification = info.get("classification", {})
    if isinstance(classification, dict):
        cve_ids = classification.get("cve-id", [])
        cve_list = _as_string_list(cve_ids)
        if cve_list:
            return cve_list[0]

    return None


def _extract_cvss(info: dict[str, Any]) -> float | None:
    classification = info.get("classification", {})
    if not isinstance(classification, dict):
        return None

    cvss_raw = classification.get("cvss-score")
    if cvss_raw is None:
        return None

    try:
        return float(cvss_raw)
    except (ValueError, TypeError):
        return None


def parse_nuclei_jsonl(path: Path) -> list[Finding]:
    """Parse Nuclei JSONL output (one JSON object per line)."""

    if not path.exists():
        LOG.warning("Nuclei JSONL file not found: %s", path)
        return []

    content = path.read_text(encoding="utf-8").strip()
    if not content:
        LOG.info("Nuclei JSONL file has no findings: %s", path)
        return []

    findings: list[Finding] = []

    for line_num, line in enumerate(content.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue

        try:
            item = json.loads(line)
        except json.JSONDecodeError as exc:
            LOG.warning("Skipping malformed JSONL line %d in %s: %s", line_num, path.name, exc)
            continue

        if not isinstance(item, dict):
            continue

        try:
            template_id = str(item.get("template-id", item.get("templateID", "")) or "")
            info = item.get("info", {})
            if not isinstance(info, dict):
                info = {}

            severity_raw = str(info.get("severity", "info")).lower()
            severity = NUCLEI_SEVERITY_MAP.get(severity_raw, "Info")

            name = str(info.get("name", template_id or "Nuclei finding") or "Nuclei finding")
            description = str(info.get("description", "") or "")
            matched_at = item.get("matched-at", item.get("matched", ""))
            matched_at_str = str(matched_at or "")
            host = str(item.get("host", "") or "")
            ip = str(item.get("ip", "") or "")

            extracted = _as_string_list(item.get("extracted-results", []))
            evidence_parts = [f"Matched at: {matched_at_str}"]
            if extracted:
                evidence_parts.append(f"Extracted: {', '.join(extracted[:5])}")

            curl_command = item.get("curl-command", "")
            if curl_command:
                evidence_parts.append(f"Curl: {str(curl_command)[:200]}")

            asset_id = ip or host
            if not asset_id:
                if "://" in matched_at_str:
                    parts = matched_at_str.split("/", 3)
                    asset_id = parts[2] if len(parts) >= 3 and parts[2] else "unknown"
                else:
                    asset_id = "unknown"

            template_tags = _as_string_list(info.get("tags", []))
            remediation = info.get("remediation", info.get("solution"))
            cve = _extract_cve(info)
            cvss_score = _extract_cvss(info)

            if not template_id and not matched_at_str and not host and not ip and not name:
                LOG.warning(
                    "Skipping empty Nuclei entry at line %d in %s",
                    line_num,
                    path.name,
                )
                continue

            findings.append(
                Finding(
                    tool="nuclei",
                    asset_id=str(asset_id),
                    endpoint=matched_at_str or None,
                    title=f"{template_id}: {name}" if template_id else name,
                    severity=severity,
                    description=str(description or name),
                    evidence="\n".join(evidence_parts),
                    vuln_id=template_id or None,
                    cve=cve,
                    cvss=cvss_score,
                    remediation=str(remediation) if remediation else None,
                    tags=["nuclei"] + template_tags[:10],
                )
            )
        except Exception as exc:
            LOG.warning(
                "Skipping malformed Nuclei entry at line %d in %s: %s",
                line_num,
                path.name,
                exc,
            )

    if not findings and content:
        LOG.warning("Nuclei JSONL parsed but produced no findings: %s", path)

    LOG.info("Parsed %d findings from Nuclei: %s", len(findings), path.name)
    return findings
