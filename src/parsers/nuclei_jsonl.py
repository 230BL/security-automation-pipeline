"""Parse Nuclei JSONL output into normalized Finding objects."""

from __future__ import annotations

import json
import logging
from pathlib import Path

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


def parse_nuclei_jsonl(path: Path) -> list[Finding]:
    """Parse Nuclei JSONL output (one JSON object per line)."""
    if not path.exists():
        LOG.warning("Nuclei JSONL file not found: %s", path)
        return []

    content = path.read_text(encoding="utf-8").strip()
    if not content:
        LOG.warning("Nuclei JSONL file is empty: %s", path)
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
            template_id = item.get("template-id", item.get("templateID", ""))
            info = item.get("info", {}) if isinstance(item.get("info", {}), dict) else {}
            severity_raw = str(info.get("severity", "info")).lower()
            severity = NUCLEI_SEVERITY_MAP.get(severity_raw, "Info")

            name = info.get("name", template_id or "Nuclei finding")
            description = info.get("description", "")
            matched_at = item.get("matched-at", item.get("matched", ""))
            host = item.get("host", "")
            ip = item.get("ip", "")

            extracted = item.get("extracted-results", [])
            matched_at_str = str(matched_at or "")
            evidence_parts = [f"Matched at: {matched_at_str}"]
            if extracted:
                evidence_parts.append(f"Extracted: {', '.join(str(e) for e in extracted[:5])}")
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

            template_tags = info.get("tags", [])
            if isinstance(template_tags, str):
                template_tags = [t.strip() for t in template_tags.split(",") if t.strip()]
            if not isinstance(template_tags, list):
                template_tags = []

            remediation = info.get("remediation", info.get("solution"))

            references = info.get("reference", [])
            cve = None
            if isinstance(references, list):
                for ref in references:
                    if isinstance(ref, str) and ref.startswith("CVE-"):
                        cve = ref
                        break

            classification = info.get("classification", {})
            if not cve and isinstance(classification, dict):
                cve_list = classification.get("cve-id", [])
                if isinstance(cve_list, list) and cve_list:
                    cve = cve_list[0] or None

            cvss_score = None
            if isinstance(classification, dict):
                cvss_raw = classification.get("cvss-score")
                if cvss_raw is not None:
                    try:
                        cvss_score = float(cvss_raw)
                    except (ValueError, TypeError):
                        cvss_score = None

            findings.append(
                Finding(
                    tool="nuclei",
                    asset_id=str(asset_id),
                    endpoint=matched_at_str or None,
                    title=f"{template_id}: {name}" if template_id else str(name),
                    severity=severity,
                    description=str(description or name),
                    evidence="\n".join(evidence_parts),
                    vuln_id=str(template_id) if template_id else None,
                    cve=cve,
                    cvss=cvss_score,
                    remediation=str(remediation) if remediation else None,
                    tags=["nuclei"] + [str(t) for t in template_tags[:10]],
                )
            )
        except Exception as exc:
            LOG.warning(
                "Skipping malformed Nuclei entry at line %d in %s: %s",
                line_num,
                path.name,
                exc,
            )
            continue

    LOG.info("Parsed %d findings from Nuclei: %s", len(findings), path.name)
    return findings
