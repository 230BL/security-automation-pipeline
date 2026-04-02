"""Parse Generic Findings Import JSON format.

This format is used for pre-normalized findings and for DefectDojo's
Generic Findings Import parser.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from src.parsers.models import Finding

LOG = logging.getLogger(__name__)


def parse_generic_json(path: Path, tool: str = "generic") -> list[Finding]:
    """Parse generic findings JSON."""
    if not path.exists():
        LOG.warning("Generic JSON file not found: %s", path)
        return []

    content = path.read_text(encoding="utf-8").strip()
    if not content:
        return []

    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        LOG.error("Failed to parse Generic JSON %s: %s", path, exc)
        return []

    if isinstance(data, dict):
        items = data.get("findings", [])
    elif isinstance(data, list):
        items = data
    else:
        items = []

    if not isinstance(items, list):
        return []

    findings: list[Finding] = []

    for item in items:
        if not isinstance(item, dict):
            continue

        try:
            findings.append(
                Finding(
                    tool=str(item.get("tool", tool)),
                    asset_id=str(item["asset_id"]),
                    title=str(item["title"]),
                    severity=str(item["severity"]),
                    description=str(item.get("description", "")),
                    evidence=str(item.get("evidence", "")),
                    endpoint=str(item["endpoint"]) if item.get("endpoint") is not None else None,
                    vuln_id=str(item["vuln_id"]) if item.get("vuln_id") is not None else None,
                    cve=str(item["cve"]) if item.get("cve") is not None else None,
                    cvss=float(item["cvss"]) if item.get("cvss") is not None else None,
                    remediation=(
                        str(item["remediation"]) if item.get("remediation") is not None else None
                    ),
                    tags=[str(tag) for tag in item.get("tags", [])]
                    if isinstance(item.get("tags", []), list)
                    else [],
                )
            )
        except (KeyError, ValueError, TypeError) as exc:
            LOG.warning("Skipping malformed generic finding: %s", exc)

    LOG.info("Parsed %d findings from generic JSON: %s", len(findings), path.name)
    return findings
