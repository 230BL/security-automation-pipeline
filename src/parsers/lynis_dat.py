"""Parse Lynis report-data (.dat) files into normalized Finding objects.

Lynis report files use a key=value format with sections like:
warning[]=check_id|description|details|severity
suggestion[]=check_id|description|details|severity

Some exports may omit the check_id or the severity field.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from src.parsers.models import Finding

LOG = logging.getLogger(__name__)

LYNIS_SEVERITY_MAP: dict[str, str] = {
    "c": "Critical",
    "critical": "Critical",
    "h": "High",
    "high": "High",
    "m": "Medium",
    "medium": "Medium",
    "l": "Low",
    "low": "Low",
    "i": "Info",
    "info": "Info",
    "": "Info",
}

CHECK_ID_RE = re.compile(r"^[A-Z0-9_]+-\d{2,}$")


def parse_lynis_dat(path: Path) -> list[Finding]:
    """Parse Lynis report-data file."""
    if not path.exists():
        LOG.warning("Lynis report file not found: %s", path)
        return []

    content = path.read_text(encoding="utf-8", errors="replace").strip()
    if not content:
        LOG.warning("Lynis report file is empty: %s", path)
        return []

    findings: list[Finding] = []
    hostname = "unknown"
    os_name = ""

    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        if line.startswith("hostname="):
            hostname = line.split("=", 1)[1].strip() or hostname
            continue

        if line.startswith("os_name="):
            os_name = line.split("=", 1)[1].strip()
            continue

        if line.startswith("warning[]="):
            parts = line[len("warning[]=") :].split("|")
            finding = _parse_lynis_entry(
                parts,
                "warning",
                hostname,
                os_name,
                default_severity="Medium",
            )
            if finding:
                findings.append(finding)
            continue

        if line.startswith("suggestion[]="):
            parts = line[len("suggestion[]=") :].split("|")
            finding = _parse_lynis_entry(
                parts,
                "suggestion",
                hostname,
                os_name,
                default_severity="Low",
            )
            if finding:
                findings.append(finding)
            continue

    if not findings and content:
        LOG.info("Lynis report parsed successfully but contained no findings: %s", path)

    LOG.info("Parsed %d findings from Lynis: %s", len(findings), path.name)
    return findings


def _looks_like_check_id(value: str) -> bool:
    return bool(CHECK_ID_RE.match(value.strip()))


def _parse_lynis_entry(
    parts: list[str],
    entry_type: str,
    hostname: str,
    os_name: str,
    default_severity: str,
) -> Finding | None:
    cleaned = [part.strip() for part in parts]
    if not cleaned or not any(cleaned):
        return None

    check_id: str | None = None
    remaining = cleaned

    if cleaned and _looks_like_check_id(cleaned[0]):
        check_id = cleaned[0]
        remaining = cleaned[1:]

    description = remaining[0] if len(remaining) > 0 else ""
    details = remaining[1] if len(remaining) > 1 else ""
    severity_code = remaining[2].lower() if len(remaining) > 2 else ""

    if not description and details:
        description = details
        details = ""

    if not description:
        description = f"Lynis {entry_type}"

    severity = LYNIS_SEVERITY_MAP.get(severity_code, default_severity)
    title = f"Lynis {entry_type}: {description}"

    description_parts = [description]
    if details:
        description_parts.append(f"Details: {details}")
    if os_name:
        description_parts.append(f"OS: {os_name}")

    evidence_parts = [f"Type: {entry_type}"]
    if check_id:
        evidence_parts.append(f"Check: {check_id}")

    return Finding(
        tool="lynis",
        asset_id=hostname,
        title=title[:200],
        severity=severity,
        description="\n".join(description_parts),
        evidence=", ".join(evidence_parts),
        vuln_id=check_id,
        tags=["host-hardening", "configuration", entry_type],
    )
