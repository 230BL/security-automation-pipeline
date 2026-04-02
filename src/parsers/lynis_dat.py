"""Parse Lynis report-data (.dat) files into normalized Finding objects.

Lynis report files use a key=value format with sections like:
warning[]=description|details|severity
suggestion[]=description|details|severity
"""

from __future__ import annotations

import logging
from pathlib import Path

from src.parsers.models import Finding

LOG = logging.getLogger(__name__)

LYNIS_SEVERITY_MAP: dict[str, str] = {
    "c": "Critical",
    "h": "High",
    "m": "Medium",
    "l": "Low",
    "i": "Info",
    "": "Info",
}


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

    for line in content.splitlines():
        line = line.strip()
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
            f = _parse_lynis_entry(parts, "warning", hostname, os_name, default_severity="Medium")
            if f:
                findings.append(f)
            continue

        if line.startswith("suggestion[]="):
            parts = line[len("suggestion[]=") :].split("|")
            f = _parse_lynis_entry(parts, "suggestion", hostname, os_name, default_severity="Low")
            if f:
                findings.append(f)
            continue

    LOG.info("Parsed %d findings from Lynis: %s", len(findings), path.name)
    return findings


def _parse_lynis_entry(
    parts: list[str],
    entry_type: str,
    hostname: str,
    os_name: str,
    default_severity: str,
) -> Finding | None:
    if len(parts) < 2:
        return None

    check_id = parts[0].strip() or None
    description = parts[1].strip() if len(parts) > 1 else ""
    details = parts[2].strip() if len(parts) > 2 else ""
    severity_code = parts[3].strip().lower() if len(parts) > 3 else ""

    severity = LYNIS_SEVERITY_MAP.get(severity_code, default_severity)
    title = (
        f"Lynis {entry_type}: {description}" if description else f"Lynis {entry_type}: {check_id}"
    )

    full_description = description
    if details:
        full_description = f"{full_description}\nDetails: {details}"
    if os_name:
        full_description = f"{full_description}\nOS: {os_name}"

    return Finding(
        tool="lynis",
        asset_id=hostname,
        title=title[:200],
        severity=severity,
        description=full_description,
        evidence=f"Check: {check_id}, Type: {entry_type}",
        vuln_id=check_id,
        tags=["host-hardening", "configuration", entry_type],
    )
