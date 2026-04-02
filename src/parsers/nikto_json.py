"""Parse Nikto JSON output into normalized Finding objects."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from src.parsers.models import Finding

LOG = logging.getLogger(__name__)


def parse_nikto_json(path: Path) -> list[Finding]:
    """Parse Nikto JSON report."""
    if not path.exists():
        LOG.warning("Nikto JSON file not found: %s", path)
        return []

    content = path.read_text(encoding="utf-8").strip()
    if not content:
        LOG.warning("Nikto JSON file is empty: %s", path)
        return []

    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        LOG.error("Failed to parse Nikto JSON %s: %s", path, exc)
        return []

    findings: list[Finding] = []
    hosts = data if isinstance(data, list) else [data]

    for host_data in hosts:
        if not isinstance(host_data, dict):
            continue

        host_ip = host_data.get("ip", host_data.get("host", "unknown"))
        host_port = host_data.get("port", "")
        target_host = host_data.get("host", host_ip)

        vulns = host_data.get("vulnerabilities", [])
        if not isinstance(vulns, list):
            continue

        for vuln in vulns:
            if not isinstance(vuln, dict):
                continue
            try:
                osvdb_id = vuln.get("OSVDB", vuln.get("id", ""))
                method = vuln.get("method", "GET")
                uri = vuln.get("url", vuln.get("uri", "/"))
                description_raw = vuln.get("msg", vuln.get("message", ""))
                description = str(description_raw or "")

                severity = _estimate_severity(description, str(osvdb_id))

                endpoint = f"{target_host}:{host_port}{uri}" if host_port else f"{target_host}{uri}"

                findings.append(
                    Finding(
                        tool="nikto",
                        asset_id=str(host_ip),
                        endpoint=endpoint,
                        title=f"Nikto: {description[:100]}" if description else f"OSVDB-{osvdb_id}",
                        severity=severity,
                        description=description,
                        evidence=f"{method} {uri}",
                        vuln_id=f"OSVDB-{osvdb_id}" if osvdb_id and str(osvdb_id) != "0" else None,
                        tags=["web-server", "misconfiguration"],
                    )
                )
            except Exception as exc:
                LOG.warning("Skipping malformed Nikto vuln in %s: %s", path.name, exc)
                continue

    LOG.info("Parsed %d findings from Nikto JSON: %s", len(findings), path.name)
    return findings


def _estimate_severity(description: str, osvdb_id: str) -> str:
    desc_lower = (description or "").lower()

    high_keywords = [
        "remote code",
        "rce",
        "sql injection",
        "command injection",
        "directory traversal",
        "path traversal",
        "file inclusion",
        "arbitrary file",
        "backdoor",
        "shell",
    ]
    medium_keywords = [
        "xss",
        "cross-site",
        "clickjacking",
        "csrf",
        "information disclosure",
        "directory listing",
        "source code",
        "backup file",
    ]
    low_keywords = ["header", "cookie", "version", "banner", "deprecated", "outdated", "missing"]

    for kw in high_keywords:
        if kw in desc_lower:
            return "High"
    for kw in medium_keywords:
        if kw in desc_lower:
            return "Medium"
    for kw in low_keywords:
        if kw in desc_lower:
            return "Low"

    if osvdb_id and osvdb_id != "0":
        return "Low"

    return "Info"
