"""Parse Nikto JSON output into normalized Finding objects."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from src.parsers.models import Finding

LOG = logging.getLogger(__name__)


def _estimate_severity(description: str, vuln_ref: str) -> str:
    text = f"{description} {vuln_ref}".lower()

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
        "phpinfo",
        "phpmyadmin",
        "directory indexing",
        "directory is browsable",
        "sensitive information",
        "trace method is active",
        "xst",
        "debug http verb",
    ]
    low_keywords = [
        "x-frame-options",
        "cookie",
        "etag",
        "server leaks",
        "allowed http methods",
        "outdated",
        "missing",
        "header",
        "banner",
    ]

    for keyword in high_keywords:
        if keyword in text:
            return "High"

    for keyword in medium_keywords:
        if keyword in text:
            return "Medium"

    for keyword in low_keywords:
        if keyword in text:
            return "Low"

    return "Info"


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

        host_ip = str(host_data.get("ip", host_data.get("host", "unknown")))
        host_port = str(host_data.get("port", ""))
        target_host = str(host_data.get("host", host_ip))
        vulnerabilities = host_data.get("vulnerabilities", [])

        if not isinstance(vulnerabilities, list):
            continue

        for vuln in vulnerabilities:
            if not isinstance(vuln, dict):
                continue

            try:
                osvdb_id = vuln.get("OSVDB", vuln.get("id", ""))
                method = str(vuln.get("method", "GET"))
                uri = str(vuln.get("url", vuln.get("uri", "/")))
                description = str(vuln.get("msg", vuln.get("message", "")) or "")
                severity = _estimate_severity(description, str(osvdb_id))
                endpoint = f"{target_host}:{host_port}{uri}" if host_port else f"{target_host}{uri}"

                findings.append(
                    Finding(
                        tool="nikto",
                        asset_id=host_ip,
                        endpoint=endpoint,
                        title=(
                            f"Nikto: {description[:100]}" if description else f"OSVDB-{osvdb_id}"
                        ),
                        severity=severity,
                        description=description,
                        evidence=f"{method} {uri}",
                        vuln_id=(
                            f"OSVDB-{osvdb_id}" if osvdb_id and str(osvdb_id) != "0" else None
                        ),
                        tags=["web-server", "misconfiguration"],
                    )
                )
            except Exception as exc:
                LOG.warning(
                    "Skipping malformed Nikto vuln in %s: %s",
                    path.name,
                    exc,
                )
                continue

    LOG.info("Parsed %d findings from Nikto JSON: %s", len(findings), path.name)
    return findings
