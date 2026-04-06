"""Parse Nikto JSON output into normalized Finding objects."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

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


def _host_meta(host_data: dict[str, Any]) -> tuple[str, str, str]:
    host_ip = str(host_data.get("ip", host_data.get("host", "unknown")))
    host_port = str(host_data.get("port", ""))
    target_host = str(host_data.get("host", host_ip))
    return host_ip, host_port, target_host


def _finding_from_vuln(
    vuln: dict[str, Any],
    *,
    host_ip: str,
    host_port: str,
    target_host: str,
) -> Finding:
    vuln_id = vuln.get("OSVDB", vuln.get("id", ""))
    method = str(vuln.get("method", "GET"))
    uri = str(vuln.get("url", vuln.get("uri", "/")))
    description = str(vuln.get("msg", vuln.get("message", "")) or "")
    severity = _estimate_severity(description, str(vuln_id))
    endpoint = f"{target_host}:{host_port}{uri}" if host_port else f"{target_host}{uri}"

    return Finding(
        tool="nikto",
        asset_id=host_ip,
        endpoint=endpoint,
        title=(
            f"Nikto: {description[:100]}"
            if description
            else f"OSVDB-{vuln_id}"
        ),
        severity=severity,
        description=description,
        evidence=f"{method} {uri}",
        vuln_id=(
            f"OSVDB-{vuln_id}"
            if vuln_id and str(vuln_id) != "0"
            else None
        ),
        tags=["web-server", "misconfiguration"],
    )


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

    items = data if isinstance(data, list) else [data]
    findings: list[Finding] = []

    fallback_host_ip = "unknown"
    fallback_host_port = ""
    fallback_target_host = "unknown"

    for item in items:
        if isinstance(item, dict) and "vulnerabilities" in item:
            fallback_host_ip, fallback_host_port, fallback_target_host = _host_meta(item)
            break

    for item in items:
        if not isinstance(item, dict):
            continue

        if "vulnerabilities" in item:
            host_ip, host_port, target_host = _host_meta(item)
            vulnerabilities = item.get("vulnerabilities", [])
            if not isinstance(vulnerabilities, list):
                continue

            for vuln in vulnerabilities:
                if not isinstance(vuln, dict):
                    continue
                try:
                    findings.append(
                        _finding_from_vuln(
                            vuln,
                            host_ip=host_ip,
                            host_port=host_port,
                            target_host=target_host,
                        )
                    )
                except Exception as exc:
                    LOG.warning(
                        "Skipping malformed Nikto vuln in %s: %s",
                        path.name,
                        exc,
                    )
            continue

        if "id" in item and ("msg" in item or "message" in item or "url" in item):
            try:
                findings.append(
                    _finding_from_vuln(
                        item,
                        host_ip=fallback_host_ip,
                        host_port=fallback_host_port,
                        target_host=fallback_target_host,
                    )
                )
            except Exception as exc:
                LOG.warning(
                    "Skipping malformed top-level Nikto vuln in %s: %s",
                    path.name,
                    exc,
                )

    LOG.info("Parsed %d findings from Nikto JSON: %s", len(findings), path.name)
    return findings
