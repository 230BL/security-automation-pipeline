"""Parse Nikto text output into normalized Finding objects."""

from __future__ import annotations

import re
from pathlib import Path

from src.parsers.models import Finding

_LINE_PREFIX = re.compile(r"^\+\s+")
_ITEM_COUNT = re.compile(
    r"\+\s+\d+\s+items checked:\s+\d+\s+error\(s\)\s+and\s+\d+\s+item\(s\)\s+reported"
)
TARGET_HOST = re.compile(r"^\+\s+Target Host(?:name)?:\s*(.+)$")
TARGET_IP = re.compile(r"^\+\s+Target IP:\s*(.+)$")
TARGET_PORT = re.compile(r"^\+\s+Target Port:\s*(.+)$")


def _severity_from_text(text: str) -> str:
    lower = text.lower()

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

    for kw in high_keywords:
        if kw in lower:
            return "High"
    for kw in medium_keywords:
        if kw in lower:
            return "Medium"
    for kw in low_keywords:
        if kw in lower:
            return "Low"
    return "Info"


def _extract_vuln_id(text: str) -> str | None:
    match = re.search(r"\bOSVDB-(\d+)\b", text)
    if match:
        return f"OSVDB-{match.group(1)}"
    return None


def parse_nikto_json(path: Path) -> list[Finding]:
    content = path.read_text(encoding="utf-8", errors="replace")
    if not content.strip():
        return []

    findings: list[Finding] = []
    target_host = ""
    target_ip = ""
    target_port = ""

    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        host_match = TARGET_HOST.match(line)
        if host_match:
            target_host = host_match.group(1).strip()
            continue

        ip_match = TARGET_IP.match(line)
        if ip_match:
            target_ip = ip_match.group(1).strip()
            continue

        port_match = TARGET_PORT.match(line)
        if port_match:
            target_port = port_match.group(1).strip()
            continue

        if not _LINE_PREFIX.match(line):
            continue

        if _ITEM_COUNT.match(line):
            continue

        if (
            line.startswith("+ Target ")
            or line.startswith("+ Start Time")
            or line.startswith("+ End Time")
        ):
            continue

        if line.startswith("+ Server:"):
            text = line[2:].strip()
            asset_id = target_ip or target_host or "unknown"
            endpoint = (
                f"{target_host or target_ip}:{target_port}"
                if target_port
                else (target_host or target_ip or None)
            )
            findings.append(
                Finding(
                    tool="nikto",
                    asset_id=asset_id,
                    endpoint=endpoint,
                    title="Nikto: Server banner exposed",
                    severity="Info",
                    description=text,
                    evidence=raw_line,
                    tags=["web-server", "misconfiguration"],
                )
            )
            continue

        if line.startswith("+ "):
            text = line[2:].strip()
            asset_id = target_ip or target_host or "unknown"
            endpoint = (
                f"{target_host or target_ip}:{target_port}"
                if target_port
                else (target_host or target_ip or None)
            )

            findings.append(
                Finding(
                    tool="nikto",
                    asset_id=asset_id,
                    endpoint=endpoint,
                    title=f"Nikto: {text[:100]}",
                    severity=_severity_from_text(text),
                    description=text,
                    evidence=raw_line,
                    vuln_id=_extract_vuln_id(text),
                    tags=["web-server", "misconfiguration"],
                )
            )

    deduped: list[Finding] = []
    seen: set[tuple[str, str | None, str | None]] = set()

    for item in findings:
        key = (item.title, item.endpoint, item.vuln_id)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)

    return deduped
