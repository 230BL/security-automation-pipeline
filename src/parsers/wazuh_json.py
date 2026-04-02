"""Parse Wazuh JSON exports into normalized Finding objects.

Handles both vulnerability detection findings and SCA results.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from src.parsers.models import Finding

LOG = logging.getLogger(__name__)

WAZUH_SEVERITY_MAP: dict[str, str] = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
    "informational": "Info",
    "none": "Info",
}


def parse_wazuh_vulnerabilities(path: Path) -> list[Finding]:
    """Parse Wazuh vulnerability detection JSON export."""
    if not path.exists():
        LOG.warning("Wazuh JSON file not found: %s", path)
        return []

    content = path.read_text(encoding="utf-8").strip()
    if not content:
        LOG.warning("Wazuh JSON file is empty: %s", path)
        return []

    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        LOG.error("Failed to parse Wazuh JSON %s: %s", path, exc)
        return []

    items = data.get("data", data.get("vulnerabilities", data))
    if isinstance(items, dict) and "affected_items" in items:
        items = items["affected_items"]
    if not isinstance(items, list):
        LOG.warning("Unexpected Wazuh JSON structure in %s", path)
        return []

    findings: list[Finding] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        try:
            agent = item.get("agent", {})
            agent_name = agent.get("name", agent.get("id", "unknown"))
            agent_ip = agent.get("ip", "")

            cve = item.get("cve", item.get("vulnerability", {}).get("cve", ""))
            package_name = item.get("package", {}).get("name", item.get("name", ""))
            package_version = item.get("package", {}).get("version", item.get("version", ""))

            severity_raw = (
                item.get("severity") or item.get("vulnerability", {}).get("severity") or "info"
            ).lower()
            severity = WAZUH_SEVERITY_MAP.get(severity_raw, "Info")

            title_parts = [cve, package_name]
            title = " - ".join(filter(None, title_parts)) or "Wazuh vulnerability finding"

            description_raw = item.get("description", item.get("title", ""))
            description = str(description_raw or "")
            if package_name and package_version:
                description = f"{description}\nPackage: {package_name} {package_version}"

            cvss_raw = item.get("cvss", {})
            cvss_score = None
            if isinstance(cvss_raw, dict):
                cvss_score = cvss_raw.get("cvss3", {}).get("base_score") or cvss_raw.get(
                    "cvss2", {}
                ).get("base_score")
            elif isinstance(cvss_raw, (int, float)):
                cvss_score = float(cvss_raw)

            findings.append(
                Finding(
                    tool="wazuh",
                    asset_id=str(agent_name or agent_ip or "unknown"),
                    endpoint=str(agent_ip or agent_name),
                    title=title,
                    severity=severity,
                    description=description.strip(),
                    evidence=(
                        f"Agent: {agent_name} ({agent_ip}), Package: {package_name} "
                        f"{package_version}"
                    ),
                    vuln_id=cve or None,
                    cve=cve if isinstance(cve, str) and cve.startswith("CVE-") else None,
                    cvss=float(cvss_score) if cvss_score is not None else None,
                    remediation=item.get("remediation", item.get("recommendation")),
                    tags=["endpoint", "vulnerability-detection"],
                )
            )
        except Exception as exc:
            LOG.warning("Skipping malformed Wazuh entry in %s: %s", path.name, exc)
            continue

    LOG.info("Parsed %d vulnerability findings from Wazuh: %s", len(findings), path.name)
    return findings


def parse_wazuh_sca(path: Path) -> list[Finding]:
    """Parse Wazuh SCA (Security Configuration Assessment) results."""
    if not path.exists():
        LOG.warning("Wazuh SCA file not found: %s", path)
        return []

    content = path.read_text(encoding="utf-8").strip()
    if not content:
        return []

    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        LOG.error("Failed to parse Wazuh SCA JSON %s: %s", path, exc)
        return []

    items = data.get("data", data.get("checks", data))
    if isinstance(items, dict) and "affected_items" in items:
        items = items["affected_items"]
    if not isinstance(items, list):
        return []

    findings: list[Finding] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        try:
            result = str(item.get("result", "")).lower()
            if result == "passed":
                continue

            agent = item.get("agent", {})
            agent_name = agent.get("name", "unknown")

            title = item.get("title", item.get("check", "SCA check"))
            rationale = item.get("rationale", item.get("description", ""))
            remediation = item.get("remediation", item.get("expected", ""))
            policy = item.get("policy", {})
            policy_name = policy.get("name", "") if isinstance(policy, dict) else str(policy)
            check_id = str(item.get("id", item.get("check_id", "")))

            findings.append(
                Finding(
                    tool="wazuh_sca",
                    asset_id=str(agent_name),
                    title=f"SCA: {title}",
                    severity="Medium",
                    description=f"{rationale}\nPolicy: {policy_name}",
                    evidence=f"Result: {result}",
                    vuln_id=check_id or None,
                    remediation=str(remediation) if remediation else None,
                    tags=["configuration", "sca", "compliance"],
                )
            )
        except Exception as exc:
            LOG.warning("Skipping malformed Wazuh SCA entry in %s: %s", path.name, exc)
            continue

    LOG.info("Parsed %d SCA findings from Wazuh: %s", len(findings), path.name)
    return findings
