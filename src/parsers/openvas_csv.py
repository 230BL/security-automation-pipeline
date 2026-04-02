"""Parse Greenbone/OpenVAS CSV report into normalized Finding objects."""

from __future__ import annotations

import csv
import logging
from pathlib import Path

from src.parsers.models import Finding

LOG = logging.getLogger(__name__)


def _cvss_to_severity(cvss: float) -> str:
    if cvss >= 9.0:
        return "Critical"
    if cvss >= 7.0:
        return "High"
    if cvss >= 4.0:
        return "Medium"
    if cvss > 0:
        return "Low"
    return "Info"


def parse_openvas_csv(path: Path) -> list[Finding]:
    """Parse OpenVAS CSV report."""
    if not path.exists():
        LOG.warning("OpenVAS CSV file not found: %s", path)
        return []

    content = path.read_text(encoding="utf-8").strip()
    if not content:
        LOG.warning("OpenVAS CSV file is empty: %s", path)
        return []

    findings: list[Finding] = []

    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)

        for row_num, row in enumerate(reader, start=2):
            try:
                cvss_raw = row.get("CVSS") or row.get("cvss") or row.get("CVSS Score") or "0"
                try:
                    cvss_val = float(cvss_raw)
                except (ValueError, TypeError):
                    cvss_val = 0.0

                severity = _cvss_to_severity(cvss_val)

                ip = row.get("IP") or row.get("ip") or row.get("Host") or "unknown"
                port = row.get("Port") or row.get("port") or ""
                protocol = row.get("Protocol") or row.get("protocol") or ""

                asset_id = ip
                endpoint = f"{ip}:{port}" if port else ip
                if protocol:
                    endpoint = f"{endpoint}/{protocol}"

                title = (
                    row.get("NVT Name")
                    or row.get("Vulnerability")
                    or row.get("name")
                    or "Unknown vulnerability"
                )
                description = (
                    row.get("Summary") or row.get("Description") or row.get("summary") or ""
                )
                evidence = (
                    row.get("Specific Result")
                    or row.get("Result")
                    or row.get("specific_result")
                    or ""
                )
                vuln_id = row.get("NVT OID") or row.get("OID") or row.get("oid") or ""

                cve_raw = row.get("CVEs") or row.get("cves") or row.get("CVE") or ""
                cve = None
                if cve_raw:
                    cve_parts = [
                        c.strip() for c in cve_raw.replace(";", ",").split(",") if c.strip()
                    ]
                    cve = cve_parts[0] if cve_parts else None

                remediation = row.get("Solution") or row.get("solution") or row.get("Fix") or None

                findings.append(
                    Finding(
                        tool="greenbone",
                        asset_id=asset_id,
                        endpoint=endpoint,
                        title=title,
                        severity=severity,
                        description=description,
                        evidence=evidence,
                        vuln_id=vuln_id or None,
                        cve=cve,
                        cvss=cvss_val if cvss_val > 0 else None,
                        remediation=remediation,
                        tags=["vulnerability-scan", "authenticated"],
                    )
                )
            except Exception as exc:
                LOG.warning("Skipping malformed row %d in %s: %s", row_num, path.name, exc)
                continue

    LOG.info("Parsed %d findings from OpenVAS CSV: %s", len(findings), path.name)
    return findings
