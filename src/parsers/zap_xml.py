"""Parse OWASP ZAP XML report into normalized Finding objects."""

from __future__ import annotations

import logging
import re
from pathlib import Path
from xml.etree.ElementTree import Element

from defusedxml.ElementTree import ParseError, parse

from src.parsers.models import Finding

LOG = logging.getLogger(__name__)

ZAP_RISK_MAP: dict[str, str] = {
    "0": "Info",
    "1": "Low",
    "2": "Medium",
    "3": "High",
}
HTML_TAG_RE = re.compile(r"<[^>]+>")


def parse_zap_xml(path: Path) -> list[Finding]:
    """Parse ZAP XML report."""
    if not path.exists():
        LOG.warning("ZAP XML file not found: %s", path)
        return []

    content = path.read_text(encoding="utf-8").strip()
    if not content:
        LOG.warning("ZAP XML file is empty: %s", path)
        return []

    try:
        tree = parse(path)
        root = tree.getroot()
    except ParseError as exc:
        LOG.error("Failed to parse ZAP XML %s: %s", path, exc)
        return []

    if root is None:
        LOG.warning("ZAP XML has no root element: %s", path)
        return []

    findings: list[Finding] = []

    for site in root.findall(".//site"):
        site_host = site.attrib.get("host", "unknown")
        site_name = site.attrib.get("name", site_host)

        for alert in site.findall(".//alertitem"):
            try:
                alert_name = _text(alert, "alert", "Unknown alert")
                risk_code = _text(alert, "riskcode", "0")
                severity = ZAP_RISK_MAP.get(risk_code, "Info")

                description = _text(alert, "desc", "")
                solution = _text(alert, "solution", "")
                evidence_text = _text(alert, "evidence", "")
                cwe_id = _text(alert, "cweid", "")
                plugin_id = _text(alert, "pluginid", "")

                instances = alert.findall(".//instance")
                if instances:
                    for instance in instances:
                        uri = _text(instance, "uri", site_name)
                        method = _text(instance, "method", "")
                        inst_evidence = _text(instance, "evidence", evidence_text)

                        endpoint = f"{method} {uri}" if method else uri

                        findings.append(
                            Finding(
                                tool="zap",
                                asset_id=site_host,
                                endpoint=endpoint,
                                title=alert_name,
                                severity=severity,
                                description=_clean_html(description),
                                evidence=inst_evidence,
                                vuln_id=f"CWE-{cwe_id}" if cwe_id else plugin_id or None,
                                remediation=_clean_html(solution),
                                tags=["web-security"],
                            )
                        )
                else:
                    findings.append(
                        Finding(
                            tool="zap",
                            asset_id=site_host,
                            endpoint=site_name,
                            title=alert_name,
                            severity=severity,
                            description=_clean_html(description),
                            evidence=evidence_text,
                            vuln_id=f"CWE-{cwe_id}" if cwe_id else plugin_id or None,
                            remediation=_clean_html(solution),
                            tags=["web-security"],
                        )
                    )
            except Exception as exc:
                LOG.warning("Skipping malformed alert in %s: %s", path.name, exc)

    if not findings and content:
        LOG.info("ZAP XML parsed successfully but contained no findings: %s", path)

    LOG.info("Parsed %d findings from ZAP XML: %s", len(findings), path.name)
    return findings


def _text(elem: Element, tag: str, default: str = "") -> str:
    child = elem.find(tag)
    if child is not None and child.text:
        return child.text.strip()
    return default


def _clean_html(text: str) -> str:
    return HTML_TAG_RE.sub("", text).strip()
