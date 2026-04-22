"""Parse Nikto XML report into normalized Finding objects.

Nikto XML structure (niktoscan DTD):
  <niktoscan>
    <niktoscan>          (inner)
      <scandetails targetip="..." targetport="..." targethostname="...">
        <item id="..." osvdbid="..." method="GET|HEAD|POST">
          <description><![CDATA[...]]></description>
          <uri><![CDATA[/path]]></uri>
          <namelink><![CDATA[http://host/path]]></namelink>
          <iplink>...</iplink>
        </item>
        ...
      </scandetails>
    </niktoscan>
  </niktoscan>

Some older Nikto versions emit a flat structure where <scandetails> is a
direct child of the root <niktoscan>. Both shapes are handled.
"""

from __future__ import annotations

import logging
from pathlib import Path
from xml.etree.ElementTree import Element

from defusedxml.ElementTree import ParseError, parse

from src.parsers.models import Finding
from src.parsers.nikto_json import _estimate_severity  # reuse existing heuristic

LOG = logging.getLogger(__name__)


def _text(elem: Element, tag: str, default: str = "") -> str:
    child = elem.find(tag)
    if child is not None and child.text:
        return str(child.text.strip())
    return default


def _parse_item(
    item_elem: Element, *, host_ip: str, host_port: str, target_host: str
) -> Finding | None:
    """Convert a single <item> element to a Finding, or None if it should be skipped."""
    description = _text(item_elem, "description")
    if not description:
        return None

    osvdb_id = item_elem.attrib.get("osvdbid", "").strip()
    item_id = item_elem.attrib.get("id", "").strip()
    method = item_elem.attrib.get("method", "GET").strip()
    uri = _text(item_elem, "uri", "/")

    severity = _estimate_severity(description, osvdb_id)

    # Build a stable vuln_id: prefer OSVDB when non-zero
    if osvdb_id and osvdb_id != "0":
        vuln_id = f"OSVDB-{osvdb_id}"
    elif item_id and item_id != "0":
        vuln_id = f"NIKTO-{item_id}"
    else:
        vuln_id = None

    endpoint = f"{target_host}:{host_port}{uri}" if host_port else f"{target_host}{uri}"

    return Finding(
        tool="nikto",
        asset_id=host_ip,
        endpoint=endpoint,
        title=f"Nikto: {description[:100]}",
        severity=severity,
        description=description,
        evidence=f"{method} {uri}",
        vuln_id=vuln_id,
        tags=["web-server", "misconfiguration"],
    )


def parse_nikto_xml(path: Path) -> list[Finding]:
    """Parse a Nikto XML report file into normalized Finding objects."""
    if not path.exists():
        LOG.warning("Nikto XML file not found: %s", path)
        return []

    content = path.read_text(encoding="utf-8").strip()
    if not content:
        LOG.warning("Nikto XML file is empty: %s", path)
        return []

    try:
        tree = parse(path)
        root = tree.getroot()
    except ParseError as exc:
        LOG.error("Failed to parse Nikto XML %s: %s", path, exc)
        return []

    if root is None:
        LOG.warning("Nikto XML has no root element: %s", path)
        return []

    # Collect all <scandetails> elements regardless of nesting depth
    scan_details = root.findall(".//scandetails")
    if not scan_details:
        LOG.info("Nikto XML parsed successfully but contained no scandetails: %s", path)
        return []

    findings: list[Finding] = []

    for details in scan_details:
        host_ip = details.attrib.get("targetip", "unknown").strip()
        host_port = details.attrib.get("targetport", "").strip()
        target_host = (
            details.attrib.get("targethostname", "").strip()
            or details.attrib.get("sitename", "").strip()
            or host_ip
        )

        for item_elem in details.findall("item"):
            try:
                finding = _parse_item(
                    item_elem,
                    host_ip=host_ip,
                    host_port=host_port,
                    target_host=target_host,
                )
                if finding is not None:
                    findings.append(finding)
            except Exception as exc:
                LOG.warning("Skipping malformed Nikto item in %s: %s", path.name, exc)

    LOG.info("Parsed %d findings from Nikto XML: %s", len(findings), path.name)
    return findings
