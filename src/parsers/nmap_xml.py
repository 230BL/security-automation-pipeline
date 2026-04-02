"""Parse Nmap XML output into normalized Finding objects.

Handles:
- Multiple hosts
- Missing service elements
- Closed/filtered ports (skipped)
- Empty scans
"""

from __future__ import annotations

import logging
from pathlib import Path

from defusedxml.ElementTree import ParseError, parse, tostring

from src.parsers.models import Finding

LOG = logging.getLogger(__name__)


def parse_nmap_xml(path: Path) -> list[Finding]:
    """Parse Nmap XML output file."""
    if not path.exists():
        LOG.warning("Nmap XML file not found: %s", path)
        return []

    content = path.read_text(encoding="utf-8").strip()
    if not content:
        LOG.warning("Nmap XML file is empty: %s", path)
        return []

    try:
        tree = parse(path)
        root = tree.getroot()
    except ParseError as exc:
        LOG.error("Failed to parse Nmap XML %s: %s", path, exc)
        return []

    if root is None:
        LOG.warning("Nmap XML has no root element: %s", path)
        return []

    findings: list[Finding] = []
    scan_start = root.attrib.get("startstr", "")

    for host in root.findall("host"):
        addr_elem = host.find("address")
        if addr_elem is None:
            LOG.debug("Skipping host with no address element")
            continue

        asset_id = addr_elem.attrib.get("addr", "unknown")
        status_elem = host.find("status")
        host_state = (
            status_elem.attrib.get("state", "unknown") if status_elem is not None else "unknown"
        )
        if host_state != "up":
            continue

        hostnames: list[str] = []
        for hostname_elem in host.findall(".//hostname"):
            name = hostname_elem.attrib.get("name")
            if name:
                hostnames.append(name)

        for port_elem in host.findall(".//port"):
            state_elem = port_elem.find("state")
            if state_elem is None:
                continue
            if state_elem.attrib.get("state", "") != "open":
                continue

            port_id = port_elem.attrib.get("portid", "unknown")
            protocol = port_elem.attrib.get("protocol", "tcp")

            service_elem = port_elem.find("service")
            if service_elem is not None:
                service_name = service_elem.attrib.get("name", "unknown")
                service_product = service_elem.attrib.get("product", "")
                service_version = service_elem.attrib.get("version", "")
                service_info = " ".join(filter(None, [service_product, service_version])).strip()
            else:
                service_name = "unknown"
                service_info = ""

            evidence_xml = tostring(port_elem, encoding="unicode")

            description_parts = [f"Open {protocol}/{port_id} ({service_name})"]
            if service_info:
                description_parts.append(f"Service: {service_info}")
            if hostnames:
                description_parts.append(f"Hostnames: {', '.join(hostnames)}")
            if scan_start:
                description_parts.append(f"Scan time: {scan_start}")

            findings.append(
                Finding(
                    tool="nmap",
                    asset_id=asset_id,
                    endpoint=f"{asset_id}:{port_id}/{protocol}",
                    title=f"Open port: {protocol}/{port_id} ({service_name})",
                    severity="Info",
                    description="\n".join(description_parts),
                    evidence=evidence_xml,
                    tags=["exposure", "service-validation"],
                )
            )

    LOG.info("Parsed %d findings from Nmap XML: %s", len(findings), path.name)
    return findings
