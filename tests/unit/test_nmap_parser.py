from __future__ import annotations

from pathlib import Path

from src.parsers.nmap_xml import parse_nmap_xml
from src.parsers.normalize import normalize
from src.parsers.schema import validate_batch


def test_parses_open_ports(fixtures: Path) -> None:
    findings = parse_nmap_xml(fixtures / "nmap" / "single_host_three_ports.xml")
    assert len(findings) == 2
    assert all(f.tool == "nmap" for f in findings)
    assert all(f.severity == "Info" for f in findings)


def test_skips_closed_ports(fixtures: Path) -> None:
    findings = parse_nmap_xml(fixtures / "nmap" / "single_host_three_ports.xml")
    assert all("3306" not in f.title for f in findings)


def test_empty_scan(fixtures: Path) -> None:
    findings = parse_nmap_xml(fixtures / "nmap" / "empty_scan.xml")
    assert findings == []


def test_missing_service(fixtures: Path) -> None:
    findings = parse_nmap_xml(fixtures / "nmap" / "port_without_service.xml")
    assert len(findings) == 1
    assert "9999" in findings[0].title


def test_schema_validation(fixtures: Path) -> None:
    findings = parse_nmap_xml(fixtures / "nmap" / "single_host_three_ports.xml")
    normalized = normalize(findings, run_id="TEST-001", environment="lab")
    validate_batch(normalized)
