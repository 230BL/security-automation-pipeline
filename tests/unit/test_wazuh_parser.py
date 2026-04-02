from __future__ import annotations

from pathlib import Path

from src.parsers.normalize import normalize
from src.parsers.schema import validate_batch
from src.parsers.wazuh_json import parse_wazuh_sca, parse_wazuh_vulnerabilities


def test_wazuh_vuln_parses(fixtures: Path) -> None:
    findings = parse_wazuh_vulnerabilities(fixtures / "wazuh" / "vulnerability_findings.json")
    assert len(findings) == 1
    assert findings[0].tool == "wazuh"
    assert findings[0].cve == "CVE-2024-1234"


def test_wazuh_sca_parses_failures(fixtures: Path) -> None:
    findings = parse_wazuh_sca(fixtures / "wazuh" / "sca_results.json")
    assert len(findings) == 1
    assert findings[0].tool == "wazuh_sca"


def test_wazuh_empty(fixtures: Path) -> None:
    assert parse_wazuh_vulnerabilities(fixtures / "wazuh" / "empty_findings.json") == []
    assert parse_wazuh_sca(fixtures / "wazuh" / "empty_findings.json") == []


def test_wazuh_schema_validation(fixtures: Path) -> None:
    findings = parse_wazuh_vulnerabilities(fixtures / "wazuh" / "vulnerability_findings.json")
    normalized = normalize(findings, run_id="TEST", environment="lab")
    validate_batch(normalized)
