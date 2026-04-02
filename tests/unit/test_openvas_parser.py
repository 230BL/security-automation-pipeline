from __future__ import annotations

from pathlib import Path

from src.parsers.normalize import normalize
from src.parsers.openvas_csv import parse_openvas_csv
from src.parsers.schema import validate_batch


def test_parses_rows(fixtures: Path) -> None:
    findings = parse_openvas_csv(fixtures / "openvas" / "basic_report.csv")
    assert len(findings) == 3


def test_cvss_to_severity_mapping(fixtures: Path) -> None:
    findings = parse_openvas_csv(fixtures / "openvas" / "basic_report.csv")
    sevs = {f.title: f.severity for f in findings}
    assert sevs["HTTP Info Disclosure"] == "Critical"
    assert sevs["SSH Weak Algo"] == "Medium"
    assert sevs["TLS Version"] == "Low"


def test_empty_report(fixtures: Path) -> None:
    findings = parse_openvas_csv(fixtures / "openvas" / "empty_report.csv")
    assert findings == []


def test_schema_valid(fixtures: Path) -> None:
    findings = parse_openvas_csv(fixtures / "openvas" / "basic_report.csv")
    normalized = normalize(findings, run_id="TEST", environment="lab")
    validate_batch(normalized)
