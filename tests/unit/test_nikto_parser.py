from __future__ import annotations

from pathlib import Path

from src.parsers.nikto_json import parse_nikto_json
from src.parsers.normalize import normalize
from src.parsers.schema import validate_batch


def test_nikto_parses_findings(fixtures: Path) -> None:
    findings = parse_nikto_json(fixtures / "nikto" / "basic_report.json")
    assert len(findings) == 1
    assert findings[0].tool == "nikto"


def test_nikto_empty_report(fixtures: Path) -> None:
    findings = parse_nikto_json(fixtures / "nikto" / "empty_report.json")
    assert findings == []


def test_nikto_schema_validation(fixtures: Path) -> None:
    findings = parse_nikto_json(fixtures / "nikto" / "basic_report.json")
    normalized = normalize(findings, run_id="TEST", environment="lab")
    validate_batch(normalized)
