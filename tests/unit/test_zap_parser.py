from __future__ import annotations

from pathlib import Path

from src.parsers.normalize import normalize
from src.parsers.schema import validate_batch
from src.parsers.zap_xml import parse_zap_xml


def test_zap_parses_alerts(fixtures: Path) -> None:
    findings = parse_zap_xml(fixtures / "zap" / "baseline_report.xml")
    assert len(findings) == 1
    assert findings[0].tool == "zap"
    assert findings[0].severity in ("Info", "Low", "Medium", "High")


def test_zap_empty_report(fixtures: Path) -> None:
    findings = parse_zap_xml(fixtures / "zap" / "empty_report.xml")
    assert findings == []


def test_zap_schema_validation(fixtures: Path) -> None:
    findings = parse_zap_xml(fixtures / "zap" / "baseline_report.xml")
    normalized = normalize(findings, run_id="TEST", environment="lab")
    validate_batch(normalized)
