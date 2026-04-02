from __future__ import annotations

from pathlib import Path

from src.parsers.normalize import normalize
from src.parsers.prowler_json import parse_prowler_json
from src.parsers.schema import validate_batch


def test_prowler_parses_failed(fixtures: Path) -> None:
    findings = parse_prowler_json(fixtures / "prowler" / "aws_findings.json")
    assert len(findings) == 1
    assert findings[0].tool == "prowler"


def test_prowler_empty(fixtures: Path) -> None:
    assert parse_prowler_json(fixtures / "prowler" / "empty_findings.json") == []


def test_prowler_schema_validation(fixtures: Path) -> None:
    findings = parse_prowler_json(fixtures / "prowler" / "aws_findings.json")
    normalized = normalize(findings, run_id="TEST", environment="lab")
    validate_batch(normalized)
