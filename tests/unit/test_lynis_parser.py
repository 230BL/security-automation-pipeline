from __future__ import annotations

from pathlib import Path

from src.parsers.lynis_dat import parse_lynis_dat
from src.parsers.normalize import normalize
from src.parsers.schema import validate_batch


def test_lynis_parses_warning_and_suggestion(fixtures: Path) -> None:
    findings = parse_lynis_dat(fixtures / "lynis" / "report.dat")
    assert len(findings) == 2
    assert all(f.tool == "lynis" for f in findings)


def test_lynis_empty(fixtures: Path) -> None:
    assert parse_lynis_dat(fixtures / "lynis" / "empty_report.dat") == []


def test_lynis_schema_validation(fixtures: Path) -> None:
    findings = parse_lynis_dat(fixtures / "lynis" / "report.dat")
    normalized = normalize(findings, run_id="TEST", environment="lab")
    validate_batch(normalized)
