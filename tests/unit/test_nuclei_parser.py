from __future__ import annotations

from pathlib import Path

from src.parsers.normalize import normalize
from src.parsers.nuclei_jsonl import parse_nuclei_jsonl
from src.parsers.schema import validate_batch


def test_nuclei_parses(fixtures: Path) -> None:
    findings = parse_nuclei_jsonl(fixtures / "nuclei" / "basic_findings.jsonl")
    assert len(findings) == 1
    assert findings[0].tool == "nuclei"


def test_nuclei_empty(fixtures: Path) -> None:
    assert parse_nuclei_jsonl(fixtures / "nuclei" / "empty_findings.jsonl") == []


def test_nuclei_schema_validation(fixtures: Path) -> None:
    findings = parse_nuclei_jsonl(fixtures / "nuclei" / "basic_findings.jsonl")
    normalized = normalize(findings, run_id="TEST", environment="lab")
    validate_batch(normalized)
