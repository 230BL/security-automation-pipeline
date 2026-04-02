from __future__ import annotations

from src.parsers.models import Finding
from src.parsers.normalize import normalize
from src.parsers.schema import validate_batch


def _make_finding(**kwargs: object) -> Finding:
    defaults: dict[str, object] = {
        "tool": "test",
        "asset_id": "10.0.0.1",
        "title": "Test finding",
        "severity": "Medium",
        "description": "desc",
        "evidence": "ev",
    }
    defaults.update(kwargs)
    return Finding(**defaults)  # type: ignore[arg-type]


def test_normalize_sets_run_id_environment() -> None:
    findings = [_make_finding()]
    result = normalize(findings, run_id="RUN-001", environment="lab")
    assert result[0]["run_id"] == "RUN-001"
    assert result[0]["environment"] == "lab"


def test_normalize_adds_fingerprint() -> None:
    findings = [_make_finding()]
    result = normalize(findings, run_id="RUN-001", environment="lab")
    assert "fingerprint" in result[0]
    assert len(result[0]["fingerprint"]) == 64


def test_fingerprint_stable_across_runs() -> None:
    r1 = normalize([_make_finding()], run_id="RUN-A", environment="lab")
    r2 = normalize([_make_finding()], run_id="RUN-B", environment="lab")
    assert r1[0]["fingerprint"] == r2[0]["fingerprint"]


def test_schema_validation_passes() -> None:
    normalized = normalize([_make_finding()], run_id="RUN-001", environment="lab")
    validate_batch(normalized)
