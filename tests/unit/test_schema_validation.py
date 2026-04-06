from __future__ import annotations

import pytest

from src.orchestrator.exceptions import ParserSchemaError
from src.parsers.schema import validate_batch, validate_finding


def _valid_finding() -> dict[str, object]:
    return {
        "tool": "nmap",
        "asset_id": "192.168.56.10",
        "title": "Open Port 80",
        "severity": "Low",
        "description": "HTTP service exposed",
        "evidence": "",
        "endpoint": "http://192.168.56.10:80",
        "vuln_id": "tcp-80",
        "cve": "",
        "cvss": 3.1,
        "remediation": "Close the port",
        "environment": "lab",
        "run_id": "RUN-UNIT",
        "fingerprint": "a" * 64,
        "tags": ["nmap"],
    }


def test_validate_finding_accepts_valid_finding() -> None:
    finding = _valid_finding()
    validate_finding(finding)


def test_validate_finding_rejects_invalid_severity() -> None:
    finding = _valid_finding()
    finding["severity"] = "Severe"

    with pytest.raises(ParserSchemaError, match="Finding validation failed"):
        validate_finding(finding)


def test_validate_finding_rejects_invalid_cve_pattern() -> None:
    finding = _valid_finding()
    finding["cve"] = "BAD-CVE"

    with pytest.raises(ParserSchemaError, match="Finding validation failed") as exc:
        validate_finding(finding)

    assert exc.value.context["finding_title"] == "Open Port 80"
    assert "cve" in str(exc.value.context["field"])


def test_validate_finding_rejects_additional_properties() -> None:
    finding = _valid_finding()
    finding["unexpected"] = "x"

    with pytest.raises(ParserSchemaError, match="Finding validation failed"):
        validate_finding(finding)


def test_validate_batch_returns_original_findings_when_valid() -> None:
    findings = [_valid_finding(), _valid_finding()]
    assert validate_batch(findings) == findings


def test_validate_batch_wraps_index_and_total_on_failure() -> None:
    good = _valid_finding()
    bad = _valid_finding()
    bad["fingerprint"] = "short"

    with pytest.raises(ParserSchemaError, match="Batch validation failed at index 1") as exc:
        validate_batch([good, bad])

    assert exc.value.context["index"] == 1
    assert exc.value.context["total"] == 2
