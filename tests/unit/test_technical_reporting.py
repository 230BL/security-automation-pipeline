"""Unit tests for src/reporting/technical.py."""

from __future__ import annotations

from typing import Any

from src.reporting.technical import remediation_status_stub


def test_remediation_status_stub_empty() -> None:
    assert remediation_status_stub([]) == {
        "open": 0,
        "closed": 0,
        "in_progress": 0,
        "untracked": 0,
    }


def test_remediation_status_stub_ticket_status_variants() -> None:
    findings: list[dict[str, Any]] = [
        {"ticket_status": "closed"},
        {"ticket_status": "in_progress"},
        {"ticket_status": "open"},
        {"ticket_status": "unknown"},
        {"status": "resolved"},
        {"status": "new"},
    ]
    counts = remediation_status_stub(findings)
    assert counts["closed"] == 2  # closed + resolved
    assert counts["in_progress"] == 1
    assert counts["open"] == 2  # explicit open + status new
    assert counts["untracked"] == 1


def test_remediation_status_stub_in_progress_spelling() -> None:
    counts = remediation_status_stub([{"ticket_status": "in progress"}])
    assert counts["in_progress"] == 1
