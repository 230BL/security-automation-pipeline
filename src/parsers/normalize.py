"""Normalize findings from any parser with run context and environment."""

from __future__ import annotations

from typing import Any

from src.parsers.models import Finding


def normalize(
    findings: list[Finding],
    run_id: str,
    environment: str,
) -> list[dict[str, Any]]:
    """Apply run context to findings and convert to dicts with fingerprints."""
    output: list[dict[str, Any]] = []
    for finding in findings:
        finding.run_id = run_id
        finding.environment = environment
        output.append(finding.to_dict())
    return output
