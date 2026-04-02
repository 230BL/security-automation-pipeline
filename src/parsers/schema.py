"""JSON Schema validation for normalized findings.

Every finding must pass validation before import or indexing.
Batch validation fails the entire batch on any single invalid finding.
"""

from __future__ import annotations

from typing import Any

from jsonschema import ValidationError, validate

from src.orchestrator.exceptions import ParserSchemaError

FINDING_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "required": ["tool", "asset_id", "title", "severity", "description", "fingerprint"],
    "properties": {
        "tool": {"type": "string", "minLength": 1},
        "asset_id": {"type": "string", "minLength": 1},
        "title": {"type": "string", "minLength": 1},
        "severity": {"type": "string", "enum": ["Critical", "High", "Medium", "Low", "Info"]},
        "description": {"type": "string"},
        "evidence": {"type": "string"},
        "endpoint": {"type": ["string", "null"]},
        "vuln_id": {"type": ["string", "null"]},
        "cve": {"type": ["string", "null"], "pattern": "^(CVE-\\d{4}-\\d{4,})?$"},
        "cvss": {"type": ["number", "null"], "minimum": 0.0, "maximum": 10.0},
        "remediation": {"type": ["string", "null"]},
        "environment": {"type": ["string", "null"]},
        "run_id": {"type": ["string", "null"]},
        "fingerprint": {"type": "string", "minLength": 64, "maxLength": 64},
        "tags": {"type": "array", "items": {"type": "string"}},
    },
    "additionalProperties": False,
}


def validate_finding(finding: dict[str, Any]) -> None:
    """Validate a single finding dict against the schema."""
    try:
        validate(instance=finding, schema=FINDING_SCHEMA)
    except ValidationError as exc:
        raise ParserSchemaError(
            f"Finding validation failed for '{finding.get('title', 'UNKNOWN')}': {exc.message}",
            context={"finding_title": finding.get("title"), "field": exc.json_path},
        ) from exc


def validate_batch(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Validate all findings. Fail the entire batch on any invalid finding."""
    for i, finding in enumerate(findings):
        try:
            validate_finding(finding)
        except ParserSchemaError as exc:
            raise ParserSchemaError(
                f"Batch validation failed at index {i}: {exc}. No findings will be imported.",
                context={"index": i, "total": len(findings)},
            ) from exc
    return findings
