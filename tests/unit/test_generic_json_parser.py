from __future__ import annotations

from pathlib import Path

from src.parsers.generic_json import parse_generic_json


def test_generic_json_missing_file_returns_empty(tmp_path: Path) -> None:
    findings = parse_generic_json(tmp_path / "missing.json")
    assert findings == []


def test_generic_json_empty_file_returns_empty(tmp_path: Path) -> None:
    path = tmp_path / "empty.json"
    path.write_text("", encoding="utf-8")

    findings = parse_generic_json(path)

    assert findings == []


def test_generic_json_invalid_json_returns_empty(tmp_path: Path) -> None:
    path = tmp_path / "invalid.json"
    path.write_text("{not valid json", encoding="utf-8")

    findings = parse_generic_json(path)

    assert findings == []


def test_generic_json_parses_findings_key_payload(tmp_path: Path) -> None:
    path = tmp_path / "findings.json"
    path.write_text(
        """
        {
          "findings": [
            {
              "asset_id": "10.0.0.1",
              "title": "Open SSH",
              "severity": "Info",
              "description": "desc",
              "evidence": "evidence",
              "endpoint": "10.0.0.1:22",
              "vuln_id": "GEN-1",
              "cve": "CVE-2024-0001",
              "cvss": 5.5,
              "remediation": "patch",
              "tags": ["network", "ssh"]
            }
          ]
        }
        """,
        encoding="utf-8",
    )

    findings = parse_generic_json(path, tool="custom-tool")

    assert len(findings) == 1
    finding = findings[0]
    assert finding.tool == "custom-tool"
    assert finding.asset_id == "10.0.0.1"
    assert finding.title == "Open SSH"
    assert finding.severity == "Info"
    assert finding.description == "desc"
    assert finding.evidence == "evidence"
    assert finding.endpoint == "10.0.0.1:22"
    assert finding.vuln_id == "GEN-1"
    assert finding.cve == "CVE-2024-0001"
    assert finding.cvss == 5.5
    assert finding.remediation == "patch"
    assert finding.tags == ["network", "ssh"]


def test_generic_json_parses_top_level_list_and_item_tool_overrides_default(tmp_path: Path) -> None:
    path = tmp_path / "list.json"
    path.write_text(
        """
        [
          {
            "tool": "provided-tool",
            "asset_id": "host-1",
            "title": "Weak cipher",
            "severity": "Medium"
          }
        ]
        """,
        encoding="utf-8",
    )

    findings = parse_generic_json(path, tool="fallback-tool")

    assert len(findings) == 1
    assert findings[0].tool == "provided-tool"
    assert findings[0].asset_id == "host-1"
    assert findings[0].title == "Weak cipher"
    assert findings[0].severity == "Medium"


def test_generic_json_non_list_findings_key_returns_empty(tmp_path: Path) -> None:
    path = tmp_path / "bad_shape.json"
    path.write_text(
        """
        {
          "findings": {
            "asset_id": "10.0.0.1"
          }
        }
        """,
        encoding="utf-8",
    )

    findings = parse_generic_json(path)

    assert findings == []


def test_generic_json_skips_non_dict_items_and_malformed_findings(tmp_path: Path) -> None:
    path = tmp_path / "mixed.json"
    path.write_text(
        """
        {
          "findings": [
            "not-a-dict",
            {
              "asset_id": "10.0.0.1",
              "title": "Valid finding",
              "severity": "Low",
              "cvss": "4.0"
            },
            {
              "asset_id": "10.0.0.2",
              "severity": "High"
            },
            {
              "asset_id": "10.0.0.3",
              "title": "Bad cvss",
              "severity": "Medium",
              "cvss": "not-a-number"
            }
          ]
        }
        """,
        encoding="utf-8",
    )

    findings = parse_generic_json(path)

    assert len(findings) == 1
    assert findings[0].asset_id == "10.0.0.1"
    assert findings[0].cvss == 4.0


def test_generic_json_non_list_tags_become_empty_list(tmp_path: Path) -> None:
    path = tmp_path / "tags.json"
    path.write_text(
        """
        {
          "findings": [
            {
              "asset_id": "10.0.0.5",
              "title": "Header leak",
              "severity": "Low",
              "tags": "not-a-list"
            }
          ]
        }
        """,
        encoding="utf-8",
    )

    findings = parse_generic_json(path)

    assert len(findings) == 1
    assert findings[0].tags == []
