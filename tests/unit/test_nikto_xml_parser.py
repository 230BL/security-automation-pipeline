"""Unit tests for src/parsers/nikto_xml.py."""

from __future__ import annotations

from pathlib import Path

from src.parsers.nikto_xml import parse_nikto_xml
from src.parsers.normalize import normalize
from src.parsers.schema import validate_batch

# ---------------------------------------------------------------------------
# fixture-based happy-path tests
# ---------------------------------------------------------------------------


def test_nikto_xml_parses_findings(fixtures: Path) -> None:
    findings = parse_nikto_xml(fixtures / "nikto" / "basic_report.xml")
    assert len(findings) == 2
    assert all(f.tool == "nikto" for f in findings)


def test_nikto_xml_asset_id_is_target_ip(fixtures: Path) -> None:
    findings = parse_nikto_xml(fixtures / "nikto" / "basic_report.xml")
    assert all(f.asset_id == "192.168.56.10" for f in findings)


def test_nikto_xml_osvdb_id_in_vuln_id(fixtures: Path) -> None:
    findings = parse_nikto_xml(fixtures / "nikto" / "basic_report.xml")
    vuln_ids = [f.vuln_id for f in findings if f.vuln_id]
    assert any("OSVDB-12184" in vid for vid in vuln_ids)


def test_nikto_xml_item_with_zero_osvdb_falls_back_to_item_id(fixtures: Path) -> None:
    findings = parse_nikto_xml(fixtures / "nikto" / "basic_report.xml")
    # item id="999970" osvdbid="0" → vuln_id should be NIKTO-999970
    nikto_ids = [f.vuln_id for f in findings if f.vuln_id and f.vuln_id.startswith("NIKTO-")]
    assert len(nikto_ids) == 1
    assert nikto_ids[0] == "NIKTO-999970"


def test_nikto_xml_empty_scandetails_returns_empty_list(fixtures: Path) -> None:
    findings = parse_nikto_xml(fixtures / "nikto" / "empty_report.xml")
    assert findings == []


def test_nikto_xml_endpoint_includes_port(fixtures: Path) -> None:
    findings = parse_nikto_xml(fixtures / "nikto" / "basic_report.xml")
    assert all(":80" in (f.endpoint or "") for f in findings)


def test_nikto_xml_schema_validation(fixtures: Path) -> None:
    findings = parse_nikto_xml(fixtures / "nikto" / "basic_report.xml")
    normalized = normalize(findings, run_id="TEST", environment="lab")
    validate_batch(normalized)


# ---------------------------------------------------------------------------
# edge / error path tests (coverage for missing branches)
# ---------------------------------------------------------------------------


def test_nikto_xml_missing_file_returns_empty(tmp_path: Path) -> None:
    assert parse_nikto_xml(tmp_path / "missing.xml") == []


def test_nikto_xml_empty_file_returns_empty(tmp_path: Path) -> None:
    p = tmp_path / "empty.xml"
    p.write_text("", encoding="utf-8")
    assert parse_nikto_xml(p) == []


def test_nikto_xml_invalid_xml_returns_empty(tmp_path: Path) -> None:
    p = tmp_path / "bad.xml"
    p.write_text("<niktoscan><unclosed>", encoding="utf-8")
    assert parse_nikto_xml(p) == []


def test_nikto_xml_no_scandetails_returns_empty(tmp_path: Path) -> None:
    p = tmp_path / "no_details.xml"
    p.write_text('<?xml version="1.0"?><niktoscan></niktoscan>', encoding="utf-8")
    assert parse_nikto_xml(p) == []


def test_nikto_xml_item_with_no_description_is_skipped(tmp_path: Path) -> None:
    """Items whose <description> element is missing or empty are silently skipped."""
    p = tmp_path / "no_desc.xml"
    p.write_text(
        '<?xml version="1.0"?><niktoscan><niktoscan>'
        '<scandetails targetip="10.0.0.1" targetport="80">'
        '<item id="1" osvdbid="0" method="GET"><uri>/</uri></item>'
        "</scandetails></niktoscan></niktoscan>",
        encoding="utf-8",
    )
    assert parse_nikto_xml(p) == []


def test_nikto_xml_item_with_zero_osvdb_and_zero_id_has_no_vuln_id(tmp_path: Path) -> None:
    """When both osvdbid and id are 0, vuln_id must be None."""
    p = tmp_path / "no_vuln_id.xml"
    p.write_text(
        '<?xml version="1.0"?><niktoscan><niktoscan>'
        '<scandetails targetip="10.0.0.1" targetport="80">'
        '<item id="0" osvdbid="0" method="GET">'
        "<description>Some finding</description>"
        "<uri>/</uri></item>"
        "</scandetails></niktoscan></niktoscan>",
        encoding="utf-8",
    )
    findings = parse_nikto_xml(p)
    assert len(findings) == 1
    assert findings[0].vuln_id is None


def test_nikto_xml_flat_scandetails_structure(tmp_path: Path) -> None:
    """Older Nikto builds place <scandetails> as a direct child of root."""
    p = tmp_path / "flat.xml"
    p.write_text(
        '<?xml version="1.0"?>'
        "<niktoscan>"
        '<scandetails targetip="10.0.0.2" targetport="443" targethostname="myhost">'
        '<item id="42" osvdbid="999" method="GET">'
        "<description>Header missing</description>"
        "<uri>/admin</uri></item>"
        "</scandetails>"
        "</niktoscan>",
        encoding="utf-8",
    )
    findings = parse_nikto_xml(p)
    assert len(findings) == 1
    assert findings[0].asset_id == "10.0.0.2"
    assert findings[0].vuln_id == "OSVDB-999"
    assert ":443" in (findings[0].endpoint or "")
