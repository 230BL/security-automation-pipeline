from __future__ import annotations

from src.parsers.models import Finding


def test_finding_fingerprint_is_stable_for_normalized_fields() -> None:
    finding_a = Finding(
        tool="nmap",
        asset_id="192.168.56.10",
        title=" Open Port 80 ",
        severity=" Low ",
        description="desc",
        endpoint="http://192.168.56.10:80",
        vuln_id="tcp-80",
    )
    finding_b = Finding(
        tool="nmap",
        asset_id="192.168.56.10",
        title="open port 80",
        severity="low",
        description="different desc",
        endpoint="http://192.168.56.10:80",
        vuln_id="tcp-80",
    )

    assert finding_a.fingerprint() == finding_b.fingerprint()


def test_finding_fingerprint_changes_when_key_fields_change() -> None:
    base = Finding(
        tool="nmap",
        asset_id="192.168.56.10",
        title="Open Port 80",
        severity="Low",
        description="desc",
        endpoint="http://192.168.56.10:80",
        vuln_id="tcp-80",
    )
    changed = Finding(
        tool="nmap",
        asset_id="192.168.56.10",
        title="Open Port 443",
        severity="Low",
        description="desc",
        endpoint="http://192.168.56.10:443",
        vuln_id="tcp-443",
    )

    assert base.fingerprint() != changed.fingerprint()


def test_finding_to_dict_includes_fingerprint_and_fields() -> None:
    finding = Finding(
        tool="nikto",
        asset_id="web-01",
        title="Missing Security Header",
        severity="Medium",
        description="header missing",
        evidence="response headers",
        endpoint="http://web-01",
        vuln_id="nikto-001",
        cve="",
        cvss=5.0,
        remediation="add the header",
        environment="lab",
        run_id="RUN-123",
        tags=["web", "headers"],
    )

    data = finding.to_dict()

    assert data["tool"] == "nikto"
    assert data["asset_id"] == "web-01"
    assert data["title"] == "Missing Security Header"
    assert data["severity"] == "Medium"
    assert data["endpoint"] == "http://web-01"
    assert data["run_id"] == "RUN-123"
    assert data["tags"] == ["web", "headers"]
    assert data["fingerprint"] == finding.fingerprint()
