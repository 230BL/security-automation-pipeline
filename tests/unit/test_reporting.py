from __future__ import annotations

from pathlib import Path

from src.reporting.generator import generate_reports


def test_generate_reports_writes_files(tmp_path: Path) -> None:
    findings = [
        {
            "tool": "nmap",
            "asset_id": "10.0.0.1",
            "title": "Open port: tcp/22 (ssh)",
            "severity": "Info",
            "composite_severity": "Low",
            "composite_score": 1.2,
            "description": "desc",
            "evidence": "",
            "fingerprint": "a" * 64,
        }
    ]
    manifest_summary = {"organization": "Lab", "assessment_name": "Test", "asset_class_count": 1}
    reports = generate_reports(
        findings=findings,
        run_id="RUN-TEST",
        manifest_summary=manifest_summary,
        templates_dir=Path("reports/templates"),
        output_dir=tmp_path / "reports",
    )
    assert (tmp_path / "reports" / "RUN-TEST_executive.md").exists()
    assert (tmp_path / "reports" / "RUN-TEST_technical.md").exists()
    assert "executive" in reports and "technical" in reports
