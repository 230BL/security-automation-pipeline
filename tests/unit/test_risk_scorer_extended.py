from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from src.scoring.risk_scorer import (
    resolve_asset_criticality,
    score_batch,
    score_finding,
)


def test_resolve_asset_criticality_returns_policy_value_on_substring_match() -> None:
    policy: dict[str, Any] = {"asset_criticality": {"dc01": 2.0}}
    assert resolve_asset_criticality("dc01-service", policy) == 2.0


def test_resolve_asset_criticality_is_case_insensitive() -> None:
    policy: dict[str, Any] = {"asset_criticality": {"DC01": 2.0}}
    assert resolve_asset_criticality("dc01-service", policy) == 2.0


def test_resolve_asset_criticality_returns_default_when_no_match() -> None:
    policy: dict[str, Any] = {"asset_criticality": {"dc01": 2.0}}
    assert resolve_asset_criticality("unknown-host", policy) == 1.0


def test_resolve_asset_criticality_returns_default_for_empty_policy() -> None:
    assert resolve_asset_criticality("any", {}) == 1.0


def test_resolve_asset_criticality_returns_default_when_asset_criticality_not_dict() -> None:
    assert resolve_asset_criticality("any", {"asset_criticality": "nope"}) == 1.0


def test_score_finding_outputs_expected_fields_and_clamps_score() -> None:
    finding = {
        "tool": "nmap",
        "asset_id": "dc01",
        "title": "t",
        "severity": "Low",
        "description": "d",
        "cvss": 9.5,
        "endpoint": None,
        "fingerprint": "0" * 64,
    }
    out = score_finding(
        finding,
        asset_criticality=3.0,
        exposure_class="external",
        auth_confidence="agent",
        recurrence_count=9999,
        compensating_controls=[],
        policy={},
    )
    assert "composite_score" in out
    assert "composite_severity" in out
    assert "score_factors" in out
    assert 0.0 <= float(out["composite_score"]) <= 10.0
    assert float(out["composite_score"]) == 10.0


def test_score_finding_cvss_overrides_severity_weight_when_higher() -> None:
    finding = {
        "tool": "nmap",
        "asset_id": "x",
        "title": "t",
        "severity": "Info",
        "description": "d",
        "cvss": 8.0,
        "endpoint": None,
        "fingerprint": "0" * 64,
    }
    out = score_finding(
        finding,
        asset_criticality=1.0,
        exposure_class="internal",
        auth_confidence="authenticated",
        policy={},
    )
    assert float(out["score_factors"]["base_score"]) == 8.0


def test_score_finding_higher_exposure_class_produces_higher_score() -> None:
    finding = {
        "tool": "nmap",
        "asset_id": "x",
        "title": "t",
        "severity": "High",
        "description": "d",
        "cvss": None,
        "endpoint": None,
        "fingerprint": "0" * 64,
    }
    internal = score_finding(finding, asset_criticality=1.0, exposure_class="internal", policy={})
    external = score_finding(finding, asset_criticality=1.0, exposure_class="external", policy={})
    assert float(external["composite_score"]) > float(internal["composite_score"])


def test_score_finding_compensating_controls_reduce_score() -> None:
    finding = {
        "tool": "nmap",
        "asset_id": "x",
        "title": "t",
        "severity": "High",
        "description": "d",
        "cvss": None,
        "endpoint": None,
        "fingerprint": "0" * 64,
    }
    no_controls = score_finding(
        finding, asset_criticality=1.0, exposure_class="internal", policy={}
    )
    many_controls = score_finding(
        finding,
        asset_criticality=1.0,
        exposure_class="internal",
        compensating_controls=["c1", "c2", "c3", "c4", "c5", "c6"],
        policy={},
    )
    assert float(many_controls["composite_score"]) < float(no_controls["composite_score"])


def test_score_finding_recurrence_boosts_score() -> None:
    finding = {
        "tool": "nmap",
        "asset_id": "x",
        "title": "t",
        "severity": "Medium",
        "description": "d",
        "cvss": None,
        "endpoint": None,
        "fingerprint": "0" * 64,
    }
    r0 = score_finding(
        finding, asset_criticality=1.0, exposure_class="internal", recurrence_count=0, policy={}
    )
    r5 = score_finding(
        finding, asset_criticality=1.0, exposure_class="internal", recurrence_count=5, policy={}
    )
    assert float(r5["composite_score"]) > float(r0["composite_score"])


def test_score_batch_uses_policy_asset_criticality_patterns(tmp_path: Path) -> None:
    policy_path = tmp_path / "risk_policy.yml"
    policy_path.write_text(
        yaml.safe_dump({"asset_criticality": {"dc01": 2.0}}, sort_keys=True),
        encoding="utf-8",
    )

    findings = [
        {
            "tool": "nmap",
            "asset_id": "dc01-prod",
            "title": "t",
            "severity": "High",
            "description": "d",
            "fingerprint": "a" * 64,
            "cvss": None,
        },
        {
            "tool": "nmap",
            "asset_id": "unknown",
            "title": "t",
            "severity": "High",
            "description": "d",
            "fingerprint": "b" * 64,
            "cvss": None,
        },
    ]
    scored = score_batch(findings, asset_context={}, policy_path=policy_path)
    by_asset = {f["asset_id"]: float(f["composite_score"]) for f in scored}
    assert by_asset["dc01-prod"] > by_asset["unknown"]


def test_score_batch_asset_context_criticality_takes_priority(tmp_path: Path) -> None:
    policy_path = tmp_path / "risk_policy.yml"
    policy_path.write_text(
        yaml.safe_dump({"asset_criticality": {"dc01": 2.0}}, sort_keys=True),
        encoding="utf-8",
    )

    findings = [
        {
            "tool": "nmap",
            "asset_id": "dc01-prod",
            "title": "t",
            "severity": "High",
            "description": "d",
            "fingerprint": "a" * 64,
            "cvss": None,
        }
    ]

    scored_policy = score_batch(findings, asset_context={}, policy_path=policy_path)[0]
    scored_ctx = score_batch(
        findings,
        asset_context={"dc01-prod": {"criticality": 0.5}},
        policy_path=policy_path,
    )[0]
    assert float(scored_ctx["composite_score"]) < float(scored_policy["composite_score"])


def test_score_batch_returns_all_findings_and_does_not_drop() -> None:
    findings = [
        {
            "tool": "nmap",
            "asset_id": "a1",
            "title": "t",
            "severity": "High",
            "description": "d",
            "fingerprint": "1" * 64,
            "cvss": None,
        },
        {
            "tool": "nmap",
            "asset_id": "a2",
            "title": "t",
            "severity": "High",
            "description": "d",
            "fingerprint": "2" * 64,
            "cvss": None,
        },
    ]
    scored = score_batch(findings, asset_context={})
    assert len(scored) == len(findings)


def test_score_batch_does_not_crash_when_policy_file_missing(tmp_path: Path) -> None:
    findings = [
        {
            "tool": "nmap",
            "asset_id": "a1",
            "title": "t",
            "severity": "High",
            "description": "d",
            "fingerprint": "1" * 64,
            "cvss": None,
        }
    ]
    missing = tmp_path / "missing.yml"
    scored = score_batch(findings, asset_context={}, policy_path=missing)
    assert len(scored) == 1
