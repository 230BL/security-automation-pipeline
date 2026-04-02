from __future__ import annotations

from pathlib import Path

import yaml

from src.scoring.risk_scorer import score_batch


def test_risk_scoring_policy_influences_scores(tmp_path: Path) -> None:
    policy_path = tmp_path / "risk_policy.yml"
    policy_path.write_text(
        yaml.safe_dump(
            {
                "exposure_weights": {"external": 2.0, "internal": 1.0},
                "auth_confidence_weights": {"authenticated": 1.0, "unauthenticated": 0.7},
            }
        ),
        encoding="utf-8",
    )

    findings = [
        {
            "tool": "nmap",
            "asset_id": "a",
            "title": "t",
            "severity": "High",
            "description": "d",
            "fingerprint": "a" * 64,
        },
        {
            "tool": "nmap",
            "asset_id": "b",
            "title": "t",
            "severity": "High",
            "description": "d",
            "fingerprint": "b" * 64,
        },
    ]
    asset_ctx = {
        "a": {"criticality": 2.0, "exposure_class": "external", "auth_confidence": "authenticated"},
        "b": {
            "criticality": 1.0,
            "exposure_class": "internal",
            "auth_confidence": "unauthenticated",
        },
    }

    scored = score_batch(findings, asset_context=asset_ctx, policy_path=policy_path)
    a_score = [f for f in scored if f["asset_id"] == "a"][0]["composite_score"]
    b_score = [f for f in scored if f["asset_id"] == "b"][0]["composite_score"]
    assert a_score > b_score
