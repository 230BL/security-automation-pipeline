"""Composite risk scoring for normalized findings.

Asset criticality is resolved using this priority order:
1. Caller-supplied `asset_context[asset_id]["criticality"]` when present.
2. The loaded policy's `asset_criticality` map, matched as a case-insensitive
   substring against `asset_id`.
3. Default criticality of `1.0` when no match is found.

Never trusts tool severity alone. Applies asset criticality, exposure class,
authentication confidence, recurrence count, and compensating controls.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

LOG = logging.getLogger(__name__)

SEVERITY_WEIGHT: dict[str, float] = {
    "Critical": 10.0,
    "High": 8.0,
    "Medium": 5.0,
    "Low": 2.0,
    "Info": 0.5,
}


def load_risk_policy(path: Path) -> dict[str, Any]:
    """Load risk policy from YAML."""
    if not path.exists():
        LOG.warning("Risk policy not found at %s, using defaults", path)
        return {}
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return data if isinstance(data, dict) else {}


def resolve_asset_criticality(asset_id: str, policy: dict[str, Any]) -> float:
    """Resolve asset criticality using case-insensitive substring matching.

    Iterates `policy.get("asset_criticality", {})` and treats each key as a
    case-insensitive substring to match against `asset_id`.

    Returns the float value of the first match, or 1.0 when:
    - `asset_criticality` is missing or not a dict
    - no key matches
    - the matched value cannot be converted to float
    """
    crit_map = policy.get("asset_criticality", {})
    if not isinstance(crit_map, dict):
        return 1.0

    asset_lower = str(asset_id).lower()
    for pattern, value in crit_map.items():
        pattern_lower = str(pattern).lower()
        if pattern_lower in asset_lower:
            try:
                return float(value)
            except (TypeError, ValueError):
                return 1.0

    return 1.0


def score_finding(
    finding: dict[str, Any],
    asset_criticality: float = 1.0,
    exposure_class: str = "internal",
    auth_confidence: str = "authenticated",
    recurrence_count: int = 0,
    compensating_controls: list[str] | None = None,
    policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Apply composite risk scoring to a single finding."""
    policy = policy or {}
    compensating_controls = compensating_controls or []

    severity = str(finding.get("severity", "Info"))
    base_score = float(SEVERITY_WEIGHT.get(severity, 0.5))

    cvss = finding.get("cvss")
    if isinstance(cvss, (int, float)) and float(cvss) > base_score:
        base_score = float(cvss)

    exposure_weights: dict[str, float] = policy.get(
        "exposure_weights",
        {"external": 2.0, "dmz": 1.5, "internal": 1.0, "isolated": 0.5},
    )
    exposure_mult = float(exposure_weights.get(exposure_class, 1.0))

    auth_weights: dict[str, float] = policy.get(
        "auth_confidence_weights",
        {"agent": 1.0, "authenticated": 0.95, "unauthenticated": 0.7},
    )
    auth_mult = float(auth_weights.get(auth_confidence, 0.8))

    recurrence_boost = min(int(recurrence_count) * 0.2, 1.0)
    control_reduction = min(len(compensating_controls) * 0.15, 0.5)

    composite = (
        base_score * float(asset_criticality) * exposure_mult * auth_mult
        + recurrence_boost
        - control_reduction
    )
    composite = max(0.0, min(10.0, round(float(composite), 2)))

    if composite >= 9.0:
        composite_severity = "Critical"
    elif composite >= 7.0:
        composite_severity = "High"
    elif composite >= 4.0:
        composite_severity = "Medium"
    elif composite > 0.5:
        composite_severity = "Low"
    else:
        composite_severity = "Info"

    scored = dict(finding)
    scored["composite_score"] = composite
    scored["composite_severity"] = composite_severity
    scored["score_factors"] = {
        "base_score": base_score,
        "asset_criticality": asset_criticality,
        "exposure_class": exposure_class,
        "exposure_mult": exposure_mult,
        "auth_confidence": auth_confidence,
        "auth_mult": auth_mult,
        "recurrence_count": recurrence_count,
        "recurrence_boost": recurrence_boost,
        "compensating_controls": list(compensating_controls),
        "control_reduction": control_reduction,
    }
    return scored


def score_batch(
    findings: list[dict[str, Any]],
    asset_context: dict[str, dict[str, Any]] | None = None,
    policy_path: Path = Path("policy/risk_policy.yml"),
) -> list[dict[str, Any]]:
    """Score a batch of normalized findings."""
    policy = load_risk_policy(policy_path)
    asset_context = asset_context or {}
    scored: list[dict[str, Any]] = []

    for finding in findings:
        asset_id = str(finding.get("asset_id", ""))
        ctx = asset_context.get(asset_id, {})
        if isinstance(ctx, dict) and "criticality" in ctx and ctx.get("criticality") is not None:
            try:
                asset_criticality = float(ctx.get("criticality", 1.0))
            except (TypeError, ValueError):
                asset_criticality = 1.0
        else:
            asset_criticality = resolve_asset_criticality(asset_id, policy)
        scored.append(
            score_finding(
                finding,
                asset_criticality=asset_criticality,
                exposure_class=str(ctx.get("exposure_class", "internal")),
                auth_confidence=str(ctx.get("auth_confidence", "unauthenticated")),
                recurrence_count=int(ctx.get("recurrence_count", 0)),
                compensating_controls=ctx.get("compensating_controls", []),
                policy=policy,
            )
        )

    LOG.info("Scored %d findings", len(scored))
    return scored
