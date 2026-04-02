from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import patch

import yaml

from src.integrations.ticket_client import create_tickets, resolve_owner


def _write_rules(tmp_path: Path, rules: dict[str, Any]) -> Path:
    p = tmp_path / "ticket_rules.yml"
    p.write_text(yaml.safe_dump(rules), encoding="utf-8")
    return p


def test_resolve_owner_matches_prefix_key_by_substring(tmp_path: Path) -> None:
    owner_map = {"10.1.": "linux-team@acme.com"}
    assert resolve_owner("10.1.5.20", owner_map, "default") == "linux-team@acme.com"


def test_resolve_owner_matches_substring(tmp_path: Path) -> None:
    owner_map = {"staging": "appdev-team@acme.com"}
    assert resolve_owner("staging-app.local", owner_map, "default") == "appdev-team@acme.com"


def test_resolve_owner_is_case_insensitive(tmp_path: Path) -> None:
    owner_map = {"STAGING": "appdev-team@acme.com"}
    assert resolve_owner("staging-app.local", owner_map, "default") == "appdev-team@acme.com"


def test_resolve_owner_falls_back_to_default_when_nothing_matches(tmp_path: Path) -> None:
    owner_map = {"10.1.": "linux-team@acme.com"}
    assert resolve_owner("192.168.1.1", owner_map, "default-owner") == "default-owner"


def test_resolve_owner_returns_default_for_empty_map(tmp_path: Path) -> None:
    assert resolve_owner("10.1.5.20", {}, "default-owner") == "default-owner"


def test_create_tickets_excludes_findings_below_minimum_severity(
    tmp_path: Path, fixtures: Path
) -> None:
    rules = {
        "minimum_severity": "Medium",
        "default_owner": "default-owner",
        "sla_days": {"Critical": 3, "High": 7, "Medium": 30, "Low": 90, "Info": 0},
        "owner_map": {"10.1.": "linux-team@acme.com"},
    }
    rules_path = _write_rules(tmp_path, rules)

    fixed_now = datetime(2026, 1, 1, tzinfo=UTC)
    findings = [
        {
            "asset_id": "10.1.5.20",
            "severity": "Info",
            "composite_severity": "Info",
            "fingerprint": "f1",
            "title": "t1",
            "description": "d1",
        },
        {
            "asset_id": "10.1.5.20",
            "severity": "Low",
            "composite_severity": "Low",
            "fingerprint": "f2",
            "title": "t2",
            "description": "d2",
        },
        {
            "asset_id": "10.1.5.20",
            "severity": "Medium",
            "composite_severity": "Medium",
            "fingerprint": "f3",
            "title": "t3",
            "description": "d3",
        },
    ]

    output_path = tmp_path / "tickets.json"
    with patch("src.integrations.ticket_client.datetime") as mock_dt:
        mock_dt.now.return_value = fixed_now
        mock_dt.side_effect = None
        tickets = create_tickets(
            findings=findings,
            rules_path=rules_path,
            output_path=output_path,
        )

    assert len(tickets) == 1
    assert tickets[0]["severity"] == "Medium"


def test_create_tickets_sets_due_date_from_sla_days(tmp_path: Path) -> None:
    rules = {
        "minimum_severity": "Low",
        "default_owner": "default-owner",
        "sla_days": {"Critical": 3, "High": 7, "Medium": 30, "Low": 90, "Info": 0},
        "owner_map": {},
    }
    rules_path = _write_rules(tmp_path, rules)

    fixed_now = datetime(2026, 1, 1, tzinfo=UTC)
    findings = [
        {
            "asset_id": "any-asset",
            "severity": "Low",
            "composite_severity": "Low",
            "fingerprint": "fp1",
            "title": "t",
            "description": "d",
        }
    ]
    output_path = tmp_path / "tickets.json"

    with patch("src.integrations.ticket_client.datetime") as mock_dt:
        mock_dt.now.return_value = fixed_now
        mock_dt.side_effect = None
        tickets = create_tickets(findings, rules_path=rules_path, output_path=output_path)

    expected = (fixed_now + timedelta(days=90)).strftime("%Y-%m-%d")
    assert tickets[0]["due_date"] == expected


def test_create_tickets_routes_to_owner_via_substring_matching(tmp_path: Path) -> None:
    rules = {
        "minimum_severity": "Low",
        "default_owner": "default-owner",
        "sla_days": {"Critical": 3, "High": 7, "Medium": 30, "Low": 90, "Info": 0},
        "owner_map": {"10.1.": "linux-team@acme.com", "staging": "appdev-team@acme.com"},
    }
    rules_path = _write_rules(tmp_path, rules)

    fixed_now = datetime(2026, 1, 1, tzinfo=UTC)
    findings = [
        {
            "asset_id": "10.1.5.20",
            "severity": "High",
            "composite_severity": "High",
            "fingerprint": "fp1",
            "title": "t",
            "description": "d",
        },
        {
            "asset_id": "staging-app.local",
            "severity": "Medium",
            "composite_severity": "Medium",
            "fingerprint": "fp2",
            "title": "t",
            "description": "d",
        },
    ]
    output_path = tmp_path / "tickets.json"

    with patch("src.integrations.ticket_client.datetime") as mock_dt:
        mock_dt.now.return_value = fixed_now
        mock_dt.side_effect = None
        tickets = create_tickets(findings, rules_path=rules_path, output_path=output_path)

    owners = {t["asset_id"]: t["owner"] for t in tickets}
    assert owners["10.1.5.20"] == "linux-team@acme.com"
    assert owners["staging-app.local"] == "appdev-team@acme.com"


def test_create_tickets_routes_unmatched_assets_to_default_owner(tmp_path: Path) -> None:
    rules = {
        "minimum_severity": "Low",
        "default_owner": "default-owner",
        "sla_days": {"Critical": 3, "High": 7, "Medium": 30, "Low": 90, "Info": 0},
        "owner_map": {"10.1.": "linux-team@acme.com"},
    }
    rules_path = _write_rules(tmp_path, rules)

    fixed_now = datetime(2026, 1, 1, tzinfo=UTC)
    findings = [
        {
            "asset_id": "192.168.1.5",
            "severity": "Low",
            "composite_severity": "Low",
            "fingerprint": "fp1",
            "title": "t",
            "description": "d",
        }
    ]
    output_path = tmp_path / "tickets.json"

    with patch("src.integrations.ticket_client.datetime") as mock_dt:
        mock_dt.now.return_value = fixed_now
        mock_dt.side_effect = None
        tickets = create_tickets(findings, rules_path=rules_path, output_path=output_path)

    assert tickets[0]["owner"] == "default-owner"


def test_create_tickets_writes_valid_json(tmp_path: Path) -> None:
    rules = {
        "minimum_severity": "Low",
        "default_owner": "default-owner",
        "sla_days": {"Critical": 3, "High": 7, "Medium": 30, "Low": 90, "Info": 0},
        "owner_map": {},
    }
    rules_path = _write_rules(tmp_path, rules)

    fixed_now = datetime(2026, 1, 1, tzinfo=UTC)
    findings = [
        {
            "asset_id": "asset",
            "severity": "Low",
            "composite_severity": "Low",
            "fingerprint": "fp1",
            "title": "t",
            "description": "d",
        }
    ]
    output_path = tmp_path / "tickets.json"

    with patch("src.integrations.ticket_client.datetime") as mock_dt:
        mock_dt.now.return_value = fixed_now
        mock_dt.side_effect = None
        create_tickets(findings, rules_path=rules_path, output_path=output_path)

    raw = output_path.read_text(encoding="utf-8")
    data = json.loads(raw)
    assert isinstance(data, list)
    assert data and "due_date" in data[0]


def test_create_tickets_returns_empty_list_for_empty_findings(tmp_path: Path) -> None:
    rules = {
        "minimum_severity": "Low",
        "default_owner": "default-owner",
        "sla_days": {"Critical": 3, "High": 7, "Medium": 30, "Low": 90, "Info": 0},
        "owner_map": {},
    }
    rules_path = _write_rules(tmp_path, rules)
    output_path = tmp_path / "tickets.json"

    fixed_now = datetime(2026, 1, 1, tzinfo=UTC)
    with patch("src.integrations.ticket_client.datetime") as mock_dt:
        mock_dt.now.return_value = fixed_now
        mock_dt.side_effect = None
        tickets = create_tickets([], rules_path=rules_path, output_path=output_path)

    assert tickets == []
    data = json.loads(output_path.read_text(encoding="utf-8"))
    assert data == []


def test_create_tickets_uses_composite_severity_preference(tmp_path: Path) -> None:
    rules = {
        "minimum_severity": "Medium",
        "default_owner": "default-owner",
        "sla_days": {"Critical": 3, "High": 7, "Medium": 30, "Low": 90, "Info": 0},
        "owner_map": {},
    }
    rules_path = _write_rules(tmp_path, rules)

    fixed_now = datetime(2026, 1, 1, tzinfo=UTC)
    findings = [
        {
            "asset_id": "asset",
            "severity": "Info",
            "composite_severity": "Critical",
            "fingerprint": "fp1",
            "title": "t",
            "description": "d",
        }
    ]
    output_path = tmp_path / "tickets.json"
    with patch("src.integrations.ticket_client.datetime") as mock_dt:
        mock_dt.now.return_value = fixed_now
        mock_dt.side_effect = None
        tickets = create_tickets(findings, rules_path=rules_path, output_path=output_path)

    # minimum_severity=Medium, composite_severity=Critical should be included
    assert len(tickets) == 1
    expected = (fixed_now + timedelta(days=3)).strftime("%Y-%m-%d")
    assert tickets[0]["severity"] == "Critical"
    assert tickets[0]["due_date"] == expected
