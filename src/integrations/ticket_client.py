"""Ticket system integration for creating and updating remediation tickets.

Ownership routing uses substring matching:
- Each `owner_map` key is treated as a (case-insensitive) substring.
- The first pattern found inside `asset_id` determines the ticket owner.
- If nothing matches, `default_owner` is used.

This is a pluggable interface. The default implementation logs tickets
to a JSON file. Replace with Jira, ServiceNow, etc. for production.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

LOG = logging.getLogger(__name__)


@dataclass
class TicketRecord:
    """A ticket to be created or updated."""

    finding_id: str
    title: str
    severity: str
    asset_id: str
    owner: str
    due_date: str
    description: str
    status: str = "Open"

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "severity": self.severity,
            "asset_id": self.asset_id,
            "owner": self.owner,
            "due_date": self.due_date,
            "description": self.description,
            "status": self.status,
            "created": datetime.now(UTC).isoformat(),
        }


def resolve_owner(asset_id: str, owner_map: dict[str, str], default_owner: str) -> str:
    """Resolve ticket owner by substring matching.

    Iterates `owner_map` items in insertion order. If `pattern` (case-insensitive)
    is contained within `asset_id`, returns that owner. Otherwise returns
    `default_owner`.
    """
    asset_lower = str(asset_id).lower()
    for pattern, owner in owner_map.items():
        if str(pattern).lower() in asset_lower:
            return str(owner)
    return default_owner


def load_ticket_rules(path: Path = Path("policy/ticket_rules.yml")) -> dict[str, Any]:
    """Load ticket routing and SLA rules."""
    if not path.exists():
        return {
            "default_owner": "security-team",
            "sla_days": {"Critical": 3, "High": 7, "Medium": 30, "Low": 90, "Info": 0},
        }
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return data if isinstance(data, dict) else {}


def create_tickets(
    findings: list[dict[str, Any]],
    rules_path: Path = Path("policy/ticket_rules.yml"),
    output_path: Path = Path("evidence/normalized/tickets.json"),
) -> list[dict[str, Any]]:
    """Create ticket records for findings that meet severity thresholds."""
    rules = load_ticket_rules(rules_path)
    min_severity = str(rules.get("minimum_severity", rules.get("min_severity_for_ticket", "Low")))
    severity_order = ["Info", "Low", "Medium", "High", "Critical"]
    min_idx = severity_order.index(min_severity) if min_severity in severity_order else 1

    sla_days = rules.get("sla_days", {"Critical": 3, "High": 7, "Medium": 30, "Low": 90, "Info": 0})
    default_owner = str(rules.get("default_owner", "security-team"))
    owner_map = rules.get("owner_map", {})
    if not isinstance(owner_map, dict):
        owner_map = {}

    tickets: list[dict[str, Any]] = []
    now = datetime.now(UTC)

    for finding in findings:
        severity = str(finding.get("composite_severity", finding.get("severity", "Info")))
        sev_idx = severity_order.index(severity) if severity in severity_order else 0
        if sev_idx < min_idx:
            continue

        asset_id = str(finding.get("asset_id", ""))
        owner = resolve_owner(asset_id, owner_map, default_owner)
        days = int(sla_days.get(severity, 90) or 90)
        due = now + timedelta(days=days)

        ticket = TicketRecord(
            finding_id=str(finding.get("fingerprint", "")),
            title=str(finding.get("title", ""))[:200],
            severity=severity,
            asset_id=asset_id,
            owner=owner,
            due_date=due.strftime("%Y-%m-%d"),
            description=str(finding.get("description", ""))[:1000],
        )
        tickets.append(ticket.to_dict())

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(tickets, indent=2), encoding="utf-8")
    LOG.info("Created %d ticket records at %s", len(tickets), output_path)
    return tickets
