#!/usr/bin/env python3
"""CLI helper to create ticket records from findings."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.integrations.ticket_client import create_tickets  # noqa: E402


def main() -> int:
    p = argparse.ArgumentParser(description="Create ticket records from findings")
    p.add_argument("--findings", required=True, help="Path to findings.json")
    p.add_argument("--rules", default="policy/ticket_rules.yml", help="Ticket rules YAML")
    p.add_argument(
        "--output", default="evidence/normalized/tickets.json", help="Ticket output JSON"
    )
    args = p.parse_args()

    findings: list[dict[str, Any]] = json.loads(Path(args.findings).read_text(encoding="utf-8"))
    if not isinstance(findings, list):
        raise SystemExit("Findings file must be a JSON array")

    create_tickets(findings, rules_path=Path(args.rules), output_path=Path(args.output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
