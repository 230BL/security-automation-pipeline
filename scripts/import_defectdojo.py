#!/usr/bin/env python3
"""CLI helper to import artifacts into DefectDojo.

Uses the same DefectDojo client as the orchestrator. Intended for
operators who want to import a single file outside a full pipeline run.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.integrations.defectdojo_client import DefectDojoClient  # noqa: E402


def main() -> int:
    p = argparse.ArgumentParser(description="Import a scan artifact into DefectDojo")
    p.add_argument(
        "--url", default=os.environ.get("DEFECTDOJO_URL", ""), help="DefectDojo base URL"
    )
    p.add_argument(
        "--token", default=os.environ.get("DEFECTDOJO_TOKEN", ""), help="DefectDojo API token"
    )
    p.add_argument("--product", required=True, help="Product name")
    p.add_argument("--engagement", required=True, help="Engagement name")
    p.add_argument(
        "--tool", required=True, help="Tool key (nmap, zap, greenbone, nuclei, generic, ...)"
    )
    p.add_argument("--file", required=True, help="Path to artifact file")
    p.add_argument("--environment", default="Development", help="DefectDojo environment label")
    args = p.parse_args()

    if not args.url or not args.token:
        raise SystemExit("DEFECTDOJO_URL and DEFECTDOJO_TOKEN are required")

    client = DefectDojoClient(args.url, args.token)
    client.import_tool_results(
        product_name=args.product,
        engagement_name=args.engagement,
        tool=args.tool,
        file_path=Path(args.file),
        environment=args.environment,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
