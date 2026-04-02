#!/usr/bin/env python3
"""Bootstrap DefectDojo product/engagement structure for the pipeline."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.integrations.defectdojo_client import DefectDojoClient  # noqa: E402
from src.orchestrator.manifest import load_manifest  # noqa: E402


def main() -> int:
    p = argparse.ArgumentParser(description="Setup DefectDojo product & engagement")
    p.add_argument("--url", default=os.environ.get("DEFECTDOJO_URL", "http://localhost:8080"))
    p.add_argument("--token", default=os.environ.get("DEFECTDOJO_TOKEN", ""))
    p.add_argument("--product", default=None, help="Override product name")
    p.add_argument("--engagement", default=None, help="Override engagement name")
    args = p.parse_args()

    if not args.token:
        raise SystemExit("DEFECTDOJO_TOKEN is required")

    manifest = load_manifest(ROOT / "scope" / "scope_manifest.yml")
    product_name = args.product or manifest.assessment_name
    engagement_name = args.engagement or "security-automation"

    client = DefectDojoClient(args.url, args.token)
    pid = client.get_or_create_product(product_name)
    client.get_or_create_engagement(pid, engagement_name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
