#!/usr/bin/env python3
"""CLI helper to push findings and run metadata to OpenSearch."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.integrations.opensearch_client import OpenSearchClient  # noqa: E402


def main() -> int:
    p = argparse.ArgumentParser(description="Push findings to OpenSearch")
    p.add_argument("--host", default=os.environ.get("OPENSEARCH_HOST", "localhost"))
    p.add_argument("--port", default=os.environ.get("OPENSEARCH_PORT", "9200"))
    p.add_argument("--user", default=os.environ.get("OPENSEARCH_USER", "admin"))
    p.add_argument("--password", default=os.environ.get("OPENSEARCH_PASSWORD", "admin"))
    p.add_argument("--run-id", required=True)
    p.add_argument("--findings", required=True, help="Path to findings.json")
    p.add_argument("--metadata", default=None, help="Optional run metadata JSON file")
    args = p.parse_args()

    client = OpenSearchClient(
        host=args.host,
        port=int(args.port),
        http_auth=(args.user, args.password),
    )
    if not client.health_check():
        raise SystemExit("OpenSearch health check failed")

    findings_path = Path(args.findings)
    findings: list[dict[str, Any]] = json.loads(findings_path.read_text(encoding="utf-8"))
    if not isinstance(findings, list):
        raise SystemExit("Findings file must be a JSON array")

    client.index_findings(findings, run_id=args.run_id)

    if args.metadata:
        metadata = json.loads(Path(args.metadata).read_text(encoding="utf-8"))
        if not isinstance(metadata, dict):
            raise SystemExit("Metadata file must be a JSON object")
        client.index_run_metadata(args.run_id, metadata, finding_count=len(findings))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
