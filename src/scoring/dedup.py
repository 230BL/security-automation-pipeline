"""Finding deduplication based on stable fingerprints.

When duplicates exist, the finding with the highest composite_score
is retained. All others are logged and discarded.
"""

from __future__ import annotations

import logging
from typing import Any

LOG = logging.getLogger(__name__)


def deduplicate(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Deduplicate findings by fingerprint, keeping highest scored."""
    seen: dict[str, dict[str, Any]] = {}
    duplicates = 0

    for finding in findings:
        fp = str(finding.get("fingerprint", ""))
        if not fp:
            LOG.warning("Finding without fingerprint: %s", finding.get("title", "unknown"))
            continue

        existing = seen.get(fp)
        if existing is None:
            seen[fp] = finding
            continue

        duplicates += 1
        existing_score = float(existing.get("composite_score", 0) or 0)
        new_score = float(finding.get("composite_score", 0) or 0)
        if new_score > existing_score:
            seen[fp] = finding

    deduped = list(seen.values())
    LOG.info(
        "Deduplication: %d input → %d unique (%d duplicates removed)",
        len(findings),
        len(deduped),
        duplicates,
    )
    return deduped
