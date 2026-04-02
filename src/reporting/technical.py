from __future__ import annotations

from typing import Any


def remediation_status_stub(findings: list[dict[str, Any]]) -> dict[str, int]:
    """Compute basic remediation status distribution from finding fields.

    If a finding has `ticket_status` or `status`, it is counted; otherwise it's `untracked`.
    """
    counts = {"open": 0, "closed": 0, "in_progress": 0, "untracked": 0}
    for f in findings:
        status = str(f.get("ticket_status", f.get("status", ""))).lower()
        if status in ("closed", "done", "resolved"):
            counts["closed"] += 1
        elif status in ("in_progress", "in progress"):
            counts["in_progress"] += 1
        elif status in ("open", "new"):
            counts["open"] += 1
        else:
            counts["untracked"] += 1
    return counts
