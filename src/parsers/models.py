"""Normalized finding model used by all parsers.

Every tool parser converts its output into Finding instances.
The Finding.fingerprint() method produces a stable deduplication key.
"""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class Finding:
    """Normalized finding from any tool."""

    tool: str
    asset_id: str
    title: str
    severity: str
    description: str
    evidence: str = ""
    endpoint: str | None = None
    vuln_id: str | None = None
    cve: str | None = None
    cvss: float | None = None
    remediation: str | None = None
    environment: str | None = None
    run_id: str | None = None
    tags: list[str] = field(default_factory=list)

    def fingerprint(self) -> str:
        """Stable deduplication key."""
        raw = "|".join(
            [
                self.tool,
                self.asset_id,
                self.endpoint or "",
                self.vuln_id or "",
                self.title.strip().lower(),
                self.severity.strip().lower(),
            ]
        )
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        """Convert to dict with fingerprint included."""
        d = asdict(self)
        d["fingerprint"] = self.fingerprint()
        return d
