"""osquery runner (results retrieval).

This runner collects structured inventory snapshots produced by osquery
packs/scheduled queries. It does not install or modify osquery.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from src.runners.base import BaseRunner

LOG = logging.getLogger(__name__)


class OsqueryRunner(BaseRunner):
    tool_name = "osquery"

    def __init__(self, context: Any, config: dict[str, Any] | None = None) -> None:
        super().__init__(context, config)
        self.tool_config = self.config.get("osquery", {})

    def health_check(self) -> bool:
        return True

    def get_version(self) -> str:
        return "collector"

    def execute(self, targets: list[str], output_dir: Path) -> list[Path]:
        base = Path(self.tool_config.get("drop_dir", "evidence/raw/osquery"))
        base.mkdir(parents=True, exist_ok=True)
        files = list(base.rglob("*.json"))
        if not files:
            stub = output_dir / "osquery_empty.json"
            stub.write_text(json.dumps({"findings": []}, indent=2), encoding="utf-8")
            return [stub]
        return files
