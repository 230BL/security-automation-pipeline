"""Inventory runner (merge inventory sources into a single artifact).

This runner reads inventory data from inventory/* sources and writes a
merged JSON snapshot to evidence/raw/inventory/.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from src.runners.base import BaseRunner

LOG = logging.getLogger(__name__)


class InventoryRunner(BaseRunner):
    tool_name = "inventory"

    def health_check(self) -> bool:
        return True

    def get_version(self) -> str:
        return "internal"

    def execute(self, targets: list[str], output_dir: Path) -> list[Path]:
        inv_root = Path("inventory")
        sources = ["cmdb", "dns", "ad", "cloud"]
        merged: dict[str, Any] = {"sources": {}, "targets": targets}

        for src in sources:
            d = inv_root / src
            files = list(d.rglob("*")) if d.exists() else []
            merged["sources"][src] = [str(p) for p in files if p.is_file()]

        output_dir.mkdir(parents=True, exist_ok=True)
        out = output_dir / f"inventory_{self.context.run_metadata.run_id}.json"
        out.write_text(json.dumps(merged, indent=2), encoding="utf-8")
        LOG.info("Wrote inventory snapshot: %s", out)
        return [out]
