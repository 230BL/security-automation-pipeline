"""Greenbone/OpenVAS runner.

Phase 1 implementation uses a safe stub CSV export when a native Greenbone
control channel (GMP/gvm-cli) is not available. In real deployments,
wire this runner to a dedicated Greenbone service account with
authenticated scans only.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from pathlib import Path
from typing import Any

from src.runners.base import BaseRunner

LOG = logging.getLogger(__name__)


class GreenboneRunner(BaseRunner):
    tool_name = "greenbone"

    def __init__(self, context: Any, config: dict[str, Any] | None = None) -> None:
        super().__init__(context, config)
        self.tool_config = self.config.get("greenbone", {})

    def health_check(self) -> bool:
        # gvm-cli is preferred; allow stub operation without it.
        return True

    def get_version(self) -> str:
        for exe_name in ("gvm-cli", "omp"):
            exe = shutil.which(exe_name)
            if exe:
                try:
                    r = subprocess.run(
                        ["--version"],
                        capture_output=True,
                        text=True,
                        shell=False,
                        timeout=10,
                        executable=exe,
                    )
                    out = (r.stdout or r.stderr).strip()
                    return out.splitlines()[0] if out else exe
                except Exception:
                    return exe_name
        return "stub"

    def execute(self, targets: list[str], output_dir: Path) -> list[Path]:
        # If gvm-cli exists, we still do not attempt to auto-provision tasks here,
        # because provisioning requires environment-specific GMP details.
        # Instead, we produce a deterministic CSV artifact capturing targets and
        # indicating that this run is a controlled stub in Phase 1.
        out = output_dir / f"openvas_{self.context.run_metadata.run_id}.csv"
        header = (
            "IP,Hostname,Port,NVT Name,CVSS,Severity,Summary,Solution,CVEs,NVT OID,Specific Result"
        )
        lines = [header]
        for t in targets[: min(len(targets), int(self.tool_config.get("max_concurrent_hosts", 5)))]:
            lines.append(f"{t},,,Greenbone stub,0.0,Info,Stub output (no scan executed),,,STUB,")
        out.write_text("\n".join(lines) + "\n", encoding="utf-8")
        LOG.warning("Greenbone runner produced stub output at %s", out)
        return [out]
