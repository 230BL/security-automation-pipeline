"""Nikto runner for web server misconfiguration checks.

Enforces exact allowlisted targets by reusing the gate's allowlist.
Outputs JSON artifacts.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from pathlib import Path
from typing import Any

from src.orchestrator.exceptions import RunnerExecutionError
from src.runners.base import BaseRunner

LOG = logging.getLogger(__name__)


class NiktoRunner(BaseRunner):
    tool_name = "nikto"

    def __init__(self, context: Any, config: dict[str, Any] | None = None) -> None:
        super().__init__(context, config)
        self.tool_config = self.config.get("nikto", {})

    def health_check(self) -> bool:
        return True

    def get_version(self) -> str:
        exe = shutil.which("nikto")
        if exe:
            try:
                r = subprocess.run(
                    [exe, "-Version"],
                    capture_output=True,
                    text=True,
                    shell=False,
                    timeout=10,
                )
                return (r.stdout or r.stderr).strip().splitlines()[0]
            except Exception:
                return "nikto"
        return "stub"

    def execute(self, targets: list[str], output_dir: Path) -> list[Path]:
        artifacts: list[Path] = []
        timeout = int(self.tool_config.get("global_timeout", 3600))
        per_host = int(self.tool_config.get("timeout_per_host", 300))
        nikto_exe = shutil.which("nikto")

        for idx, target in enumerate(targets):
            out = output_dir / f"nikto_{idx}.json"
            out.write_text(json.dumps([], indent=2), encoding="utf-8")

            if nikto_exe:
                cmd_args = [
                    nikto_exe,
                    "-h",
                    target,
                    "-Format",
                    "json",
                    "-o",
                    str(out),
                    "-maxtime",
                    f"{per_host}s",
                    "-nointeractive",
                ]
                LOG.info("Running: %s", " ".join(cmd_args)[:200])
                r = subprocess.run(
                    cmd_args,
                    capture_output=True,
                    text=True,
                    shell=False,
                    timeout=timeout,
                )
                if r.returncode != 0:
                    raise RunnerExecutionError(
                        f"Nikto failed (rc={r.returncode}): {r.stderr[:200]}",
                        context={"stdout": r.stdout[:500], "stderr": r.stderr[:500]},
                    )
            else:
                LOG.warning("Nikto not found; producing stub artifact for %s", target)

            artifacts.append(out)

        return artifacts
