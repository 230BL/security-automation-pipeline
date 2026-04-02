"""Prowler runner (cloud posture assessment).

Runs Prowler in read-only mode; this runner does not manage credentials.
Artifacts are JSON/JSONL exports written to output_dir.
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


class ProwlerRunner(BaseRunner):
    tool_name = "prowler"

    def __init__(self, context: Any, config: dict[str, Any] | None = None) -> None:
        super().__init__(context, config)
        self.tool_config = self.config.get("prowler", {})

    def health_check(self) -> bool:
        return True

    def get_version(self) -> str:
        exe = shutil.which("prowler")
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
                return (r.stdout or r.stderr).strip().splitlines()[0]
            except Exception:
                return "prowler"
        return "stub"

    def execute(self, targets: list[str], output_dir: Path) -> list[Path]:
        out = output_dir / f"prowler_{self.context.run_metadata.run_id}.json"
        out.write_text(json.dumps([], indent=2), encoding="utf-8")

        prowler_exe = shutil.which("prowler")
        if not prowler_exe:
            LOG.warning("Prowler not found; producing stub artifact at %s", out)
            return [out]

        provider = str(self.tool_config.get("provider", "aws"))
        timeout = int(self.tool_config.get("global_timeout", 21600))

        cmd_args = [provider, "-M", "json", "-F", str(out), "--no-banner"]
        LOG.info("Running: %s", " ".join([prowler_exe, *cmd_args])[:200])
        r = subprocess.run(
            cmd_args,
            capture_output=True,
            text=True,
            shell=False,
            timeout=timeout,
            executable=prowler_exe,
        )
        if r.returncode != 0:
            raise RunnerExecutionError(
                f"Prowler failed (rc={r.returncode}): {r.stderr[:200]}",
                context={"stdout": r.stdout[:500], "stderr": r.stderr[:500]},
            )

        return [out]
