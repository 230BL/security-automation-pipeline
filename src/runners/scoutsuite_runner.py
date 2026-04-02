"""ScoutSuite runner (secondary cloud snapshot tool)."""

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


class ScoutSuiteRunner(BaseRunner):
    tool_name = "scoutsuite"

    def __init__(self, context: Any, config: dict[str, Any] | None = None) -> None:
        super().__init__(context, config)
        self.tool_config = self.config.get("scoutsuite", {})

    def health_check(self) -> bool:
        return True

    def get_version(self) -> str:
        exe = shutil.which("scout")
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
                return "scout"
        return "stub"

    def execute(self, targets: list[str], output_dir: Path) -> list[Path]:
        # ScoutSuite produces a directory; we collect JSON outputs if any.
        report_dir = output_dir / "scoutsuite_report"
        report_dir.mkdir(parents=True, exist_ok=True)

        scout_exe = shutil.which("scout")
        if not scout_exe:
            stub = report_dir / "scoutsuite_stub.json"
            stub.write_text(json.dumps({"findings": []}, indent=2), encoding="utf-8")
            return [stub]

        provider = str(self.tool_config.get("provider", "aws"))
        timeout = int(self.tool_config.get("global_timeout", 21600))
        cmd_args = ["--provider", provider, "--report-dir", str(report_dir), "--no-browser"]
        LOG.info("Running: %s", " ".join([scout_exe, *cmd_args])[:200])
        r = subprocess.run(
            cmd_args,
            capture_output=True,
            text=True,
            shell=False,
            timeout=timeout,
            executable=scout_exe,
        )
        if r.returncode != 0:
            raise RunnerExecutionError(
                f"ScoutSuite failed (rc={r.returncode}): {r.stderr[:200]}",
                context={"stdout": r.stdout[:500], "stderr": r.stderr[:500]},
            )

        jsons = list(report_dir.rglob("*.json"))
        return jsons if jsons else []
