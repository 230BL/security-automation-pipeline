"""Nikto runner for web server misconfiguration checks."""

from __future__ import annotations

import logging
import shutil
import subprocess
from pathlib import Path
from typing import Any

from src.orchestrator.exceptions import RunnerExecutionError
from src.runners.base import BaseRunner

LOG = logging.getLogger(__name__)


def _looks_like_web_target(target: str) -> bool:
    value = str(target).strip().lower()
    return value.startswith("http://") or value.startswith("https://")


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
                    check=False,
                )
                output = (r.stdout or r.stderr or "").strip()
                if output:
                    return output.splitlines()[0]
            except Exception:
                return "nikto"
        return "stub"

    def execute(self, targets: list[str], output_dir: Path) -> list[Path]:
        artifacts: list[Path] = []
        timeout = int(self.tool_config.get("global_timeout", 3600))
        per_host = int(self.tool_config.get("timeout_per_host", 300))
        nikto_exe = shutil.which("nikto")

        for idx, target in enumerate(targets):
            out = output_dir / f"nikto_{idx}.txt"
            stdout_log = output_dir / f"nikto_{idx}.stdout.log"
            stderr_log = output_dir / f"nikto_{idx}.stderr.log"

            out.write_text("", encoding="utf-8")

            if not _looks_like_web_target(target):
                LOG.warning(
                    "Nikto skipping non-web target '%s' (needs http:// or https://)",
                    target,
                )
                artifacts.append(out)
                continue

            if not nikto_exe:
                LOG.warning("Nikto not found; producing empty artifact for %s", target)
                artifacts.append(out)
                continue

            cmd_args = [
                nikto_exe,
                "-h",
                target,
                "-Format",
                "txt",
                "-o",
                str(out),
                "-maxtime",
                f"{per_host}s",
                "-nointeractive",
            ]
            LOG.info("Running: %s", " ".join(cmd_args)[:300])

            r = subprocess.run(
                cmd_args,
                capture_output=True,
                text=True,
                shell=False,
                timeout=timeout,
                check=False,
            )

            stdout_log.write_text(r.stdout or "", encoding="utf-8")
            stderr_log.write_text(r.stderr or "", encoding="utf-8")

            if r.returncode != 0:
                stderr_text = (r.stderr or "").strip()
                stdout_text = (r.stdout or "").strip()

                if not out.exists() or not out.read_text(encoding="utf-8").strip():
                    raise RunnerExecutionError(
                        f"Nikto failed (rc={r.returncode}): {stderr_text[:200]}",
                        context={
                            "stdout": stdout_text[:500],
                            "stderr": stderr_text[:500],
                        },
                    )

                LOG.warning(
                    "Nikto returned rc=%s for %s but produced a text report; continuing",
                    r.returncode,
                    target,
                )

            artifacts.append(out)

        return artifacts
