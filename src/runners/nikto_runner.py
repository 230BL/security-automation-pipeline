"""Nikto runner for web server misconfiguration checks."""

from __future__ import annotations

import json
import logging
import re
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


def _repair_nikto_json(raw: str) -> str:
    repaired = raw.strip()
    repaired = re.sub(r"}\s*{", "},{", repaired)
    repaired = repaired.replace(r"[\,", "[")
    return repaired


class NiktoRunner(BaseRunner):
    """Run Nikto and store JSON artifacts compatible with parse_nikto_json."""

    tool_name = "nikto"

    def __init__(
        self,
        context: Any,
        config: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(context, config)
        self.tool_config = self.config.get("nikto", {})

    def health_check(self) -> bool:
        return True

    def get_version(self) -> str:
        exe = shutil.which("nikto")
        if exe:
            try:
                result = subprocess.run(
                    [exe, "-Version"],
                    capture_output=True,
                    text=True,
                    shell=False,
                    timeout=10,
                    check=False,
                )
                output = (result.stdout or result.stderr or "").strip()
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

        output_dir.mkdir(parents=True, exist_ok=True)

        for idx, target in enumerate(targets):
            out = output_dir / f"nikto_{idx}.json"
            stdout_log = output_dir / f"nikto_{idx}.stdout.log"
            stderr_log = output_dir / f"nikto_{idx}.stderr.log"

            out.write_text("[]", encoding="utf-8")

            if not _looks_like_web_target(target):
                LOG.warning(
                    "Nikto skipping non-web target '%s' (needs http:// or https://)",
                    target,
                )
                artifacts.append(out)
                continue

            if not nikto_exe:
                LOG.warning("Nikto not found; producing empty JSON artifact for %s", target)
                artifacts.append(out)
                continue

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
            LOG.info("Running: %s", " ".join(cmd_args)[:300])

            result = subprocess.run(
                cmd_args,
                capture_output=True,
                text=True,
                shell=False,
                timeout=timeout,
                check=False,
            )

            stdout_log.write_text(result.stdout or "", encoding="utf-8")
            stderr_log.write_text(result.stderr or "", encoding="utf-8")

            raw_output = out.read_text(encoding="utf-8").strip() if out.exists() else ""

            if result.returncode != 0 and raw_output in {"", "[]", "{}"}:
                raise RunnerExecutionError(
                    f"Nikto failed (rc={result.returncode}): {(result.stderr or '').strip()[:200]}",
                    context={
                        "target": target,
                        "artifact": str(out),
                        "stdout_log": str(stdout_log),
                        "stderr_log": str(stderr_log),
                        "stdout": (result.stdout or "")[:500],
                        "stderr": (result.stderr or "")[:500],
                    },
                )

            if not raw_output:
                LOG.warning(
                    "Nikto completed for %s without JSON output; keeping empty artifact",
                    target,
                )
                out.write_text("[]", encoding="utf-8")
                artifacts.append(out)
                continue

            try:
                json.loads(raw_output)
            except json.JSONDecodeError:
                repaired = _repair_nikto_json(raw_output)
                try:
                    json.loads(repaired)
                except json.JSONDecodeError as exc:
                    corrupt_copy = output_dir / f"nikto_{idx}.json.corrupt"
                    corrupt_copy.write_text(raw_output, encoding="utf-8")
                    raise RunnerExecutionError(
                        f"Nikto produced invalid JSON for {target}: {exc}",
                        context={
                            "target": target,
                            "artifact": str(out),
                            "corrupt_copy": str(corrupt_copy),
                            "stdout_log": str(stdout_log),
                            "stderr_log": str(stderr_log),
                            "stdout": (result.stdout or "")[:500],
                            "stderr": (result.stderr or "")[:500],
                        },
                    ) from exc
                else:
                    out.write_text(repaired, encoding="utf-8")
                    LOG.warning("Nikto JSON repaired for %s", target)

            artifacts.append(out)

        return artifacts
