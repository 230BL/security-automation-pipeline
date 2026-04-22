"""Nikto runner for web server misconfiguration checks.

Output format: XML (``-Format xml``).

Rationale: Nikto's JSON report plugin is broken in current portable builds
(crashes at nikto_report_json.plugin line 113 after producing real scan
results).  The XML reporter works correctly.  Downstream parsing uses
``parse_nikto_xml`` instead of the old ``parse_nikto_json``.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from pathlib import Path
from typing import Any

from src.orchestrator.exceptions import RunnerExecutionError
from src.runners.base import BaseRunner

LOG = logging.getLogger(__name__)

_EMPTY_XML = '<?xml version="1.0" ?>\n<niktoscan>\n  <niktoscan>\n  </niktoscan>\n</niktoscan>\n'


def _looks_like_web_target(target: str) -> bool:
    value = str(target).strip().lower()
    return value.startswith("http://") or value.startswith("https://")


class NiktoRunner(BaseRunner):
    """Run Nikto and store XML artifacts compatible with ``parse_nikto_xml``."""

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
            out = output_dir / f"nikto_{idx}.xml"
            stdout_log = output_dir / f"nikto_{idx}.stdout.log"
            stderr_log = output_dir / f"nikto_{idx}.stderr.log"

            # Pre-write a valid empty XML so the artifact always exists
            out.write_text(_EMPTY_XML, encoding="utf-8")

            if not _looks_like_web_target(target):
                LOG.warning(
                    "Nikto skipping non-web target '%s' (needs http:// or https://)",
                    target,
                )
                artifacts.append(out)
                continue

            if not nikto_exe:
                LOG.warning("Nikto not found; producing empty XML artifact for %s", target)
                artifacts.append(out)
                continue

            cmd_args = [
                nikto_exe,
                "-h",
                target,
                "-Format",
                "xml",
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

            # Nikto exit code is unreliable (returns 255 or 1 even on success).
            # Only treat a non-zero code as a hard failure when the output file
            # is still the pre-written empty placeholder.
            out_content = out.read_text(encoding="utf-8").strip() if out.exists() else ""
            produced_real_output = out_content not in {"", _EMPTY_XML.strip()}

            if result.returncode != 0 and not produced_real_output:
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

            if not out_content:
                LOG.warning(
                    "Nikto completed for %s without XML output; keeping empty artifact",
                    target,
                )
                out.write_text(_EMPTY_XML, encoding="utf-8")

            artifacts.append(out)

        return artifacts
