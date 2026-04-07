"""OWASP ZAP runner (Docker-based).

Governance:
- Active scans are allowed in staging/lab only.
- Runner produces XML report artifacts.
- When Docker image is unavailable or target is not a web URL, produces a
  non-breaking empty XML report.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from pathlib import Path
from typing import Any

from src.orchestrator.exceptions import EnvironmentMismatchError, RunnerExecutionError
from src.runners.base import BaseRunner

LOG = logging.getLogger(__name__)

ZAP_IMAGE = "ghcr.io/zaproxy/zaproxy:stable"


def _empty_zap_report_xml() -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<OWASPZAPReport version="2.15.0"></OWASPZAPReport>\n'
    )


def _is_web_target(target: str) -> bool:
    """Return True only if target looks like an HTTP/HTTPS URL."""
    return target.startswith("http://") or target.startswith("https://")


class ZapRunner(BaseRunner):
    tool_name = "zap"

    def __init__(self, context: Any, config: dict[str, Any] | None = None) -> None:
        super().__init__(context, config)
        self.tool_config = self.config.get("zap", {})

    def health_check(self) -> bool:
        return True

    def get_version(self) -> str:
        docker_exe = shutil.which("docker")
        if not docker_exe:
            return "unknown"

        try:
            result = subprocess.run(
                [docker_exe, "--version"],
                capture_output=True,
                text=True,
                shell=False,
                timeout=10,
                check=False,
            )
            output = (result.stdout or result.stderr).strip()
            return output or "docker"
        except (OSError, subprocess.SubprocessError):
            return "unknown"

    def _image_available(self, docker_exe: str) -> bool:
        """Check if ZAP image is already pulled locally."""
        try:
            result = subprocess.run(
                [docker_exe, "image", "inspect", ZAP_IMAGE],
                capture_output=True,
                text=True,
                shell=False,
                timeout=10,
                check=False,
            )
            return result.returncode == 0
        except (OSError, subprocess.SubprocessError):
            return False

    def _prepare_workdir(self, output_dir: Path) -> str:
        """Ensure the bind-mounted workdir exists for Dockerized ZAP."""
        output_dir.mkdir(parents=True, exist_ok=True)
        return str(output_dir.resolve())

    def _write_empty_report(self, out: Path) -> None:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(_empty_zap_report_xml(), encoding="utf-8")

    def execute(self, targets: list[str], output_dir: Path) -> list[Path]:
        env = self.context.run_metadata.environment
        mode = str(self.tool_config.get("mode", "baseline")).lower()

        if mode in ("full", "active", "auth", "api") and env not in ("staging", "lab"):
            raise EnvironmentMismatchError(
                f"ZAP active scan blocked outside staging/lab (env={env})"
            )

        artifacts: list[Path] = []
        timeout = int(self.tool_config.get("global_timeout", 7200))
        docker_exe = shutil.which("docker")
        workdir = self._prepare_workdir(output_dir)

        for idx, target in enumerate(targets):
            out = output_dir / f"zap_{idx}.xml"
            stdout_log = output_dir / f"zap_{idx}.stdout.log"
            stderr_log = output_dir / f"zap_{idx}.stderr.log"

            if not _is_web_target(target):
                LOG.warning(
                    "ZAP skipping non-web target '%s' (needs http:// or https://)",
                    target,
                )
                self._write_empty_report(out)
                stdout_log.write_text("", encoding="utf-8")
                stderr_log.write_text(
                    "Skipped non-web target; ZAP requires http:// or https://\n",
                    encoding="utf-8",
                )
                artifacts.append(out)
                continue

            if not docker_exe:
                LOG.warning("Docker not found; ZAP producing empty report for %s", target)
                self._write_empty_report(out)
                stdout_log.write_text("", encoding="utf-8")
                stderr_log.write_text("Docker executable not found\n", encoding="utf-8")
                artifacts.append(out)
                continue

            if not self._image_available(docker_exe):
                LOG.warning(
                    "ZAP image '%s' not found locally. Pull it manually with: docker pull %s",
                    ZAP_IMAGE,
                    ZAP_IMAGE,
                )
                self._write_empty_report(out)
                stdout_log.write_text("", encoding="utf-8")
                stderr_log.write_text(
                    f"ZAP image not available locally: {ZAP_IMAGE}\n",
                    encoding="utf-8",
                )
                artifacts.append(out)
                continue

            common_args = [
                "run",
                "--rm",
                "--user",
                "0:0",
                "-v",
                f"{workdir}:/zap/wrk:rw",
                ZAP_IMAGE,
            ]

            if mode in ("baseline", "passive"):
                cmd_args = [
                    *common_args,
                    "zap-baseline.py",
                    "--autooff",
                    "-t",
                    target,
                    "-x",
                    out.name,
                    "-I",
                ]
            else:
                cmd_args = [
                    *common_args,
                    "zap-full-scan.py",
                    "--autooff",
                    "-t",
                    target,
                    "-x",
                    out.name,
                    "-I",
                ]

            LOG.info("Running: %s", " ".join([docker_exe, *cmd_args])[:300])
            result = subprocess.run(
                [docker_exe, *cmd_args],
                capture_output=True,
                text=True,
                shell=False,
                timeout=timeout,
                check=False,
            )

            stdout_log.write_text(result.stdout or "", encoding="utf-8")
            stderr_log.write_text(result.stderr or "", encoding="utf-8")

            if result.returncode != 0:
                raise RunnerExecutionError(
                    f"ZAP failed (rc={result.returncode}): {(result.stderr or '')[:200]}",
                    context={
                        "target": target,
                        "stdout": (result.stdout or "")[:500],
                        "stderr": (result.stderr or "")[:500],
                        "stdout_log": str(stdout_log),
                        "stderr_log": str(stderr_log),
                    },
                )

            if not out.exists():
                LOG.warning(
                    "ZAP completed for %s without XML output; keeping empty report artifact",
                    target,
                )
                self._write_empty_report(out)
            else:
                content = out.read_text(encoding="utf-8").strip()
                if not content:
                    LOG.warning(
                        "ZAP completed for %s with empty XML output; keeping empty report artifact",
                        target,
                    )
                    self._write_empty_report(out)

            artifacts.append(out)

        return artifacts
