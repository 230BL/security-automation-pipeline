"""OWASP ZAP runner (Docker-based).

Governance:
- Active scans are allowed in staging/lab only.
- Runner produces XML report artifacts.
- When Docker image is unavailable or target is not a web URL, produces a stub.
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
        '<?xml version="1.0" encoding="UTF-8"?><OWASPZAPReport version="2.15.0"></OWASPZAPReport>\n'
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
            )
            return result.stdout.strip() or "docker"
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
            )
            return result.returncode == 0
        except (OSError, subprocess.SubprocessError):
            return False

    def _prepare_workdir(self, output_dir: Path) -> str:
        """Ensure the bind-mounted workdir exists for Dockerized ZAP."""
        output_dir.mkdir(parents=True, exist_ok=True)
        return str(output_dir.resolve())

    def _prepare_report_file(self, out: Path) -> None:
        """Create a stub report so the pipeline always has a valid XML artifact."""
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
            self._prepare_report_file(out)

            if not _is_web_target(target):
                LOG.warning(
                    "ZAP skipping non-web target '%s' (needs http:// or https://)",
                    target,
                )
                artifacts.append(out)
                continue

            if not docker_exe:
                LOG.warning("Docker not found; ZAP producing stub for %s", target)
                artifacts.append(out)
                continue

            if not self._image_available(docker_exe):
                LOG.warning(
                    "ZAP image '%s' not found locally. Pull it manually with: docker pull %s",
                    ZAP_IMAGE,
                    ZAP_IMAGE,
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
            )

            if result.returncode != 0:
                raise RunnerExecutionError(
                    f"ZAP failed (rc={result.returncode}): {result.stderr[:200]}",
                    context={
                        "stdout": result.stdout[:500],
                        "stderr": result.stderr[:500],
                    },
                )

            artifacts.append(out)

        return artifacts
