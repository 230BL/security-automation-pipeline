"""Nmap runner for safe service validation.

Uses conservative profiles only. Never T5. Enforces exclusions
and rate limits from config/tools.yml.

Behavior:
- No stubs.
- If nmap is missing locally, optionally falls back to Docker.
- If a scan fails or produces no XML artifact, fail honestly.
- Uses a connect scan locally when not running with elevated privileges,
  so real scans still work under an unprivileged user such as `su - brahim`.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

from src.orchestrator.exceptions import RunnerExecutionError
from src.runners.base import BaseRunner

LOG = logging.getLogger(__name__)

NMAP_DOCKER_IMAGE = "instrumentisto/nmap:7.94"


class NmapRunner(BaseRunner):
    tool_name = "nmap"

    def __init__(self, context: Any, config: dict[str, Any] | None = None) -> None:
        super().__init__(context, config)
        safe_profile = self.config.get("nmap_safe_profile", {})
        nmap_config = self.config.get("nmap", {})
        self.tool_config = {**safe_profile, **nmap_config}

    def health_check(self) -> bool:
        return shutil.which("nmap") is not None or shutil.which("docker") is not None

    def get_version(self) -> str:
        nmap_exe = shutil.which("nmap")
        if nmap_exe is not None:
            try:
                result = subprocess.run(
                    [nmap_exe, "--version"],
                    capture_output=True,
                    text=True,
                    shell=False,
                    timeout=10,
                    check=False,
                )
                output = (result.stdout or result.stderr).splitlines()
                for line in output:
                    if "Nmap version" in line:
                        return line.strip()
            except Exception:
                LOG.debug("Failed to get local nmap version", exc_info=True)

        docker_exe = shutil.which("docker")
        if docker_exe is not None:
            try:
                result = subprocess.run(
                    [docker_exe, "run", "--rm", NMAP_DOCKER_IMAGE, "--version"],
                    capture_output=True,
                    text=True,
                    shell=False,
                    timeout=30,
                    check=False,
                )
                output = (result.stdout or result.stderr).splitlines()
                for line in output:
                    if "Nmap version" in line:
                        return f"{line.strip()} (docker)"
            except Exception:
                LOG.debug("Failed to get Docker nmap version", exc_info=True)

        return "unknown"

    @staticmethod
    def _is_privileged() -> bool:
        geteuid = getattr(os, "geteuid", None)
        if geteuid is None:
            return False
        try:
            uid = geteuid()
        except Exception:
            return False
        return bool(uid == 0)

    def _build_nmap_args(
        self,
        *,
        output_file: Path,
        target_file: Path,
        exclude_file: Path | None,
        local_execution: bool,
    ) -> list[str]:
        max_rate = int(self.tool_config.get("max_rate", 500))
        max_retries = int(self.tool_config.get("max_retries", 2))
        host_timeout = str(self.tool_config.get("host_timeout", "300s"))
        max_parallelism = int(self.tool_config.get("max_parallelism", 10))
        timing = str(self.tool_config.get("timing_template", "T3")).upper().lstrip("-")

        if timing == "T5":
            LOG.warning("Timing template T5 blocked. Falling back to T3.")
            timing = "T3"

        if local_execution and not self._is_privileged():
            scan_technique = "-sT"
        else:
            scan_technique = "-sS"

        nmap_args = [
            f"-{timing}",
            scan_technique,
            "-sV",
            "--version-intensity",
            "2",
            "--max-rate",
            str(max_rate),
            "--max-retries",
            str(max_retries),
            "--host-timeout",
            host_timeout,
            "--max-parallelism",
            str(max_parallelism),
            "-oX",
            str(output_file),
            "-iL",
            str(target_file),
        ]

        if exclude_file is not None:
            nmap_args.extend(["--excludefile", str(exclude_file)])

        return nmap_args

    @staticmethod
    def _truncate(text: str | None, limit: int = 500) -> str:
        if not text:
            return ""
        text = text.strip()
        return text[:limit]

    def _run_local(self, nmap_exe: str, nmap_args: list[str]) -> subprocess.CompletedProcess[str]:
        cmd = [nmap_exe, *nmap_args]
        LOG.info("Running nmap locally: %s", " ".join(cmd)[:400])
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            shell=False,
            timeout=int(self.tool_config.get("global_timeout", 3600)),
            check=False,
        )

    def _run_docker(
        self,
        docker_exe: str,
        *,
        output_dir: Path,
        output_file: Path,
        target_file: Path,
        exclude_file: Path | None,
        nmap_args: list[str],
    ) -> subprocess.CompletedProcess[str]:
        output_dir_abs = str(output_dir.resolve())

        def remap(arg: str) -> str:
            host_paths = {
                str(output_file): f"/scan/{output_file.name}",
                str(target_file): f"/scan/{target_file.name}",
            }
            if exclude_file is not None:
                host_paths[str(exclude_file)] = f"/scan/{exclude_file.name}"
            return host_paths.get(arg, arg)

        remapped_args = [remap(arg) for arg in nmap_args]
        cmd = [
            docker_exe,
            "run",
            "--rm",
            "--network",
            "host",
            "-v",
            f"{output_dir_abs}:/scan",
            NMAP_DOCKER_IMAGE,
            *remapped_args,
        ]
        LOG.info("Running nmap via Docker: %s", " ".join(cmd)[:400])
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            shell=False,
            timeout=int(self.tool_config.get("global_timeout", 3600)),
            check=False,
        )

    def execute(self, targets: list[str], output_dir: Path) -> list[Path]:
        output_dir.mkdir(parents=True, exist_ok=True)

        if not targets:
            raise RunnerExecutionError(
                "Nmap runner received no targets",
                context={"tool": self.tool_name},
            )

        nmap_exe = shutil.which("nmap")
        docker_exe = shutil.which("docker")

        if nmap_exe is None and docker_exe is None:
            raise RunnerExecutionError(
                "Neither nmap nor docker is installed",
                context={"tool": self.tool_name},
            )

        output_file = output_dir / f"nmap_{self.context.run_metadata.run_id}.xml"

        exclusions = self.context.manifest.all_exclusions()
        exclude_file: Path | None = None
        if exclusions:
            exclude_file = output_dir / "nmap_exclude.txt"
            exclude_file.write_text("\n".join(exclusions), encoding="utf-8")

        target_file = output_dir / "nmap_targets.txt"
        target_file.write_text("\n".join(targets), encoding="utf-8")

        local_execution = nmap_exe is not None
        nmap_args = self._build_nmap_args(
            output_file=output_file,
            target_file=target_file,
            exclude_file=exclude_file,
            local_execution=local_execution,
        )

        if nmap_exe is not None:
            result = self._run_local(nmap_exe, nmap_args)
        else:
            if docker_exe is None:
                raise RunnerExecutionError(
                    "Docker is not installed",
                    context={"tool": self.tool_name},
                )

            result = self._run_docker(
                docker_exe,
                output_dir=output_dir,
                output_file=output_file,
                target_file=target_file,
                exclude_file=exclude_file,
                nmap_args=nmap_args,
            )

        stderr = self._truncate(result.stderr)
        stdout = self._truncate(result.stdout)

        if result.returncode not in (0, 1):
            raise RunnerExecutionError(
                f"Nmap exited with code {result.returncode}",
                context={
                    "tool": self.tool_name,
                    "stderr": stderr,
                    "stdout": stdout,
                },
            )

        if not output_file.exists():
            raise RunnerExecutionError(
                "Nmap did not produce the expected XML output file",
                context={
                    "tool": self.tool_name,
                    "output_file": str(output_file),
                    "return_code": result.returncode,
                    "stderr": stderr,
                    "stdout": stdout,
                },
            )

        if output_file.stat().st_size == 0:
            raise RunnerExecutionError(
                "Nmap produced an empty XML output file",
                context={
                    "tool": self.tool_name,
                    "output_file": str(output_file),
                    "return_code": result.returncode,
                    "stderr": stderr,
                    "stdout": stdout,
                },
            )

        LOG.info("Nmap runner produced %s", output_file)
        return [output_file]
