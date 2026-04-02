"""Nmap runner for safe service validation.

Uses conservative profiles only. Never T5. Enforces exclusions
and rate limits from config/tools.yml.

When nmap is not installed locally, falls back to running via Docker
using the instrumentisto/nmap image defined in compose/docker-compose.yml.
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

NMAP_DOCKER_IMAGE = "instrumentisto/nmap:7.94"


class NmapRunner(BaseRunner):
    tool_name = "nmap"

    def __init__(self, context: Any, config: dict[str, Any] | None = None) -> None:
        super().__init__(context, config)
        self.tool_config = self.config.get("nmap", self.config.get("nmap_safe_profile", {}))

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
                )
                for line in result.stdout.splitlines():
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
                )
                for line in result.stdout.splitlines():
                    if "Nmap version" in line:
                        return f"{line.strip()} (docker)"
            except Exception:
                LOG.debug("Failed to get Docker nmap version", exc_info=True)

        return "unknown"

    def execute(self, targets: list[str], output_dir: Path) -> list[Path]:
        nmap_exe = shutil.which("nmap")
        docker_exe_opt = shutil.which("docker")

        if nmap_exe is None and docker_exe_opt is None:
            LOG.warning("Neither nmap nor docker found; producing empty stub artifact")
            stub = output_dir / f"nmap_{self.context.run_metadata.run_id}.xml"
            stub.write_text(
                '<?xml version="1.0"?><nmaprun scanner="nmap" args="stub"></nmaprun>\n',
                encoding="utf-8",
            )
            return [stub]

        output_file = output_dir / f"nmap_{self.context.run_metadata.run_id}.xml"

        exclusions = self.context.manifest.all_exclusions()
        exclude_file = None
        if exclusions:
            exclude_file = output_dir / "nmap_exclude.txt"
            exclude_file.write_text("\n".join(exclusions), encoding="utf-8")

        target_file = output_dir / "nmap_targets.txt"
        target_file.write_text("\n".join(targets), encoding="utf-8")

        max_rate = int(self.tool_config.get("max_rate", 500))
        max_retries = int(self.tool_config.get("max_retries", 2))
        host_timeout = str(self.tool_config.get("host_timeout", "300s"))
        max_parallelism = int(self.tool_config.get("max_parallelism", 10))
        timing = str(self.tool_config.get("timing_template", "T3"))

        if timing.upper() in ("T5", "-T5"):
            LOG.warning("Timing template T5 blocked. Falling back to T3.")
            timing = "T3"

        nmap_args = [
            f"-{timing}",
            "-sS",
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
        if exclude_file:
            nmap_args.extend(["--excludefile", str(exclude_file)])

        if nmap_exe is not None:
            cmd = [nmap_exe, *nmap_args]
            LOG.info("Running nmap locally: %s", " ".join(cmd)[:200])
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                shell=False,
                timeout=int(self.tool_config.get("global_timeout", 3600)),
            )
        else:
            LOG.info("nmap not found locally; running via Docker image %s", NMAP_DOCKER_IMAGE)
            output_dir_abs = str(output_file.parent.resolve())

            if docker_exe_opt is None:
                LOG.error("Docker is not available and local nmap was not found")
                return []

            docker_exe = docker_exe_opt

            def _remap(arg: str) -> str:
                """Remap absolute host paths to container /scan/ paths."""
                host_paths = [str(output_file), str(target_file)]
                if exclude_file is not None:
                    host_paths.append(str(exclude_file))

                for host_path in host_paths:
                    if arg == host_path:
                        return f"/scan/{Path(host_path).name}"
                return arg

            remapped_args = [_remap(arg) for arg in nmap_args]
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
            LOG.info("Running nmap via Docker: %s", " ".join(cmd)[:200])
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                shell=False,
                timeout=int(self.tool_config.get("global_timeout", 3600)),
            )

        if result.returncode not in (0, 1):
            raise RunnerExecutionError(
                f"Nmap exited with code {result.returncode}: {result.stderr[:200]}",
                context={"stderr": result.stderr[:500], "stdout": result.stdout[:500]},
            )

        if not output_file.exists() or output_file.stat().st_size == 0:
            LOG.warning("Nmap produced no output")
            return []

        return [output_file]
