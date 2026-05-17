"""Lynis runner for host hardening audit artifacts.

Modes:
- local: run Lynis locally and produce a real .dat artifact.
- collect: collect existing non-empty Lynis .dat files from a drop directory.
- ansible: run an Ansible playbook first, then collect non-empty .dat files.

No placeholder or stub artifacts are produced.
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from src.orchestrator.exceptions import RunnerExecutionError, RunnerOutputError
from src.runners.base import BaseRunner

LOG = logging.getLogger(__name__)


class LynisRunner(BaseRunner):
    """Run or collect real Lynis report-data artifacts."""

    tool_name = "lynis"

    def __init__(self, context: Any, config: dict[str, Any] | None = None) -> None:
        super().__init__(context, config)

        raw_tool_config = self.config.get("lynis", {})
        self.tool_config: dict[str, Any] = (
            raw_tool_config if isinstance(raw_tool_config, dict) else {}
        )

    def _project_root(self) -> Path:
        base_dir = getattr(self.context, "base_dir", None)
        return Path(base_dir) if base_dir else Path.cwd()

    def _resolve_path(self, value: str | Path) -> Path:
        path = Path(value).expanduser()
        if path.is_absolute():
            return path
        return self._project_root() / path

    def _mode(self) -> str:
        return str(self.tool_config.get("mode", "collect")).strip().lower()

    def _lynis_executable(self) -> str:
        configured = self.tool_config.get("executable")
        if configured:
            return str(configured)

        resolved = shutil.which("lynis")
        if resolved:
            return resolved

        return "lynis"

    def health_check(self) -> bool:
        mode = self._mode()

        if mode == "local":
            return (
                shutil.which(self._lynis_executable()) is not None
                or Path(self._lynis_executable()).exists()
            )

        if mode == "collect":
            return True

        if mode == "ansible":
            return shutil.which("ansible-playbook") is not None

        LOG.error("Unsupported Lynis mode: %s", mode)
        return False

    def get_version(self) -> str:
        exe = self._lynis_executable()

        if not shutil.which(exe) and not Path(exe).exists():
            return "collector"

        try:
            result = subprocess.run(
                [exe, "--version"],
                capture_output=True,
                text=True,
                shell=False,
                timeout=10,
                check=False,
            )
            output = (result.stdout or result.stderr or "").strip()
            if output:
                return output.splitlines()[0]
        except Exception as exc:
            LOG.debug("Failed to get Lynis version: %s", exc)

        return "lynis"

    def execute(self, targets: list[str], output_dir: Path) -> list[Path]:
        mode = self._mode()

        if mode == "local":
            return self._run_local(output_dir)

        if mode == "ansible":
            self._run_ansible()
        elif mode != "collect":
            raise RunnerExecutionError(
                f"Unsupported Lynis mode: {mode}",
                context={"mode": mode},
            )

        drop_dir = self._resolve_path(str(self.tool_config.get("drop_dir", "evidence/raw/lynis")))

        dat_files = self._find_non_empty_dat_files(drop_dir)
        if not dat_files:
            raise RunnerOutputError(
                "Lynis produced no non-empty .dat artifacts",
                context={
                    "drop_dir": str(drop_dir),
                    "mode": mode,
                    "targets": targets,
                },
            )

        artifacts = self._copy_artifacts(dat_files, output_dir)

        LOG.info(
            "Collected %d Lynis .dat artifact(s) from %s",
            len(artifacts),
            drop_dir,
        )

        return artifacts

    def _safe_slug(self, value: str) -> str:
        cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "_", value.strip())
        return cleaned.strip("._-") or "unknown"

    def _run_local(self, output_dir: Path) -> list[Path]:
        exe = self._lynis_executable()

        if not shutil.which(exe) and not Path(exe).exists():
            raise RunnerExecutionError(
                "Lynis executable not found",
                context={"executable": exe},
            )

        output_dir.mkdir(parents=True, exist_ok=True)

        run_id = self._safe_slug(str(getattr(self.context, "run_id", "run")))
        hostname = self._safe_slug(
            subprocess.run(
                ["hostname"],
                capture_output=True,
                text=True,
                shell=False,
                timeout=5,
                check=False,
            ).stdout.strip()
            or "localhost"
        )

        report_file = output_dir / f"lynis_{hostname}_{run_id}.dat"
        log_file = output_dir / f"lynis_{hostname}_{run_id}.log"

        cmd = [
            exe,
            "audit",
            "system",
            "--quick",
            "--no-colors",
            "--report-file",
            str(report_file),
            "--log-file",
            str(log_file),
        ]

        timeout = int(self.tool_config.get("global_timeout", 1800))

        LOG.info("Running Lynis locally: %s", " ".join(cmd)[:300])

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                shell=False,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise RunnerExecutionError(
                f"Local Lynis timed out after {timeout}s",
                context={"timeout": timeout, "cmd": cmd},
            ) from exc

        if not report_file.exists() or report_file.stat().st_size == 0:
            raise RunnerOutputError(
                "Local Lynis did not produce a non-empty .dat artifact",
                context={
                    "returncode": result.returncode,
                    "stdout": (result.stdout or "")[:1000],
                    "stderr": (result.stderr or "")[:1000],
                    "report_file": str(report_file),
                    "log_file": str(log_file),
                },
            )

        if result.returncode != 0:
            LOG.warning(
                "Lynis exited with rc=%s but produced a valid report: %s",
                result.returncode,
                report_file,
            )

        return [report_file]

    def _run_ansible(self) -> None:
        ansible_exe = shutil.which("ansible-playbook")
        if not ansible_exe:
            raise RunnerExecutionError("ansible-playbook not found for Lynis ansible mode")

        playbook = self._resolve_path(
            str(self.tool_config.get("playbook", "ansible/playbooks/run_lynis.yml"))
        )
        inventory = self._resolve_path(
            str(self.tool_config.get("inventory", "ansible/inventories/lab/hosts.yml"))
        )

        if not playbook.exists():
            raise RunnerExecutionError(
                f"Lynis Ansible playbook not found: {playbook}",
                context={"playbook": str(playbook)},
            )

        if not inventory.exists():
            raise RunnerExecutionError(
                f"Lynis Ansible inventory not found: {inventory}",
                context={"inventory": str(inventory)},
            )

        timeout = int(self.tool_config.get("global_timeout", 7200))
        cmd = [ansible_exe, str(playbook), "-i", str(inventory)]

        LOG.info("Running Lynis Ansible playbook: %s", " ".join(cmd)[:300])

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                shell=False,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise RunnerExecutionError(
                f"Ansible Lynis timed out after {timeout}s",
                context={
                    "playbook": str(playbook),
                    "inventory": str(inventory),
                    "timeout": timeout,
                },
            ) from exc

        if result.returncode != 0:
            raise RunnerExecutionError(
                f"Ansible Lynis failed (rc={result.returncode}): "
                f"{(result.stderr or result.stdout or '').strip()[:300]}",
                context={
                    "playbook": str(playbook),
                    "inventory": str(inventory),
                    "stdout": (result.stdout or "")[:1000],
                    "stderr": (result.stderr or "")[:1000],
                },
            )

    def _find_non_empty_dat_files(self, drop_dir: Path) -> list[Path]:
        if not drop_dir.exists():
            LOG.warning("Lynis drop directory does not exist: %s", drop_dir)
            return []

        dat_files: list[Path] = []

        for path in sorted(drop_dir.rglob("*.dat")):
            try:
                if path.is_file() and path.stat().st_size > 0:
                    dat_files.append(path)
                elif path.is_file():
                    LOG.warning("Ignoring empty Lynis artifact: %s", path)
            except OSError as exc:
                LOG.warning("Unable to inspect Lynis artifact %s: %s", path, exc)

        return dat_files

    def _copy_artifacts(self, sources: list[Path], output_dir: Path) -> list[Path]:
        output_dir.mkdir(parents=True, exist_ok=True)

        artifacts: list[Path] = []

        for index, source in enumerate(sources):
            destination = output_dir / source.name

            if destination.exists() and source.resolve() != destination.resolve():
                destination = output_dir / f"lynis_{index}_{source.name}"

            if source.resolve() != destination.resolve():
                shutil.copy2(source, destination)

            artifacts.append(destination)

        return artifacts
