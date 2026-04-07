"""Lynis runner (host hardening audits).

Phase 1: collects existing Lynis .dat artifacts produced by Ansible.
Phase 2+: can invoke Ansible playbook if configured.
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


def _empty_lynis_report_dat() -> str:
    return (
        "# Lynis placeholder report\n"
        "# No non-empty Lynis .dat artifacts were collected for this run\n"
        "hostname=unknown\n"
        "os_name=\n"
    )


class LynisRunner(BaseRunner):
    tool_name = "lynis"

    def __init__(self, context: Any, config: dict[str, Any] | None = None) -> None:
        super().__init__(context, config)
        self.tool_config = self.config.get("lynis", {})

    def _project_root(self) -> Path:
        base_dir = getattr(self.context, "base_dir", None)
        return Path(base_dir) if base_dir else Path.cwd()

    def _resolve_path(self, value: str) -> Path:
        path = Path(value).expanduser()
        if path.is_absolute():
            return path

        project_relative = self._project_root() / path
        if project_relative.exists():
            return project_relative

        return path

    def _write_placeholder_artifact(self, output_dir: Path, reason: str) -> Path:
        output_dir.mkdir(parents=True, exist_ok=True)
        artifact = output_dir / "lynis_empty_report.dat"
        artifact.write_text(_empty_lynis_report_dat(), encoding="utf-8")
        LOG.warning("Lynis produced no usable .dat files; using placeholder artifact: %s", reason)
        return artifact

    def health_check(self) -> bool:
        mode = str(self.tool_config.get("mode", "collect")).lower()
        if mode == "ansible":
            return shutil.which("ansible-playbook") is not None
        return True

    def get_version(self) -> str:
        exe = shutil.which("lynis")
        if not exe:
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
            output = (result.stdout or result.stderr).strip()
            if output:
                return output.splitlines()[0]
        except Exception as exc:
            LOG.debug("Failed to get Lynis version: %s", exc)

        return "lynis"

    def _run_ansible(self) -> None:
        ansible_exe = shutil.which("ansible-playbook")
        if not ansible_exe:
            raise RunnerExecutionError(
                "Lynis mode is 'ansible' but ansible-playbook is not installed"
            )

        playbook = self._resolve_path(
            str(self.tool_config.get("playbook", "ansible/playbooks/run_lynis.yml"))
        )
        inventory = self._resolve_path(
            str(self.tool_config.get("inventory", "ansible/inventories/lab/hosts.yml"))
        )

        if not playbook.exists():
            raise RunnerExecutionError(f"Lynis Ansible playbook not found: {playbook}")

        if not inventory.exists():
            raise RunnerExecutionError(f"Lynis Ansible inventory not found: {inventory}")

        cmd = [ansible_exe, str(playbook), "-i", str(inventory)]
        timeout = int(self.tool_config.get("global_timeout", 7200))

        LOG.info("Running Lynis via Ansible: %s", " ".join(cmd)[:300])

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            shell=False,
            timeout=timeout,
            check=False,
        )

        if result.returncode != 0:
            raise RunnerExecutionError(
                f"Ansible Lynis failed (rc={result.returncode})",
                context={
                    "stdout": result.stdout[:500],
                    "stderr": result.stderr[:500],
                    "playbook": str(playbook),
                    "inventory": str(inventory),
                },
            )

    def execute(self, targets: list[str], output_dir: Path) -> list[Path]:
        del targets

        mode = str(self.tool_config.get("mode", "collect")).lower()

        if mode == "ansible":
            self._run_ansible()
        elif mode != "collect":
            raise RunnerExecutionError(f"Unsupported Lynis mode: {mode}")

        drop_dir = self._resolve_path(str(self.tool_config.get("drop_dir", "evidence/raw/lynis")))
        output_dir.mkdir(parents=True, exist_ok=True)

        if not drop_dir.exists():
            placeholder = self._write_placeholder_artifact(
                output_dir,
                f"drop directory does not exist: {drop_dir}",
            )
            return [placeholder]

        dats = sorted(
            path for path in drop_dir.rglob("*.dat") if path.is_file() and path.stat().st_size > 0
        )

        if not dats:
            placeholder = self._write_placeholder_artifact(
                output_dir,
                f"no non-empty .dat files found under {drop_dir}",
            )
            return [placeholder]

        LOG.info("Collected %d Lynis artifact(s) from %s", len(dats), drop_dir)
        return dats
