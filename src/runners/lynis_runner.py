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


class LynisRunner(BaseRunner):
    tool_name = "lynis"

    def __init__(self, context: Any, config: dict[str, Any] | None = None) -> None:
        super().__init__(context, config)
        self.tool_config = self.config.get("lynis", {})

    def health_check(self) -> bool:
        return True

    def get_version(self) -> str:
        exe = shutil.which("lynis")
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
                return "lynis"
        return "collector"

    def execute(self, targets: list[str], output_dir: Path) -> list[Path]:
        mode = str(self.tool_config.get("mode", "collect")).lower()
        ansible_exe = shutil.which("ansible-playbook")
        if mode == "ansible" and ansible_exe:
            playbook = Path(self.tool_config.get("playbook", "ansible/playbooks/run_lynis.yml"))
            inventory = Path(self.tool_config.get("inventory", "ansible/inventories/lab/hosts.yml"))
            if not playbook.exists():
                raise RunnerExecutionError(f"Lynis Ansible playbook not found: {playbook}")
            cmd_args = [str(playbook), "-i", str(inventory)]
            timeout = int(self.tool_config.get("global_timeout", 7200))
            LOG.info("Running: %s", " ".join([ansible_exe, *cmd_args])[:200])
            r = subprocess.run(
                cmd_args,
                capture_output=True,
                text=True,
                shell=False,
                timeout=timeout,
                executable=ansible_exe,
            )
            if r.returncode != 0:
                raise RunnerExecutionError(
                    f"Ansible Lynis failed (rc={r.returncode}): {r.stderr[:200]}",
                    context={"stdout": r.stdout[:500], "stderr": r.stderr[:500]},
                )

        base = Path(self.tool_config.get("drop_dir", "evidence/raw/lynis"))
        base.mkdir(parents=True, exist_ok=True)
        dats = list(base.rglob("*.dat"))
        if not dats:
            stub = output_dir / "lynis_empty_report.dat"
            stub.write_text("", encoding="utf-8")
            return [stub]
        return dats
