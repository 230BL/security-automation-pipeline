"""Nuclei runner with curated safe template enforcement.

Controls:
- Only runs with local approved templates directory.
- Enforces allowed/blocked tags and max severity from policy.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from pathlib import Path
from typing import Any

import yaml

from src.orchestrator.exceptions import RunnerExecutionError
from src.runners.base import BaseRunner

LOG = logging.getLogger(__name__)


def _empty_jsonl() -> str:
    return ""


class NucleiRunner(BaseRunner):
    tool_name = "nuclei"

    def __init__(self, context: Any, config: dict[str, Any] | None = None) -> None:
        super().__init__(context, config)
        self.tool_config = self.config.get("nuclei", {})

    def health_check(self) -> bool:
        return True

    def get_version(self) -> str:
        exe = shutil.which("nuclei")
        if exe:
            try:
                r = subprocess.run(
                    [exe, "-version"],
                    capture_output=True,
                    text=True,
                    shell=False,
                    timeout=10,
                )
                return (r.stdout or r.stderr).strip().splitlines()[0]
            except Exception:
                return "nuclei"
        return "stub"

    def execute(self, targets: list[str], output_dir: Path) -> list[Path]:
        out = output_dir / f"nuclei_{self.context.run_metadata.run_id}.jsonl"
        out.write_text(_empty_jsonl(), encoding="utf-8")

        nuclei_exe = shutil.which("nuclei")

        policy_path = Path("policy/approved_nuclei_templates.yml")
        policy: dict[str, Any] = {}
        if policy_path.exists():
            loaded_policy = yaml.safe_load(policy_path.read_text(encoding="utf-8")) or {}
            if isinstance(loaded_policy, dict):
                policy = loaded_policy

        allowed_tags = policy.get("allowed_template_tags", [])
        blocked_tags = policy.get("blocked_template_tags", [])
        max_severity = str(policy.get("max_severity", "medium")).lower()

        template_dir = Path("runners/nuclei/templates")
        template_dir.mkdir(parents=True, exist_ok=True)

        target_file = output_dir / "targets.txt"
        target_file.write_text("\n".join(targets), encoding="utf-8")

        if not nuclei_exe:
            LOG.warning("Nuclei not found; producing stub artifact at %s", out)
            return [out]

        args = [
            nuclei_exe,
            "-l",
            str(target_file),
            "-t",
            str(template_dir),
            "-jsonl",
            "-o",
            str(out),
            "-silent",
            "-duc",
            "-severity",
            f"info,low,{max_severity}",
            "-rate-limit",
            str(int(self.tool_config.get("rate_limit", 50))),
            "-bulk-size",
            str(int(self.tool_config.get("bulk_size", 25))),
            "-c",
            str(int(self.tool_config.get("concurrency", 10))),
            "-timeout",
            str(int(self.tool_config.get("timeout", 10))),
        ]

        if isinstance(allowed_tags, list) and allowed_tags:
            args += ["-tags", ",".join(str(t) for t in allowed_tags)]
        if isinstance(blocked_tags, list) and blocked_tags:
            args += ["-exclude-tags", ",".join(str(t) for t in blocked_tags)]

        LOG.info("Running: %s", " ".join(args)[:200])
        r = subprocess.run(
            args,
            capture_output=True,
            text=True,
            shell=False,
            timeout=int(self.tool_config.get("global_timeout", 7200)),
        )
        if r.returncode != 0:
            raise RunnerExecutionError(
                f"Nuclei failed (rc={r.returncode}): {r.stderr[:200]}",
                context={"stdout": r.stdout[:500], "stderr": r.stderr[:500]},
            )

        return [out]
