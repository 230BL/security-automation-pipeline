from __future__ import annotations

import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import yaml

from src.orchestrator.exceptions import RunnerExecutionError
from src.runners.base import BaseRunner

LOG = logging.getLogger(__name__)

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


def _empty_jsonl() -> str:
    return ""


def _has_templates(path: Path) -> bool:
    try:
        if not path.is_dir():
            return False

        for file_path in path.rglob("*"):
            try:
                if file_path.is_file() and file_path.suffix.lower() in {".yaml", ".yml"}:
                    return True
            except (PermissionError, OSError):
                continue
    except (PermissionError, OSError):
        return False

    return False


def _severity_range(max_severity: str) -> str:
    normalized = str(max_severity).strip().lower()
    if normalized not in SEVERITY_ORDER:
        normalized = "medium"
    index = SEVERITY_ORDER.index(normalized)
    return ",".join(SEVERITY_ORDER[: index + 1])


def _dedupe_paths(paths: list[Path]) -> list[Path]:
    seen: set[str] = set()
    unique: list[Path] = []
    for path in paths:
        expanded = path.expanduser()
        resolved = str(expanded)
        if resolved not in seen:
            seen.add(resolved)
            unique.append(expanded)
    return unique


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
                result = subprocess.run(
                    [exe, "-version"],
                    capture_output=True,
                    text=True,
                    shell=False,
                    timeout=10,
                )
                return (result.stdout or result.stderr).strip().splitlines()[0]
            except Exception:
                return "nuclei"
        return "stub"

    def _candidate_template_dirs(self) -> list[Path]:
        configured = self.tool_config.get("templates_dir")
        env_path = os.getenv("NUCLEI_TEMPLATES_DIR")

        candidates: list[Path] = []
        if configured:
            candidates.append(Path(str(configured)))
        if env_path:
            candidates.append(Path(env_path))

        candidates.extend(
            [
                Path("runners/nuclei/templates"),
                Path.home() / "nuclei-templates",
                Path.home() / ".local" / "nuclei-templates",
                Path("/root/nuclei-templates"),
            ]
        )
        return _dedupe_paths(candidates)

    def _resolve_template_dir(self) -> Path | None:
        for candidate in self._candidate_template_dirs():
            if _has_templates(candidate):
                return candidate
        return None

    def _ensure_templates(self, nuclei_exe: str) -> Path | None:
        resolved = self._resolve_template_dir()
        if resolved is not None:
            return resolved

        LOG.info("No populated Nuclei template directory found; attempting template update")
        try:
            update = subprocess.run(
                [nuclei_exe, "-update-templates"],
                capture_output=True,
                text=True,
                shell=False,
                timeout=int(self.tool_config.get("template_update_timeout", 900)),
            )
            if update.returncode != 0:
                LOG.warning(
                    "nuclei -update-templates failed: %s",
                    (update.stderr or update.stdout)[:500],
                )
        except Exception as exc:
            LOG.warning("Automatic template update failed: %s", exc)

        return self._resolve_template_dir()

    def execute(self, targets: list[str], output_dir: Path) -> list[Path]:
        output_dir.mkdir(parents=True, exist_ok=True)

        out = output_dir / f"nuclei_{self.context.run_metadata.run_id}.jsonl"
        out.write_text(_empty_jsonl(), encoding="utf-8")

        nuclei_exe = shutil.which("nuclei")
        if not nuclei_exe:
            LOG.warning("Nuclei not found; producing stub artifact at %s", out)
            return [out]

        policy_path = Path("policy/approved_nuclei_templates.yml")
        policy: dict[str, Any] = {}
        if policy_path.exists():
            loaded_policy = yaml.safe_load(policy_path.read_text(encoding="utf-8")) or {}
            if isinstance(loaded_policy, dict):
                policy = loaded_policy

        allowed_tags = policy.get("allowed_template_tags", [])
        blocked_tags = policy.get("blocked_template_tags", [])
        max_severity = _severity_range(str(policy.get("max_severity", "medium")))

        template_dir = self._ensure_templates(nuclei_exe)
        if template_dir is None:
            raise RunnerExecutionError(
                "Nuclei templates not found. Set NUCLEI_TEMPLATES_DIR or run "
                "'nuclei -update-templates'."
            )

        target_file = output_dir / "targets.txt"
        target_file.write_text("\n".join(targets), encoding="utf-8")

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
            max_severity,
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
            args += ["-tags", ",".join(str(tag) for tag in allowed_tags)]

        if isinstance(blocked_tags, list) and blocked_tags:
            args += ["-exclude-tags", ",".join(str(tag) for tag in blocked_tags)]

        LOG.info("Using Nuclei templates from %s", template_dir)
        LOG.info("Running: %s", " ".join(args)[:500])

        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            shell=False,
            timeout=int(self.tool_config.get("global_timeout", 7200)),
        )
        if result.returncode != 0:
            raise RunnerExecutionError(
                f"Nuclei failed (rc={result.returncode}): {result.stderr[:200]}",
                context={
                    "stdout": result.stdout[:500],
                    "stderr": result.stderr[:500],
                    "template_dir": str(template_dir),
                },
            )

        return [out]
