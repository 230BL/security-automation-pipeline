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


def _no_findings_jsonl() -> str:
    return "\n"


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

    def _project_root(self) -> Path:
        base_dir = getattr(self.context, "base_dir", None)
        return Path(base_dir) if base_dir else Path.cwd()

    def _resolve_path(self, value: str | Path) -> Path:
        path = Path(value).expanduser()
        if path.is_absolute():
            return path
        return self._project_root() / path

    def health_check(self) -> bool:
        return True

    def get_version(self) -> str:
        exe = shutil.which("nuclei")
        if not exe:
            return "stub"

        try:
            result = subprocess.run(
                [exe, "-version"],
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
            LOG.debug("Failed to get Nuclei version: %s", exc)

        return "nuclei"

    def _candidate_template_dirs(self) -> list[Path]:
        configured = self.tool_config.get("templates_dir")
        env_path = os.getenv("NUCLEI_TEMPLATES_DIR")

        candidates: list[Path] = []
        if configured:
            candidates.append(self._resolve_path(str(configured)))
        if env_path:
            candidates.append(self._resolve_path(env_path))

        candidates.extend(
            [
                self._project_root() / "runners" / "nuclei" / "templates",
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
                check=False,
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

        run_id = self.context.run_metadata.run_id
        out = output_dir / f"nuclei_{run_id}.jsonl"
        stdout_log = output_dir / f"nuclei_{run_id}.stdout.log"
        stderr_log = output_dir / f"nuclei_{run_id}.stderr.log"

        nuclei_exe = shutil.which("nuclei")
        if not nuclei_exe:
            LOG.warning("Nuclei not found; producing non-breaking empty artifact at %s", out)
            out.write_text(_no_findings_jsonl(), encoding="utf-8")
            stdout_log.write_text("", encoding="utf-8")
            stderr_log.write_text("Nuclei executable not found\n", encoding="utf-8")
            return [out]

        policy_path = self._project_root() / "policy" / "approved_nuclei_templates.yml"
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
            check=False,
        )

        stdout_log.write_text(result.stdout or "", encoding="utf-8")
        stderr_log.write_text(result.stderr or "", encoding="utf-8")

        if result.returncode != 0:
            raise RunnerExecutionError(
                f"Nuclei failed (rc={result.returncode}): {(result.stderr or '')[:200]}",
                context={
                    "stdout": (result.stdout or "")[:500],
                    "stderr": (result.stderr or "")[:500],
                    "template_dir": str(template_dir),
                    "stdout_log": str(stdout_log),
                    "stderr_log": str(stderr_log),
                },
            )

        if not out.exists():
            LOG.info("Nuclei completed and produced no JSONL report; treating as no findings")
            out.write_text(_no_findings_jsonl(), encoding="utf-8")
            return [out]

        content = out.read_text(encoding="utf-8").strip()
        if not content:
            LOG.info("Nuclei completed with no findings for %d target(s)", len(targets))
            out.write_text(_no_findings_jsonl(), encoding="utf-8")

        return [out]
