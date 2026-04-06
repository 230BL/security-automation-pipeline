"""ScoutSuite runner for cloud security snapshots.

Behavior:
- No stubs.
- Requires a real ScoutSuite installation.
- Requires real cloud credentials/configuration for the selected provider.
- Fails honestly when the environment is not configured for a real cloud scan.
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

SUPPORTED_PROVIDERS = {"aws", "azure", "gcp"}


class ScoutSuiteRunner(BaseRunner):
    tool_name = "scoutsuite"

    def __init__(self, context: Any, config: dict[str, Any] | None = None) -> None:
        super().__init__(context, config)
        self.tool_config = self.config.get("scoutsuite", {})

    @staticmethod
    def _first_non_empty(*values: object) -> str | None:
        for value in values:
            if value is None:
                continue
            text = str(value).strip()
            if text:
                return text
        return None

    def _provider(self) -> str:
        return (
            (
                self._first_non_empty(
                    os.getenv("SCOUTSUITE_PROVIDER"),
                    self.tool_config.get("provider"),
                    "aws",
                )
                or "aws"
            )
            .strip()
            .lower()
        )

    def _binary(self) -> str | None:
        return shutil.which("scout") or shutil.which("ScoutSuite")

    def _credential_issues(self, provider: str) -> list[str]:
        issues: list[str] = []

        if provider == "aws":
            has_env_creds = all(
                [
                    self._first_non_empty(os.getenv("AWS_ACCESS_KEY_ID")),
                    self._first_non_empty(os.getenv("AWS_SECRET_ACCESS_KEY")),
                ]
            )
            has_profile = self._first_non_empty(
                os.getenv("AWS_PROFILE"),
                self.tool_config.get("aws_profile"),
            )
            if not has_env_creds and not has_profile:
                issues.append(
                    "missing AWS credentials "
                    "(AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY or AWS_PROFILE)"
                )

        elif provider == "azure":
            has_subscription = self._first_non_empty(
                os.getenv("AZURE_SUBSCRIPTION_ID"),
                self.tool_config.get("subscription_id"),
            )
            has_client_creds = all(
                [
                    self._first_non_empty(os.getenv("AZURE_CLIENT_ID")),
                    self._first_non_empty(os.getenv("AZURE_CLIENT_SECRET")),
                    self._first_non_empty(os.getenv("AZURE_TENANT_ID")),
                ]
            )
            if not has_subscription:
                issues.append(
                    "missing Azure subscription "
                    "(AZURE_SUBSCRIPTION_ID or scoutsuite.subscription_id)"
                )
            if not has_client_creds:
                issues.append(
                    "missing Azure service principal credentials "
                    "(AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID)"
                )

        elif provider == "gcp":
            creds_file = self._first_non_empty(
                os.getenv("GOOGLE_APPLICATION_CREDENTIALS"),
                self.tool_config.get("credentials_file"),
            )
            project_id = self._first_non_empty(
                os.getenv("GOOGLE_CLOUD_PROJECT"),
                os.getenv("GCP_PROJECT"),
                self.tool_config.get("project_id"),
            )
            if not creds_file:
                issues.append(
                    "missing GCP credentials file "
                    "(GOOGLE_APPLICATION_CREDENTIALS or "
                    "scoutsuite.credentials_file)"
                )
            elif not Path(creds_file).exists():
                issues.append(f"GCP credentials file does not exist: {creds_file}")
            if not project_id:
                issues.append(
                    "missing GCP project id "
                    "(GOOGLE_CLOUD_PROJECT, GCP_PROJECT, or scoutsuite.project_id)"
                )

        else:
            issues.append(f"unsupported ScoutSuite provider: {provider}")

        return issues

    def _runtime_issues(self) -> list[str]:
        issues: list[str] = []
        provider = self._provider()

        if self._binary() is None:
            issues.append("ScoutSuite executable not found (expected 'scout' or 'ScoutSuite')")

        if provider not in SUPPORTED_PROVIDERS:
            issues.append(f"unsupported ScoutSuite provider: {provider}")
            return issues

        issues.extend(self._credential_issues(provider))
        return issues

    def health_check(self) -> bool:
        issues = self._runtime_issues()
        if issues:
            LOG.error("ScoutSuite health check failed: %s", "; ".join(issues))
            return False
        return True

    def get_version(self) -> str:
        exe = self._binary()
        if exe is None:
            return "missing:scoutsuite"

        try:
            result = subprocess.run(
                [exe, "--version"],
                capture_output=True,
                text=True,
                shell=False,
                timeout=10,
                check=False,
            )
        except Exception:
            return "scoutsuite"

        output = (result.stdout or result.stderr).strip()
        return output.splitlines()[0] if output else "scoutsuite"

    def _build_command(self, report_dir: Path) -> list[str]:
        exe = self._binary()
        if exe is None:
            raise RunnerExecutionError(
                "ScoutSuite executable not found",
                context={"tool": self.tool_name},
            )

        provider = self._provider()
        if provider not in SUPPORTED_PROVIDERS:
            raise RunnerExecutionError(
                f"Unsupported ScoutSuite provider: {provider}",
                context={"tool": self.tool_name, "provider": provider},
            )

        cmd = [
            exe,
            "--provider",
            provider,
            "--report-dir",
            str(report_dir),
            "--no-browser",
        ]

        if provider == "aws":
            aws_profile = self._first_non_empty(
                os.getenv("AWS_PROFILE"),
                self.tool_config.get("aws_profile"),
            )
            if aws_profile:
                cmd.extend(["--profile", aws_profile])

        elif provider == "azure":
            subscription_id = self._first_non_empty(
                os.getenv("AZURE_SUBSCRIPTION_ID"),
                self.tool_config.get("subscription_id"),
            )
            if subscription_id:
                cmd.extend(["--subscription", subscription_id])

        elif provider == "gcp":
            project_id = self._first_non_empty(
                os.getenv("GOOGLE_CLOUD_PROJECT"),
                os.getenv("GCP_PROJECT"),
                self.tool_config.get("project_id"),
            )
            if project_id:
                cmd.extend(["--project-id", project_id])

        return cmd

    def execute(self, targets: list[str], output_dir: Path) -> list[Path]:
        del targets

        output_dir.mkdir(parents=True, exist_ok=True)
        report_dir = output_dir / "scoutsuite_report"
        report_dir.mkdir(parents=True, exist_ok=True)

        issues = self._runtime_issues()
        if issues:
            raise RunnerExecutionError(
                f"ScoutSuite is not configured correctly: {'; '.join(issues)}",
                context={"tool": self.tool_name, "provider": self._provider()},
            )

        cmd = self._build_command(report_dir)
        timeout = int(self.tool_config.get("global_timeout", 21600))

        LOG.info("Running ScoutSuite: %s", " ".join(cmd)[:400])
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
                f"ScoutSuite failed (rc={result.returncode})",
                context={
                    "tool": self.tool_name,
                    "provider": self._provider(),
                    "stdout": (result.stdout or "")[:500],
                    "stderr": (result.stderr or "")[:500],
                },
            )

        json_files = sorted(
            path
            for path in report_dir.rglob("*.json")
            if path.is_file() and path.stat().st_size > 0
        )

        if not json_files:
            raise RunnerExecutionError(
                "ScoutSuite completed but produced no JSON report artifacts",
                context={
                    "tool": self.tool_name,
                    "provider": self._provider(),
                    "report_dir": str(report_dir),
                    "stdout": (result.stdout or "")[:500],
                    "stderr": (result.stderr or "")[:500],
                },
            )

        LOG.info("ScoutSuite runner produced %d JSON artifact(s)", len(json_files))
        return json_files
