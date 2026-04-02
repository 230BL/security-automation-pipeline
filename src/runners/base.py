"""Abstract base runner for all tool runners.

Enforces:
- Allowlist re-verification before execution
- Maintenance window check
- Start/end logging with tool version
- Artifact path tracking
"""

from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from src.orchestrator.exceptions import RunnerError, RunnerHealthError, TargetOutOfScopeError
from src.orchestrator.gate import GateContext
from src.orchestrator.maintenance_window import validate_window
from src.utils.logging_setup import step_context

LOG = logging.getLogger(__name__)


class BaseRunner(ABC):
    """Base class for all tool runners."""

    tool_name: str = "unknown"

    def __init__(self, context: GateContext, config: dict[str, Any] | None = None):
        self.context = context
        self.config = config or {}
        self.artifacts: list[Path] = []

    @abstractmethod
    def execute(self, targets: list[str], output_dir: Path) -> list[Path]:
        """Execute the tool against the given targets."""

    @abstractmethod
    def health_check(self) -> bool:
        """Verify the tool is available and functional."""

    @abstractmethod
    def get_version(self) -> str:
        """Return the tool version string."""

    def run(
        self, targets: list[str], output_dir: Path, window_name: str | None = None
    ) -> list[Path]:
        """Gated execution wrapper."""
        with step_context(f"runner_{self.tool_name}", self.tool_name):
            self.context.allowlist.enforce(targets)

            if window_name:
                validate_window(self.context.manifest, window_name)

            max_targets = self.context.manifest.max_target_count
            if len(targets) > max_targets:
                raise TargetOutOfScopeError(
                    set(),
                    message=f"Target count {len(targets)} exceeds ceiling {max_targets}",
                )

            if not self.health_check():
                raise RunnerHealthError(
                    f"{self.tool_name} health check failed", context={"tool": self.tool_name}
                )

            output_dir.mkdir(parents=True, exist_ok=True)
            version = self.get_version()
            LOG.info(
                "Starting %s (version: %s) against %d targets",
                self.tool_name,
                version,
                len(targets),
                extra={"target_count": len(targets)},
            )

            start = time.monotonic()
            try:
                artifacts = self.execute(targets, output_dir)
                duration = time.monotonic() - start
                self.artifacts = artifacts
                LOG.info(
                    "%s completed in %.1fs, produced %d artifacts",
                    self.tool_name,
                    duration,
                    len(artifacts),
                    extra={"duration_seconds": duration, "finding_count": len(artifacts)},
                )
                return artifacts
            except Exception as exc:
                duration = time.monotonic() - start
                LOG.error(
                    "%s failed after %.1fs: %s",
                    self.tool_name,
                    duration,
                    exc,
                    extra={"duration_seconds": duration, "status": "failed"},
                )
                raise RunnerError(
                    f"{self.tool_name} execution failed: {exc}",
                    context={"tool": self.tool_name, "duration_seconds": duration},
                ) from exc
