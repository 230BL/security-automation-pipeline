"""Structured JSON logging for pipeline runs.

Every log entry includes run_id, step_id, tool, and timestamp.
Outputs JSON lines to both console and a per-run log file.
"""

from __future__ import annotations

import json
import logging
import sys
from collections.abc import Generator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_RUN_CONTEXT: dict[str, str] = {}


class JsonFormatter(logging.Formatter):
    """Formats log records as JSON lines with pipeline context."""

    def format(self, record: logging.LogRecord) -> str:
        entry: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "run_id": _RUN_CONTEXT.get("run_id", ""),
            "step_id": _RUN_CONTEXT.get("step_id", ""),
            "tool": _RUN_CONTEXT.get("tool", ""),
        }
        if record.exc_info and record.exc_info[1]:
            entry["exception"] = str(record.exc_info[1])
            entry["exception_type"] = type(record.exc_info[1]).__name__

        for key in (
            "target_count",
            "finding_count",
            "artifact_path",
            "scope_hash",
            "targets_hash",
            "duration_seconds",
            "status",
        ):
            val = getattr(record, key, None)
            if val is not None:
                entry[key] = val
        return json.dumps(entry, default=str)


def setup_logging(
    run_id: str,
    log_dir: Path = Path("evidence/logs"),
    console_level: int = logging.INFO,
    file_level: int = logging.DEBUG,
) -> logging.Logger:
    """Configure root logger with JSON console and file handlers."""
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / f"{run_id}.jsonl"

    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    root.handlers.clear()

    formatter = JsonFormatter()

    console = logging.StreamHandler(sys.stdout)
    console.setLevel(console_level)
    console.setFormatter(formatter)
    root.addHandler(console)

    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setLevel(file_level)
    fh.setFormatter(formatter)
    root.addHandler(fh)

    _RUN_CONTEXT["run_id"] = run_id
    return root


def set_step_context(step_id: str, tool: str = "") -> None:
    """Set the current step and tool context for log entries."""
    _RUN_CONTEXT["step_id"] = step_id
    _RUN_CONTEXT["tool"] = tool


def clear_step_context() -> None:
    """Clear step-level context after a step completes."""
    _RUN_CONTEXT.pop("step_id", None)
    _RUN_CONTEXT.pop("tool", None)


@contextmanager
def step_context(step_id: str, tool: str = "") -> Generator[None, None, None]:
    """Context manager that sets and clears step context."""
    set_step_context(step_id, tool)
    try:
        yield
    finally:
        clear_step_context()


def get_logger(name: str) -> logging.Logger:
    """Get a named logger."""
    return logging.getLogger(name)
