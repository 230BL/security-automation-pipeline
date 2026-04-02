"""Unit tests for src/utils/logging_setup.py."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from src.utils import logging_setup as ls


def test_setup_logging_creates_handlers_and_sets_run_id(tmp_path: Path) -> None:
    log_dir = tmp_path / "logs"
    root = ls.setup_logging("RUN-X", log_dir=log_dir, console_level=logging.WARNING)
    assert isinstance(root, logging.Logger)
    assert len(root.handlers) == 2
    assert (log_dir / "RUN-X.jsonl").exists()
    assert ls._RUN_CONTEXT.get("run_id") == "RUN-X"


def test_setup_logging_clears_previous_handlers(tmp_path: Path) -> None:
    ls.setup_logging("RUN-A", log_dir=tmp_path / "a")
    ls.setup_logging("RUN-B", log_dir=tmp_path / "b")
    root = logging.getLogger()
    assert len(root.handlers) == 2


def test_json_formatter_includes_exception_and_extra_fields() -> None:
    fmt = ls.JsonFormatter()
    rec = logging.LogRecord(
        name="test",
        level=logging.ERROR,
        pathname="x",
        lineno=1,
        msg="boom",
        args=(),
        exc_info=None,
    )
    rec.target_count = 3
    rec.finding_count = 5
    line = fmt.format(rec)
    data = json.loads(line)
    assert data["message"] == "boom"
    assert data["target_count"] == 3
    assert data["finding_count"] == 5

    try:
        raise ValueError("inner")
    except ValueError:
        rec2 = logging.LogRecord(
            name="test",
            level=logging.ERROR,
            pathname="x",
            lineno=1,
            msg="with exc",
            args=(),
            exc_info=__import__("sys").exc_info(),
        )
        line2 = fmt.format(rec2)
        data2 = json.loads(line2)
        assert "exception" in data2
        assert data2["exception_type"] == "ValueError"


def test_step_context_sets_and_clears() -> None:
    ls._RUN_CONTEXT.clear()
    with ls.step_context("step-1", "nmap"):
        assert ls._RUN_CONTEXT.get("step_id") == "step-1"
        assert ls._RUN_CONTEXT.get("tool") == "nmap"
    assert "step_id" not in ls._RUN_CONTEXT
    assert "tool" not in ls._RUN_CONTEXT


def test_get_logger_returns_named_logger() -> None:
    log = ls.get_logger("my.module")
    assert log.name == "my.module"
