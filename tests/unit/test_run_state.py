from __future__ import annotations

from pathlib import Path

from src.orchestrator.run_state import RunState


def test_run_state_marks_phases(tmp_path: Path) -> None:
    rs = RunState("RUN-1", state_dir=tmp_path)
    assert rs.is_complete("phase1") is False
    rs.mark_started("phase1")
    assert rs.get_status("phase1") == "running"
    rs.mark_complete("phase1", artifacts=["a.txt"])
    assert rs.is_complete("phase1") is True
    assert rs.get_artifacts("phase1") == ["a.txt"]


def test_run_state_marks_failed(tmp_path: Path) -> None:
    rs = RunState("RUN-2", state_dir=tmp_path)
    rs.mark_failed("phaseX", "boom")
    assert rs.is_failed("phaseX") is True
