"""Unit tests for src/runners/nuclei_runner.py."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from src.orchestrator.exceptions import RunnerError
from src.runners.nuclei_runner import NucleiRunner
from tests.unit.runner_test_context import build_gate_context


def _make_template_dir(tmp_path: Path) -> Path:
    template_dir = tmp_path / "nuclei-templates"
    template_dir.mkdir()
    (template_dir / "test-template.yaml").write_text(
        "id: test-template\ninfo:\n  name: test-template\n  author: unit-test\n  severity: info\n",
        encoding="utf-8",
    )
    return template_dir


def test_nuclei_stub_without_binary(
    tmp_path: Path, fixtures: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = build_gate_context(tmp_path, fixtures, run_id="RUN-NU")
    monkeypatch.setattr("src.runners.nuclei_runner.shutil.which", lambda *_: None)
    paths = NucleiRunner(ctx).run(["192.168.56.10"], tmp_path / "out")
    assert len(paths) == 1
    assert paths[0].name.startswith("nuclei_")


def test_nuclei_success_invokes_subprocess(
    tmp_path: Path, fixtures: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = build_gate_context(tmp_path, fixtures, run_id="RUN-NU")
    template_dir = _make_template_dir(tmp_path)

    monkeypatch.setenv("NUCLEI_TEMPLATES_DIR", str(template_dir))
    monkeypatch.setattr("src.runners.nuclei_runner.shutil.which", lambda *_: "/bin/nuclei")

    mock_run = MagicMock(return_value=MagicMock(returncode=0, stdout="", stderr=""))
    monkeypatch.setattr("src.runners.nuclei_runner.subprocess.run", mock_run)

    out = tmp_path / "out"
    NucleiRunner(ctx).run(["192.168.56.10"], out)

    args = mock_run.call_args[0][0]
    assert args[0] == "/bin/nuclei"
    assert "-jsonl" in args
    assert str(template_dir) in args


def test_nuclei_nonzero_raises(
    tmp_path: Path, fixtures: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = build_gate_context(tmp_path, fixtures)
    template_dir = _make_template_dir(tmp_path)

    monkeypatch.setenv("NUCLEI_TEMPLATES_DIR", str(template_dir))
    monkeypatch.setattr("src.runners.nuclei_runner.shutil.which", lambda *_: "/bin/nuclei")
    monkeypatch.setattr(
        "src.runners.nuclei_runner.subprocess.run",
        lambda *_a, **_k: MagicMock(returncode=1, stdout="", stderr="bad"),
    )

    with pytest.raises(RunnerError, match="Nuclei failed"):
        NucleiRunner(ctx).run(["192.168.56.10"], tmp_path / "out")
