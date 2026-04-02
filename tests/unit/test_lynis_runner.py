"""Unit tests for src/runners/lynis_runner.py."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from src.orchestrator.exceptions import RunnerError
from src.runners.lynis_runner import LynisRunner
from tests.unit.runner_test_context import build_gate_context


def test_lynis_stub_when_no_dat(tmp_path: Path, fixtures: Path) -> None:
    ctx = build_gate_context(tmp_path, fixtures)
    drop = tmp_path / "lynis_drop"
    r = LynisRunner(ctx, {"lynis": {"drop_dir": str(drop)}})
    paths = r.run(["192.168.56.10"], tmp_path / "out")
    assert len(paths) == 1
    assert paths[0].name == "lynis_empty_report.dat"


def test_lynis_collects_dat_files(tmp_path: Path, fixtures: Path) -> None:
    ctx = build_gate_context(tmp_path, fixtures)
    drop = tmp_path / "lynis_drop"
    drop.mkdir()
    dat = drop / "report.dat"
    dat.write_text("x", encoding="utf-8")
    r = LynisRunner(ctx, {"lynis": {"drop_dir": str(drop)}})
    paths = r.run(["192.168.56.10"], tmp_path / "out")
    assert paths == [dat]


def test_lynis_ansible_missing_playbook_raises(
    tmp_path: Path, fixtures: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = build_gate_context(tmp_path, fixtures)
    monkeypatch.setattr(
        "src.runners.lynis_runner.shutil.which",
        lambda name: "/bin/ansible-playbook" if name == "ansible-playbook" else None,
    )
    r = LynisRunner(ctx, {"lynis": {"mode": "ansible", "playbook": str(tmp_path / "missing.yml")}})
    with pytest.raises(RunnerError, match="not found"):
        r.run(["192.168.56.10"], tmp_path / "out")


def test_lynis_ansible_nonzero_raises(
    tmp_path: Path, fixtures: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = build_gate_context(tmp_path, fixtures)
    pb = tmp_path / "play.yml"
    pb.write_text("---\n", encoding="utf-8")
    inv = tmp_path / "hosts.yml"
    inv.write_text("all:\n  hosts:\n", encoding="utf-8")
    monkeypatch.setattr(
        "src.runners.lynis_runner.shutil.which",
        lambda name: "/bin/ansible-playbook" if name == "ansible-playbook" else None,
    )
    mock_run = MagicMock(return_value=MagicMock(returncode=1, stdout="", stderr="fail"))
    monkeypatch.setattr("src.runners.lynis_runner.subprocess.run", mock_run)
    r = LynisRunner(
        ctx,
        {
            "lynis": {
                "mode": "ansible",
                "playbook": str(pb),
                "inventory": str(inv),
            }
        },
    )
    drop = tmp_path / "ld"
    drop.mkdir()
    with pytest.raises(RunnerError, match="Ansible"):
        r.run(["192.168.56.10"], tmp_path / "out")


def test_lynis_get_version_collector(
    tmp_path: Path, fixtures: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = build_gate_context(tmp_path, fixtures)
    monkeypatch.setattr("src.runners.lynis_runner.shutil.which", lambda *_: None)
    assert LynisRunner(ctx).get_version() == "collector"
