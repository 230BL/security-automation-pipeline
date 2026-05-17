"""Unit tests for src/runners/lynis_runner.py."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from src.orchestrator.exceptions import RunnerError
from src.runners.lynis_runner import LynisRunner
from tests.unit.runner_test_context import build_gate_context


def _fake_executable(path: Path) -> Path:
    path.write_text("#!/bin/sh\n", encoding="utf-8")
    path.chmod(0o755)
    return path


def test_lynis_fails_when_no_dat(tmp_path: Path, fixtures: Path) -> None:
    ctx = build_gate_context(tmp_path, fixtures)
    drop = tmp_path / "lynis_drop"

    runner = LynisRunner(ctx, {"lynis": {"drop_dir": str(drop)}})

    out_dir = tmp_path / "out"

    with pytest.raises(RunnerError, match="no non-empty .dat artifacts"):
        runner.run(["192.168.56.10"], out_dir)

    assert not list(out_dir.glob("*.dat"))


def test_lynis_fails_when_only_empty_dat_exists(tmp_path: Path, fixtures: Path) -> None:
    ctx = build_gate_context(tmp_path, fixtures)
    drop = tmp_path / "lynis_drop"
    drop.mkdir()

    empty_dat = drop / "empty.dat"
    empty_dat.write_text("", encoding="utf-8")

    runner = LynisRunner(ctx, {"lynis": {"drop_dir": str(drop)}})

    with pytest.raises(RunnerError, match="no non-empty .dat artifacts"):
        runner.run(["192.168.56.10"], tmp_path / "out")


def test_lynis_collects_non_empty_dat_files(tmp_path: Path, fixtures: Path) -> None:
    ctx = build_gate_context(tmp_path, fixtures)
    drop = tmp_path / "lynis_drop"
    drop.mkdir()

    dat = drop / "report.dat"
    dat.write_text(
        "hostname=target-c\n"
        "os_name=Ubuntu\n"
        "warning[]=AUTH-9282|SSH root login permitted|PermitRootLogin yes|h\n",
        encoding="utf-8",
    )

    out_dir = tmp_path / "out"

    runner = LynisRunner(ctx, {"lynis": {"drop_dir": str(drop)}})
    paths = runner.run(["192.168.56.10"], out_dir)

    assert len(paths) == 1
    assert paths[0].parent == out_dir
    assert paths[0].name == "report.dat"
    assert paths[0].read_text(encoding="utf-8") == dat.read_text(encoding="utf-8")


def test_lynis_local_health_check_false_when_executable_missing(
    tmp_path: Path,
    fixtures: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctx = build_gate_context(tmp_path, fixtures)

    monkeypatch.setattr("src.runners.lynis_runner.shutil.which", lambda *_: None)

    runner = LynisRunner(
        ctx,
        {
            "lynis": {
                "mode": "local",
                "executable": str(tmp_path / "missing-lynis"),
            }
        },
    )

    assert runner.health_check() is False


def test_lynis_local_success_produces_real_dat(
    tmp_path: Path,
    fixtures: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctx = build_gate_context(tmp_path, fixtures)
    exe = _fake_executable(tmp_path / "lynis")

    def fake_run(cmd: list[str], *args: object, **kwargs: object) -> MagicMock:
        if cmd == [str(exe), "--version"]:
            return MagicMock(returncode=0, stdout="3.0.9\n", stderr="")

        if cmd == ["hostname"]:
            return MagicMock(returncode=0, stdout="lab host\n", stderr="")

        if cmd and cmd[0] == str(exe):
            report_file = Path(cmd[cmd.index("--report-file") + 1])
            log_file = Path(cmd[cmd.index("--log-file") + 1])

            report_file.write_text(
                "hostname=lab-host\n"
                "os_name=Ubuntu\n"
                "warning[]=AUTH-9282|SSH root login permitted|PermitRootLogin yes|h\n",
                encoding="utf-8",
            )
            log_file.write_text("lynis log\n", encoding="utf-8")

            return MagicMock(returncode=0, stdout="ok", stderr="")

        raise AssertionError(f"Unexpected command: {cmd}")

    monkeypatch.setattr("src.runners.lynis_runner.subprocess.run", fake_run)

    runner = LynisRunner(
        ctx,
        {
            "lynis": {
                "mode": "local",
                "executable": str(exe),
                "global_timeout": 30,
            }
        },
    )

    paths = runner.run(["192.168.56.10"], tmp_path / "out")

    assert len(paths) == 1
    assert paths[0].exists()
    assert paths[0].suffix == ".dat"
    assert "lynis_lab_host_" in paths[0].name
    assert "warning[]=AUTH-9282" in paths[0].read_text(encoding="utf-8")


def test_lynis_local_nonzero_with_valid_report_does_not_raise(
    tmp_path: Path,
    fixtures: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctx = build_gate_context(tmp_path, fixtures)
    exe = _fake_executable(tmp_path / "lynis")

    def fake_run(cmd: list[str], *args: object, **kwargs: object) -> MagicMock:
        if cmd == [str(exe), "--version"]:
            return MagicMock(returncode=0, stdout="3.0.9\n", stderr="")

        if cmd == ["hostname"]:
            return MagicMock(returncode=0, stdout="lab-host\n", stderr="")

        if cmd and cmd[0] == str(exe):
            report_file = Path(cmd[cmd.index("--report-file") + 1])
            report_file.write_text(
                "hostname=lab-host\n"
                "suggestion[]=BOOT-5122|Enable bootloader password|GRUB missing password|m\n",
                encoding="utf-8",
            )
            return MagicMock(returncode=1, stdout="", stderr="warning")

        raise AssertionError(f"Unexpected command: {cmd}")

    monkeypatch.setattr("src.runners.lynis_runner.subprocess.run", fake_run)

    runner = LynisRunner(
        ctx,
        {
            "lynis": {
                "mode": "local",
                "executable": str(exe),
            }
        },
    )

    paths = runner.run(["192.168.56.10"], tmp_path / "out")

    assert len(paths) == 1
    assert paths[0].exists()
    assert "suggestion[]=BOOT-5122" in paths[0].read_text(encoding="utf-8")


def test_lynis_local_without_report_raises(
    tmp_path: Path,
    fixtures: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctx = build_gate_context(tmp_path, fixtures)
    exe = _fake_executable(tmp_path / "lynis")

    def fake_run(cmd: list[str], *args: object, **kwargs: object) -> MagicMock:
        if cmd == [str(exe), "--version"]:
            return MagicMock(returncode=0, stdout="3.0.9\n", stderr="")

        if cmd == ["hostname"]:
            return MagicMock(returncode=0, stdout="lab-host\n", stderr="")

        if cmd and cmd[0] == str(exe):
            return MagicMock(returncode=0, stdout="ok", stderr="")

        raise AssertionError(f"Unexpected command: {cmd}")

    monkeypatch.setattr("src.runners.lynis_runner.subprocess.run", fake_run)

    runner = LynisRunner(
        ctx,
        {
            "lynis": {
                "mode": "local",
                "executable": str(exe),
            }
        },
    )

    with pytest.raises(RunnerError, match="Local Lynis did not produce"):
        runner.run(["192.168.56.10"], tmp_path / "out")


def test_lynis_ansible_missing_playbook_raises(
    tmp_path: Path,
    fixtures: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctx = build_gate_context(tmp_path, fixtures)

    monkeypatch.setattr(
        "src.runners.lynis_runner.shutil.which",
        lambda name: "/bin/ansible-playbook" if name == "ansible-playbook" else None,
    )

    runner = LynisRunner(
        ctx,
        {
            "lynis": {
                "mode": "ansible",
                "playbook": str(tmp_path / "missing.yml"),
            }
        },
    )

    with pytest.raises(RunnerError, match="not found"):
        runner.run(["192.168.56.10"], tmp_path / "out")


def test_lynis_ansible_nonzero_raises(
    tmp_path: Path,
    fixtures: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctx = build_gate_context(tmp_path, fixtures)

    playbook = tmp_path / "play.yml"
    playbook.write_text("---\n", encoding="utf-8")

    inventory = tmp_path / "hosts.yml"
    inventory.write_text("all:\n  hosts:\n", encoding="utf-8")

    monkeypatch.setattr(
        "src.runners.lynis_runner.shutil.which",
        lambda name: "/bin/ansible-playbook" if name == "ansible-playbook" else None,
    )

    mock_run = MagicMock(return_value=MagicMock(returncode=1, stdout="", stderr="fail"))
    monkeypatch.setattr("src.runners.lynis_runner.subprocess.run", mock_run)

    runner = LynisRunner(
        ctx,
        {
            "lynis": {
                "mode": "ansible",
                "playbook": str(playbook),
                "inventory": str(inventory),
            }
        },
    )

    with pytest.raises(RunnerError, match="Ansible Lynis failed"):
        runner.run(["192.168.56.10"], tmp_path / "out")


def test_lynis_ansible_success_collects_dat(
    tmp_path: Path,
    fixtures: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctx = build_gate_context(tmp_path, fixtures)

    playbook = tmp_path / "play.yml"
    playbook.write_text("---\n", encoding="utf-8")

    inventory = tmp_path / "hosts.yml"
    inventory.write_text("all:\n  hosts:\n", encoding="utf-8")

    drop = tmp_path / "lynis_drop"
    drop.mkdir()

    dat = drop / "remote_report.dat"
    dat.write_text(
        "hostname=target-c\n"
        "suggestion[]=BOOT-5122|Enable bootloader password|GRUB missing password|m\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        "src.runners.lynis_runner.shutil.which",
        lambda name: "/bin/ansible-playbook" if name == "ansible-playbook" else None,
    )

    mock_run = MagicMock(return_value=MagicMock(returncode=0, stdout="ok", stderr=""))
    monkeypatch.setattr("src.runners.lynis_runner.subprocess.run", mock_run)

    runner = LynisRunner(
        ctx,
        {
            "lynis": {
                "mode": "ansible",
                "playbook": str(playbook),
                "inventory": str(inventory),
                "drop_dir": str(drop),
            }
        },
    )

    paths = runner.run(["192.168.56.10"], tmp_path / "out")

    assert len(paths) == 1
    assert paths[0].name == "remote_report.dat"
    assert paths[0].read_text(encoding="utf-8") == dat.read_text(encoding="utf-8")

    called_cmd = mock_run.call_args.args[0]
    assert called_cmd[0] == "/bin/ansible-playbook"
    assert str(playbook) in called_cmd
    assert str(inventory) in called_cmd


def test_lynis_get_version_collector(
    tmp_path: Path,
    fixtures: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctx = build_gate_context(tmp_path, fixtures)

    monkeypatch.setattr("src.runners.lynis_runner.shutil.which", lambda *_: None)

    assert LynisRunner(ctx).get_version() == "collector"
