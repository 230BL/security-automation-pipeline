"""Unit tests for src/runners/nmap_runner.py."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from src.orchestrator.exceptions import RunnerError
from src.runners.nmap_runner import NMAP_DOCKER_IMAGE, NmapRunner
from tests.unit.runner_test_context import build_gate_context


def test_nmap_health_no_tools(
    tmp_path: Path, fixtures: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = build_gate_context(tmp_path, fixtures)
    monkeypatch.setattr("src.runners.nmap_runner.shutil.which", lambda *_: None)
    assert NmapRunner(ctx).health_check() is False


def test_nmap_health_with_nmap(
    tmp_path: Path, fixtures: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = build_gate_context(tmp_path, fixtures)
    monkeypatch.setattr(
        "src.runners.nmap_runner.shutil.which",
        lambda name: f"/{name}" if name in ("nmap", "docker") else None,
    )
    assert NmapRunner(ctx).health_check() is True


def test_nmap_get_version_local(
    tmp_path: Path, fixtures: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = build_gate_context(tmp_path, fixtures)
    monkeypatch.setattr(
        "src.runners.nmap_runner.shutil.which", lambda name: "/bin/nmap" if name == "nmap" else None
    )
    mock_run = MagicMock(
        return_value=MagicMock(
            stdout="Nmap version 7.94\n",
            stderr="",
            returncode=0,
        )
    )
    monkeypatch.setattr("src.runners.nmap_runner.subprocess.run", mock_run)
    assert NmapRunner(ctx).get_version() == "Nmap version 7.94"


def test_nmap_get_version_docker_fallback(
    tmp_path: Path, fixtures: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = build_gate_context(tmp_path, fixtures)

    def which(name: str) -> str | None:
        if name == "docker":
            return "/bin/docker"
        return None

    monkeypatch.setattr("src.runners.nmap_runner.shutil.which", which)
    mock_run = MagicMock(
        return_value=MagicMock(
            stdout="Nmap version 7.94\n",
            stderr="",
            returncode=0,
        )
    )
    monkeypatch.setattr("src.runners.nmap_runner.subprocess.run", mock_run)
    assert NmapRunner(ctx).get_version() == "Nmap version 7.94 (docker)"


def test_nmap_get_version_unknown(
    tmp_path: Path, fixtures: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = build_gate_context(tmp_path, fixtures)
    monkeypatch.setattr("src.runners.nmap_runner.shutil.which", lambda *_: None)
    assert NmapRunner(ctx).get_version() == "unknown"


def test_nmap_execute_stub_no_nmap_no_docker(
    tmp_path: Path, fixtures: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = build_gate_context(tmp_path, fixtures, run_id="RUN-NM")
    monkeypatch.setattr("src.runners.nmap_runner.shutil.which", lambda *_: None)
    # health_check would fail with no tools; call execute() as direct entry for stub artifact
    out = tmp_path / "out"
    out.mkdir(parents=True, exist_ok=True)
    paths = NmapRunner(ctx).execute(["192.168.56.10"], out)
    assert len(paths) == 1
    assert paths[0].read_text(encoding="utf-8").startswith("<?xml")


def test_nmap_execute_local_success(
    tmp_path: Path, fixtures: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = build_gate_context(tmp_path, fixtures, run_id="RUN-NM")
    out_dir = tmp_path / "out"
    out_file = out_dir / "nmap_RUN-NM.xml"

    def which(name: str) -> str | None:
        return "/bin/nmap" if name == "nmap" else None

    monkeypatch.setattr("src.runners.nmap_runner.shutil.which", which)

    def fake_run(cmd: list[str], **_kwargs):
        assert cmd[0] == "/bin/nmap"
        out_file.parent.mkdir(parents=True, exist_ok=True)
        out_file.write_text("<nmaprun/>", encoding="utf-8")
        return MagicMock(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("src.runners.nmap_runner.subprocess.run", fake_run)
    paths = NmapRunner(ctx).run(["192.168.56.10"], out_dir)
    assert paths == [out_file]


def test_nmap_timing_t5_reset_to_t3(
    tmp_path: Path, fixtures: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = build_gate_context(tmp_path, fixtures, run_id="RUN-NM")
    out_dir = tmp_path / "out"
    out_file = out_dir / "nmap_RUN-NM.xml"
    monkeypatch.setattr(
        "src.runners.nmap_runner.shutil.which", lambda name: "/bin/nmap" if name == "nmap" else None
    )
    captured: list[list[str]] = []

    def fake_run(cmd: list[str], **_kwargs):
        captured.append(cmd)
        out_file.parent.mkdir(parents=True, exist_ok=True)
        out_file.write_text("<nmaprun/>", encoding="utf-8")
        return MagicMock(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("src.runners.nmap_runner.subprocess.run", fake_run)
    NmapRunner(ctx, {"nmap": {"timing_template": "T5"}}).run(["192.168.56.10"], out_dir)
    # First subprocess call is get_version's --version; scan is second
    scan_cmd = captured[1] if len(captured) > 1 else captured[0]
    assert any(x == "-T3" or x.endswith("T3") for x in scan_cmd)


def test_nmap_exclusions_file(
    tmp_path: Path, fixtures: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = build_gate_context(tmp_path, fixtures, run_id="RUN-NM")
    out_dir = tmp_path / "out"
    out_file = out_dir / "nmap_RUN-NM.xml"
    monkeypatch.setattr(
        "src.runners.nmap_runner.shutil.which", lambda name: "/bin/nmap" if name == "nmap" else None
    )

    def fake_run(cmd: list[str], **_kwargs):
        out_file.parent.mkdir(parents=True, exist_ok=True)
        out_file.write_text("<nmaprun/>", encoding="utf-8")
        return MagicMock(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("src.runners.nmap_runner.subprocess.run", fake_run)
    monkeypatch.setattr(ctx.manifest, "all_exclusions", lambda: ["10.0.0.0/8"])
    NmapRunner(ctx).run(["192.168.56.10"], out_dir)
    exclude = out_dir / "nmap_exclude.txt"
    assert exclude.exists()
    assert "10.0.0.0/8" in exclude.read_text(encoding="utf-8")


def test_nmap_bad_return_code_raises(
    tmp_path: Path, fixtures: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = build_gate_context(tmp_path, fixtures)
    monkeypatch.setattr(
        "src.runners.nmap_runner.shutil.which", lambda name: "/bin/nmap" if name == "nmap" else None
    )
    monkeypatch.setattr(
        "src.runners.nmap_runner.subprocess.run",
        lambda *_a, **_k: MagicMock(returncode=2, stdout="", stderr="err"),
    )
    with pytest.raises(RunnerError, match="Nmap exited"):
        NmapRunner(ctx).run(["192.168.56.10"], tmp_path / "out")


def test_nmap_no_output_returns_empty(
    tmp_path: Path, fixtures: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = build_gate_context(tmp_path, fixtures)
    monkeypatch.setattr(
        "src.runners.nmap_runner.shutil.which", lambda name: "/bin/nmap" if name == "nmap" else None
    )
    monkeypatch.setattr(
        "src.runners.nmap_runner.subprocess.run",
        lambda *_a, **_k: MagicMock(returncode=0, stdout="", stderr=""),
    )
    paths = NmapRunner(ctx).run(["192.168.56.10"], tmp_path / "out")
    assert paths == []


def test_nmap_execute_docker_path(
    tmp_path: Path, fixtures: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = build_gate_context(tmp_path, fixtures, run_id="RUN-NM")
    out_dir = tmp_path / "out"
    out_file = out_dir / "nmap_RUN-NM.xml"

    def which(name: str) -> str | None:
        if name == "docker":
            return "/bin/docker"
        return None

    monkeypatch.setattr("src.runners.nmap_runner.shutil.which", which)

    def fake_run(cmd: list[str], **_kwargs):
        assert cmd[0] == "/bin/docker"
        assert NMAP_DOCKER_IMAGE in cmd
        out_file.parent.mkdir(parents=True, exist_ok=True)
        out_file.write_text("<nmaprun/>", encoding="utf-8")
        return MagicMock(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("src.runners.nmap_runner.subprocess.run", fake_run)
    paths = NmapRunner(ctx).run(["192.168.56.10"], out_dir)
    assert paths == [out_file]
