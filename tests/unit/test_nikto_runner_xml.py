"""Unit tests for src/runners/nikto_runner.py (XML output)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from src.orchestrator.exceptions import RunnerError
from src.runners.nikto_runner import NiktoRunner
from tests.unit.runner_test_context import build_gate_context


def _scan_calls(captured: list[list[str]]) -> list[list[str]]:
    """Return only subprocess calls that are real Nikto scans (contain -h)."""
    return [cmd for cmd in captured if "-h" in cmd]


def test_nikto_stub_without_binary(
    tmp_path: Path, fixtures: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = build_gate_context(tmp_path, fixtures)
    monkeypatch.setattr("src.runners.nikto_runner.shutil.which", lambda *_: None)

    r = NiktoRunner(ctx)
    paths = r.run(["http://192.168.56.10/"], tmp_path / "out")

    assert len(paths) == 1
    assert paths[0].suffix == ".xml"
    assert paths[0].name == "nikto_0.xml"


def test_nikto_skips_non_web_target(
    tmp_path: Path, fixtures: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When a target is not an HTTP/HTTPS URL, no scan subprocess must be launched."""
    ctx = build_gate_context(tmp_path, fixtures)
    monkeypatch.setattr("src.runners.nikto_runner.shutil.which", lambda *_: "/usr/bin/nikto")
    scan_cmds: list[list[str]] = []

    def fake_run(cmd: list[str], **_kw: object) -> MagicMock:
        if "-h" in cmd:
            scan_cmds.append(cmd)
        return MagicMock(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("src.runners.nikto_runner.subprocess.run", fake_run)

    paths = NiktoRunner(ctx).run(["192.168.56.10"], tmp_path / "out")

    assert len(paths) == 1
    assert scan_cmds == [], "Nikto scan must not be triggered for a non-web target"


def test_nikto_subprocess_uses_xml_format(
    tmp_path: Path, fixtures: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = build_gate_context(tmp_path, fixtures)
    monkeypatch.setattr("src.runners.nikto_runner.shutil.which", lambda *_: "/usr/bin/nikto")
    out_dir = tmp_path / "out"

    def fake_run(cmd: list[str], **_kw: object) -> MagicMock:
        out_xml = out_dir / "nikto_0.xml"
        out_xml.parent.mkdir(parents=True, exist_ok=True)
        out_xml.write_text(
            '<?xml version="1.0"?><niktoscan><niktoscan>'
            '<scandetails targetip="192.168.56.10" targetport="80"'
            ' targethostname="192.168.56.10"></scandetails>'
            "</niktoscan></niktoscan>",
            encoding="utf-8",
        )
        return MagicMock(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("src.runners.nikto_runner.subprocess.run", fake_run)

    paths = NiktoRunner(ctx).run(["http://192.168.56.10/"], out_dir)

    assert len(paths) == 1
    assert paths[0].suffix == ".xml"


def test_nikto_cmd_passes_format_xml(
    tmp_path: Path, fixtures: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The scan subprocess must receive -Format xml and write to an .xml path."""
    ctx = build_gate_context(tmp_path, fixtures)
    monkeypatch.setattr("src.runners.nikto_runner.shutil.which", lambda *_: "/usr/bin/nikto")
    captured: list[list[str]] = []

    def fake_run(cmd: list[str], **_kw: object) -> MagicMock:
        captured.append(cmd)
        out_xml = tmp_path / "out" / "nikto_0.xml"
        out_xml.parent.mkdir(parents=True, exist_ok=True)
        out_xml.write_text(
            "<niktoscan><niktoscan></niktoscan></niktoscan>",
            encoding="utf-8",
        )
        return MagicMock(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("src.runners.nikto_runner.subprocess.run", fake_run)

    NiktoRunner(ctx).run(["http://192.168.56.10/"], tmp_path / "out")

    scan_cmds = _scan_calls(captured)
    assert scan_cmds, "No scan command was captured"
    cmd = scan_cmds[0]

    assert "-Format" in cmd
    fmt_idx = cmd.index("-Format")
    assert cmd[fmt_idx + 1] == "xml"

    assert "-o" in cmd
    out_idx = cmd.index("-o")
    assert cmd[out_idx + 1].endswith(".xml")


def test_nikto_subprocess_failure_raises_when_no_real_output(
    tmp_path: Path, fixtures: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = build_gate_context(tmp_path, fixtures)
    monkeypatch.setattr("src.runners.nikto_runner.shutil.which", lambda *_: "/usr/bin/nikto")
    monkeypatch.setattr(
        "src.runners.nikto_runner.subprocess.run",
        lambda *_a, **_k: MagicMock(returncode=1, stdout="", stderr="fatal error"),
    )

    with pytest.raises(RunnerError, match="Nikto failed"):
        NiktoRunner(ctx).run(["http://192.168.56.10/"], tmp_path / "out")


def test_nikto_nonzero_exit_with_real_output_does_not_raise(
    tmp_path: Path, fixtures: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Nikto often exits 255 even on a successful scan; only raise when output is empty."""
    ctx = build_gate_context(tmp_path, fixtures)
    monkeypatch.setattr("src.runners.nikto_runner.shutil.which", lambda *_: "/usr/bin/nikto")
    out_dir = tmp_path / "out"

    def fake_run(cmd: list[str], **_kw: object) -> MagicMock:
        out_xml = out_dir / "nikto_0.xml"
        out_xml.parent.mkdir(parents=True, exist_ok=True)
        out_xml.write_text(
            '<?xml version="1.0"?><niktoscan><niktoscan>'
            '<scandetails targetip="10.0.0.1" targetport="80">'
            '<item id="1" osvdbid="0" method="GET">'
            "<description>Test finding</description>"
            "<uri>/</uri></item></scandetails>"
            "</niktoscan></niktoscan>",
            encoding="utf-8",
        )
        return MagicMock(returncode=255, stdout="", stderr="")

    monkeypatch.setattr("src.runners.nikto_runner.subprocess.run", fake_run)

    paths = NiktoRunner(ctx).run(["http://192.168.56.10/"], out_dir)

    assert len(paths) == 1


def test_nikto_stub_without_binary_writes_placeholder_xml(
    tmp_path: Path, fixtures: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = build_gate_context(tmp_path, fixtures)
    monkeypatch.setattr("src.runners.nikto_runner.shutil.which", lambda *_: None)

    paths = NiktoRunner(ctx).run(["http://192.168.56.10/"], tmp_path / "out")

    assert len(paths) == 1
    assert paths[0].suffix == ".xml"
    content = paths[0].read_text(encoding="utf-8")
    assert "<niktoscan" in content


def test_nikto_uses_configured_perl_script_path(
    tmp_path: Path, fixtures: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = build_gate_context(tmp_path, fixtures)
    out_dir = tmp_path / "out"
    captured: list[list[str]] = []

    def fake_exists(self: Path) -> bool:
        return str(self) == "/opt/nikto/program/nikto.pl"

    def fake_which(name: str) -> str | None:
        if name == "perl":
            return "/usr/bin/perl"
        if name == "nikto":
            return None
        return None

    def fake_run(cmd: list[str], **_kw: object) -> MagicMock:
        captured.append(cmd)
        out_xml = out_dir / "nikto_0.xml"
        out_xml.parent.mkdir(parents=True, exist_ok=True)
        out_xml.write_text(
            (
                '<?xml version="1.0" ?>\n'
                "<niktoscan>\n"
                "  <niktoscan>\n"
                "    <scandetails "
                'targetip="192.168.56.10" '
                'targethostname="192.168.56.10" '
                'targetport="80" '
                'targetbanner="" '
                'starttime="2026-04-21 09:30:00" '
                'sitename="http://192.168.56.10/" '
                'siteip="http://192.168.56.10:80/" '
                'hostheader="192.168.56.10" '
                'errors="0" '
                'checks="0">\n'
                "    </scandetails>\n"
                "  </niktoscan>\n"
                "</niktoscan>\n"
            ),
            encoding="utf-8",
        )
        return MagicMock(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("src.runners.nikto_runner.Path.exists", fake_exists)
    monkeypatch.setattr("src.runners.nikto_runner.shutil.which", fake_which)
    monkeypatch.setattr("src.runners.nikto_runner.subprocess.run", fake_run)

    runner = NiktoRunner(
        ctx,
        config={
            "nikto": {
                "executable": "/opt/nikto/program/nikto.pl",
                "interpreter": "perl",
            }
        },
    )
    paths = runner.run(["http://192.168.56.10/"], out_dir)

    assert len(paths) == 1
    scan_cmds = _scan_calls(captured)
    assert scan_cmds, "No scan command was captured"
    cmd = scan_cmds[0]
    assert cmd[0] == "/usr/bin/perl"
    assert cmd[1] == "/opt/nikto/program/nikto.pl"


def test_nikto_missing_configured_executable_falls_back_to_stub(
    tmp_path: Path, fixtures: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = build_gate_context(tmp_path, fixtures)

    monkeypatch.setattr("src.runners.nikto_runner.Path.exists", lambda _self: False)
    monkeypatch.setattr("src.runners.nikto_runner.shutil.which", lambda *_: None)

    runner = NiktoRunner(
        ctx,
        config={"nikto": {"executable": "/does/not/exist/nikto.pl"}},
    )
    paths = runner.run(["http://192.168.56.10/"], tmp_path / "out")

    assert len(paths) == 1
    assert paths[0].name == "nikto_0.xml"
    assert "<niktoscan" in paths[0].read_text(encoding="utf-8")
