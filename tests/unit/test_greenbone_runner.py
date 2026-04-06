"""Unit tests for src/runners/greenbone_runner.py."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest
from defusedxml.ElementTree import fromstring as safe_fromstring

from src.orchestrator.exceptions import RunnerHealthError
from src.runners.greenbone_runner import GreenboneRunner
from tests.unit.runner_test_context import build_gate_context


def _clear_greenbone_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "GREENBONE_CONNECTION",
        "GREENBONE_SOCKET_PATH",
        "GREENBONE_HOST",
        "GREENBONE_PORT",
        "GREENBONE_GMP_USERNAME",
        "GREENBONE_GMP_PASSWORD",
        "GREENBONE_SSH_USERNAME",
        "GREENBONE_SSH_PASSWORD",
        "GREENBONE_SSH_CREDENTIAL_ID",
        "GREENBONE_SSH_PORT",
        "GREENBONE_SSH_LSC_CREDENTIAL_ID",
        "GREENBONE_SSH_LSC_PORT",
        "GREENBONE_SSH_ELEVATE_CREDENTIAL_ID",
    ):
        monkeypatch.delenv(name, raising=False)


def test_greenbone_run_fails_when_runtime_not_ready(
    tmp_path: Path,
    fixtures: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_greenbone_env(monkeypatch)
    monkeypatch.setattr("src.runners.greenbone_runner.shutil.which", lambda *_: None)

    ctx = build_gate_context(tmp_path, fixtures, run_id="RUN-GB")
    runner = GreenboneRunner(ctx, {"greenbone": {"max_concurrent_hosts": 2}})
    out = tmp_path / "out"

    with pytest.raises(RunnerHealthError, match="greenbone health check failed"):
        runner.run(["10.0.0.1", "10.0.0.2", "10.0.0.3"], out)


def test_greenbone_get_version_missing_exe(
    tmp_path: Path,
    fixtures: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_greenbone_env(monkeypatch)

    ctx = build_gate_context(tmp_path, fixtures)
    runner = GreenboneRunner(ctx)

    monkeypatch.setattr("src.runners.greenbone_runner.shutil.which", lambda *_: None)

    assert runner.get_version() == "missing:gvm-cli"


def test_greenbone_get_version_from_exe(
    tmp_path: Path,
    fixtures: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_greenbone_env(monkeypatch)

    ctx = build_gate_context(tmp_path, fixtures)
    runner = GreenboneRunner(ctx)

    monkeypatch.setattr(
        "src.runners.greenbone_runner.shutil.which",
        lambda name: "/bin/gvm-cli" if name == "gvm-cli" else None,
    )
    mock_run = MagicMock(return_value=MagicMock(stdout="1.0\n", stderr="", returncode=0))
    monkeypatch.setattr("src.runners.greenbone_runner.subprocess.run", mock_run)

    assert runner.get_version() == "1.0"


def test_greenbone_write_csv_from_empty_report(
    tmp_path: Path,
    fixtures: Path,
) -> None:
    ctx = build_gate_context(tmp_path, fixtures, run_id="RUN-GB")
    runner = GreenboneRunner(ctx)
    out = tmp_path / "openvas_RUN-GB.csv"

    report_root = safe_fromstring(
        """
        <get_reports_response status="200" status_text="OK">
          <report id="outer">
            <report id="inner">
              <results />
            </report>
          </report>
        </get_reports_response>
        """
    )

    runner._write_csv_from_report(report_root, out)

    text = out.read_text(encoding="utf-8")
    assert text == (
        "IP,Hostname,Port,NVT Name,CVSS,Severity,Summary,Solution,CVEs,NVT OID,Specific Result\n"
    )


def test_greenbone_report_id_from_start_response_direct(
    tmp_path: Path,
    fixtures: Path,
) -> None:
    ctx = build_gate_context(tmp_path, fixtures)
    runner = GreenboneRunner(ctx)

    root = safe_fromstring(
        """
        <start_task_response status="202" status_text="OK">
          <report_id>report-123</report_id>
        </start_task_response>
        """
    )

    assert runner._report_id_from_start_response(root) == "report-123"


def test_greenbone_report_id_for_task_reads_last_report_id(
    tmp_path: Path,
    fixtures: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctx = build_gate_context(tmp_path, fixtures)
    runner = GreenboneRunner(ctx)

    root = safe_fromstring(
        """
        <get_tasks_response status="200" status_text="OK">
          <task id="task-1">
            <last_report>
              <report id="report-456" />
            </last_report>
          </task>
        </get_tasks_response>
        """
    )

    monkeypatch.setattr(runner, "_run_xml", lambda *_args, **_kwargs: root)

    assert runner._report_id_for_task("task-1") == "report-456"


def test_greenbone_write_csv_from_report_with_result(
    tmp_path: Path,
    fixtures: Path,
) -> None:
    ctx = build_gate_context(tmp_path, fixtures, run_id="RUN-GB")
    runner = GreenboneRunner(ctx)
    out = tmp_path / "openvas_RUN-GB.csv"

    report_root = safe_fromstring(
        """
        <get_reports_response status="200" status_text="OK">
          <report id="outer">
            <report id="inner">
              <results>
                <result>
                  <host>10.0.0.5</host>
                  <port>80/tcp</port>
                  <threat>High</threat>
                  <description>Detected issue details</description>
                  <nvt oid="1.3.6.1.4.1.test">
                    <name>Sample NVT</name>
                    <cvss_base>7.5</cvss_base>
                    <solution>Apply patch</solution>
                    <refs>
                      <ref type="cve" id="CVE-2026-0001" />
                      <ref type="cve" id="CVE-2026-0002" />
                      <ref type="url" id="https://example.test/advisory" />
                    </refs>
                  </nvt>
                </result>
              </results>
            </report>
          </report>
        </get_reports_response>
        """
    )

    runner._write_csv_from_report(report_root, out)

    lines = out.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2

    header = lines[0]
    row = lines[1]

    assert header == (
        "IP,Hostname,Port,NVT Name,CVSS,Severity,Summary,Solution,CVEs,NVT OID,Specific Result"
    )
    assert "10.0.0.5" in row
    assert "80/tcp" in row
    assert "Sample NVT" in row
    assert "7.5" in row
    assert "High" in row
    assert "Apply patch" in row
    assert "CVE-2026-0001,CVE-2026-0002" in row
    assert "1.3.6.1.4.1.test" in row
    assert "Detected issue details" in row
