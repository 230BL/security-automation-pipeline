"""Greenbone/OpenVAS runner backed by GMP via gvm-cli.

Behavior:
- No stubs.
- If Greenbone runtime requirements are missing, fail honestly.
- If Greenbone is configured, create a target and task through GMP, start the
  task, wait for completion, download the report, and convert it to the
  OpenVAS-style CSV shape already consumed by the pipeline.
- A real scan with zero findings still produces a valid header-only CSV.
"""

from __future__ import annotations

import csv
import logging
import os
import shutil
import subprocess
import time
import xml.etree.ElementTree as ElementTree
from pathlib import Path
from typing import Any

from defusedxml.ElementTree import fromstring as safe_fromstring

from src.orchestrator.exceptions import RunnerExecutionError
from src.runners.base import BaseRunner

LOG = logging.getLogger(__name__)

DEFAULT_SCAN_CONFIG = "Full and fast"
DEFAULT_PORT_LIST = "All IANA assigned TCP"
DEFAULT_SCANNER = "OpenVAS Default"

DONE_STATUSES = {"Done"}
FAILED_STATUSES = {
    "Delete Requested",
    "Internal Error",
    "Interrupted",
    "Stop Requested",
    "Stopped",
}


class GreenboneRunner(BaseRunner):
    """Run authenticated vulnerability scans through Greenbone GMP."""

    tool_name = "greenbone"

    def __init__(
        self,
        context: Any,
        config: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(context, config)
        self.tool_config: dict[str, Any] = self.config.get("greenbone", {})

    def _allow_stub(self) -> bool:
        return False

    def _runtime_settings(self) -> dict[str, str | None]:
        connection = (
            str(
                self.tool_config.get("connection", "socket")
                or os.getenv("GREENBONE_CONNECTION")
                or "socket"
            )
            .strip()
            .lower()
        )

        socket_path_raw = self.tool_config.get("socket_path") or os.getenv("GREENBONE_SOCKET_PATH")
        host_raw = self.tool_config.get("host") or os.getenv("GREENBONE_HOST")
        port_raw = self.tool_config.get("port") or os.getenv("GREENBONE_PORT")
        username_raw = self.tool_config.get("gmp_username") or os.getenv("GREENBONE_GMP_USERNAME")
        password_raw = self.tool_config.get("gmp_password") or os.getenv("GREENBONE_GMP_PASSWORD")

        socket_path = (
            str(socket_path_raw).strip()
            if socket_path_raw is not None and str(socket_path_raw).strip()
            else None
        )
        host = (
            str(host_raw).strip() if host_raw is not None and str(host_raw).strip() else "localhost"
        )
        port = str(port_raw).strip() if port_raw is not None and str(port_raw).strip() else "9390"
        username = (
            str(username_raw).strip()
            if username_raw is not None and str(username_raw).strip()
            else None
        )
        password = (
            str(password_raw).strip()
            if password_raw is not None and str(password_raw).strip()
            else None
        )

        ssh_username_raw = self.tool_config.get("ssh_username") or os.getenv(
            "GREENBONE_SSH_USERNAME"
        )
        ssh_password_raw = self.tool_config.get("ssh_password") or os.getenv(
            "GREENBONE_SSH_PASSWORD"
        )

        ssh_username = (
            str(ssh_username_raw).strip()
            if ssh_username_raw is not None and str(ssh_username_raw).strip()
            else None
        )
        ssh_password = (
            str(ssh_password_raw).strip()
            if ssh_password_raw is not None and str(ssh_password_raw).strip()
            else None
        )

        return {
            "gvm_cli": shutil.which("gvm-cli"),
            "connection": connection,
            "socket_path": socket_path,
            "host": host,
            "port": port,
            "username": username,
            "password": password,
            "ssh_username": ssh_username,
            "ssh_password": ssh_password,
        }

    def _runtime_issues(self) -> list[str]:
        settings = self._runtime_settings()
        issues: list[str] = []

        if settings["gvm_cli"] is None:
            issues.append("gvm-cli is not installed")

        if settings["username"] is None:
            issues.append(
                "missing Greenbone GMP username (greenbone.gmp_username or GREENBONE_GMP_USERNAME)"
            )

        if settings["password"] is None:
            issues.append(
                "missing Greenbone GMP password (greenbone.gmp_password or GREENBONE_GMP_PASSWORD)"
            )

        connection = settings["connection"]

        if connection == "socket":
            socket_path = settings["socket_path"]
            if socket_path is None:
                issues.append(
                    "missing Greenbone socket path (greenbone.socket_path or GREENBONE_SOCKET_PATH)"
                )
            elif not Path(socket_path).exists():
                issues.append(f"Greenbone socket does not exist: {socket_path}")
        elif connection in {"ssh", "tls"}:
            if not settings["host"]:
                issues.append(f"missing Greenbone host for {connection} connection")
            if not settings["port"]:
                issues.append(f"missing Greenbone port for {connection} connection")
        else:
            issues.append(f"unsupported Greenbone connection type: {connection}")

        return issues

    def health_check(self) -> bool:
        return not self._runtime_issues()

    def get_version(self) -> str:
        exe = self._runtime_settings()["gvm_cli"]

        if exe is None:
            return "missing:gvm-cli"

        try:
            result = subprocess.run(
                [exe, "--version"],
                capture_output=True,
                text=True,
                shell=False,
                timeout=10,
                check=False,
            )
        except Exception:
            return "gvm-cli"

        output = (result.stdout or result.stderr).strip()
        return output.splitlines()[0] if output else "gvm-cli"

    def _base_command(self) -> list[str]:
        settings = self._runtime_settings()
        exe = settings["gvm_cli"]
        connection = settings["connection"]
        username = settings["username"]
        password = settings["password"]

        if exe is None:
            raise RunnerExecutionError(
                "gvm-cli is not installed",
                context={"tool": self.tool_name},
            )

        if username is None:
            raise RunnerExecutionError(
                "Missing Greenbone GMP username",
                context={
                    "tool": self.tool_name,
                    "expected": ("greenbone.gmp_username or GREENBONE_GMP_USERNAME"),
                },
            )

        if password is None:
            raise RunnerExecutionError(
                "Missing Greenbone GMP password",
                context={
                    "tool": self.tool_name,
                    "expected": ("greenbone.gmp_password or GREENBONE_GMP_PASSWORD"),
                },
            )

        timeout = str(int(self.tool_config.get("network_timeout", 40)))

        cmd = [
            exe,
            "--timeout",
            timeout,
            "--gmp-username",
            username,
            "--gmp-password",
            password,
        ]

        if connection == "socket":
            socket_path = settings["socket_path"]
            if socket_path is None:
                raise RunnerExecutionError(
                    "Missing Greenbone socket path",
                    context={
                        "tool": self.tool_name,
                        "expected": ("greenbone.socket_path or GREENBONE_SOCKET_PATH"),
                    },
                )
            cmd += ["socket", "--socketpath", socket_path]
            return cmd

        if connection == "ssh":
            host = settings["host"] or "localhost"
            port = settings["port"] or "9390"
            cmd += ["ssh", "--hostname", host, "--port", port, "-A"]

            ssh_username = settings["ssh_username"]
            ssh_password = settings["ssh_password"]

            if ssh_username:
                cmd += ["--ssh-username", ssh_username]
            if ssh_password:
                cmd += ["--ssh-password", ssh_password]

            return cmd

        if connection == "tls":
            host = settings["host"] or "localhost"
            port = settings["port"] or "9390"
            cmd += ["tls", "--hostname", host, "--port", port]
            return cmd

        raise RunnerExecutionError(
            f"Unsupported Greenbone connection type: {connection}",
            context={
                "tool": self.tool_name,
                "connection": connection,
            },
        )

    def _run_xml(
        self,
        xml_payload: str,
        timeout: int | None = None,
    ) -> ElementTree.Element:
        cmd = [*self._base_command(), "--xml", xml_payload]
        LOG.info("Running Greenbone GMP command: %s", " ".join(cmd[:-1]))

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            shell=False,
            timeout=timeout or int(self.tool_config.get("network_timeout", 40)),
            check=False,
        )

        raw = (result.stdout or "").strip()
        if result.returncode != 0:
            raise RunnerExecutionError(
                f"gvm-cli failed (rc={result.returncode})",
                context={
                    "tool": self.tool_name,
                    "stderr": (result.stderr or "")[:500],
                    "stdout": raw[:500],
                },
            )

        if not raw:
            raise RunnerExecutionError(
                "gvm-cli returned empty output",
                context={"tool": self.tool_name},
            )

        try:
            root = safe_fromstring(raw)
        except Exception as exc:
            raise RunnerExecutionError(
                f"Unable to parse gvm-cli XML response: {exc}",
                context={"tool": self.tool_name, "response": raw[:500]},
            ) from exc

        status = (root.get("status") or "").strip()
        if status and not status.startswith("2"):
            raise RunnerExecutionError(
                f"Greenbone API error {status}: {root.get('status_text', '').strip()}",
                context={"tool": self.tool_name, "response": raw[:500]},
            )

        return root

    def _resource_names(self, resource_type: str) -> dict[str, str]:
        root = self._run_xml(f'<get_resource_names type="{resource_type}" filter="rows=-1"/>')
        resources: dict[str, str] = {}

        for item in root.findall(".//resource"):
            resource_id = (item.get("id") or "").strip()
            name = (item.findtext("name") or "").strip()
            if resource_id and name:
                resources[name] = resource_id

        return resources

    def _wait_until_initialized(self) -> tuple[str, str, str]:
        scan_config_name = str(self.tool_config.get("scan_config_name", DEFAULT_SCAN_CONFIG))
        port_list_name = str(self.tool_config.get("port_list_name", DEFAULT_PORT_LIST))
        scanner_name = str(self.tool_config.get("scanner_name", DEFAULT_SCANNER))
        poll_interval = int(self.tool_config.get("poll_interval_seconds", 15))
        deadline = time.monotonic() + int(self.tool_config.get("init_timeout", 1800))

        while True:
            configs = self._resource_names("config")
            port_lists = self._resource_names("port_list")
            scanners = self._resource_names("scanner")

            config_id = configs.get(scan_config_name)
            port_list_id = port_lists.get(port_list_name)
            scanner_id = scanners.get(scanner_name)

            if config_id and port_list_id and scanner_id:
                return config_id, port_list_id, scanner_id

            if time.monotonic() >= deadline:
                raise RunnerExecutionError(
                    "Greenbone is not initialized yet",
                    context={
                        "tool": self.tool_name,
                        "needed_scan_config": scan_config_name,
                        "needed_port_list": port_list_name,
                        "needed_scanner": scanner_name,
                        "found_scan_configs": sorted(configs.keys())[:10],
                        "found_port_lists": sorted(port_lists.keys())[:10],
                        "found_scanners": sorted(scanners.keys())[:10],
                    },
                )

            LOG.info(
                "Waiting for Greenbone feed/init. Need config=%s port_list=%s scanner=%s",
                scan_config_name,
                port_list_name,
                scanner_name,
            )
            time.sleep(poll_interval)

    def _build_target_xml(
        self,
        *,
        name: str,
        targets: list[str],
        port_list_id: str,
    ) -> str:
        target = ElementTree.Element("create_target")
        ElementTree.SubElement(target, "name").text = name
        ElementTree.SubElement(target, "hosts").text = ",".join(targets)
        ElementTree.SubElement(target, "port_list", {"id": port_list_id})

        ssh_credential_id = self.tool_config.get("ssh_credential_id") or os.getenv(
            "GREENBONE_SSH_CREDENTIAL_ID"
        )
        if ssh_credential_id:
            ssh_port = str(
                self.tool_config.get("ssh_port") or os.getenv("GREENBONE_SSH_PORT") or "22"
            )
            ssh_credential = ElementTree.SubElement(
                target,
                "ssh_credential",
                {"id": str(ssh_credential_id)},
            )
            ElementTree.SubElement(ssh_credential, "port").text = ssh_port

        ssh_lsc_credential_id = self.tool_config.get("ssh_lsc_credential_id") or os.getenv(
            "GREENBONE_SSH_LSC_CREDENTIAL_ID"
        )
        if ssh_lsc_credential_id:
            ssh_lsc_port = str(
                self.tool_config.get("ssh_lsc_port") or os.getenv("GREENBONE_SSH_LSC_PORT") or "22"
            )
            ssh_lsc = ElementTree.SubElement(
                target,
                "ssh_lsc_credential",
                {"id": str(ssh_lsc_credential_id)},
            )
            ElementTree.SubElement(ssh_lsc, "port").text = ssh_lsc_port

        ssh_elevate_credential_id = self.tool_config.get("ssh_elevate_credential_id") or os.getenv(
            "GREENBONE_SSH_ELEVATE_CREDENTIAL_ID"
        )
        if ssh_elevate_credential_id:
            ElementTree.SubElement(
                target,
                "ssh_elevate_credential",
                {"id": str(ssh_elevate_credential_id)},
            )

        return ElementTree.tostring(target, encoding="unicode")

    def _build_task_xml(
        self,
        *,
        name: str,
        target_id: str,
        config_id: str,
        scanner_id: str,
    ) -> str:
        task = ElementTree.Element("create_task")
        ElementTree.SubElement(task, "name").text = name
        ElementTree.SubElement(task, "config", {"id": config_id})
        ElementTree.SubElement(task, "target", {"id": target_id})
        ElementTree.SubElement(task, "scanner", {"id": scanner_id})

        preferences = ElementTree.SubElement(task, "preferences")

        pref_checks = ElementTree.SubElement(preferences, "preference")
        ElementTree.SubElement(pref_checks, "scanner_name").text = "max_checks"
        ElementTree.SubElement(pref_checks, "value").text = str(
            int(self.tool_config.get("max_concurrent_nvts", 4))
        )

        pref_hosts = ElementTree.SubElement(preferences, "preference")
        ElementTree.SubElement(pref_hosts, "scanner_name").text = "max_hosts"
        ElementTree.SubElement(pref_hosts, "value").text = str(
            int(self.tool_config.get("max_concurrent_hosts", 5))
        )

        return ElementTree.tostring(task, encoding="unicode")

    def _wait_for_task_completion(self, task_id: str) -> None:
        deadline = time.monotonic() + int(self.tool_config.get("global_timeout", 14400))
        poll_interval = int(self.tool_config.get("poll_interval_seconds", 15))

        while True:
            root = self._run_xml(f'<get_tasks task_id="{task_id}" details="1"/>')
            status = (root.findtext(".//task/status") or "").strip()
            progress = (root.findtext(".//task/progress") or "").strip()

            LOG.info(
                "Greenbone task %s status=%s progress=%s",
                task_id,
                status,
                progress or "n/a",
            )

            if status in DONE_STATUSES:
                return

            if status in FAILED_STATUSES:
                raise RunnerExecutionError(
                    f"Greenbone task failed with status: {status}",
                    context={
                        "tool": self.tool_name,
                        "task_id": task_id,
                        "progress": progress,
                    },
                )

            if time.monotonic() >= deadline:
                raise RunnerExecutionError(
                    f"Greenbone task did not finish before timeout. Last status: {status}",
                    context={
                        "tool": self.tool_name,
                        "task_id": task_id,
                        "progress": progress,
                    },
                )

            time.sleep(poll_interval)

    def _report_id_from_start_response(
        self,
        root: ElementTree.Element,
    ) -> str:
        return ((root.findtext("report_id") or "") or (root.findtext(".//report_id") or "")).strip()

    def _report_id_for_task(self, task_id: str) -> str:
        root = self._run_xml(f'<get_tasks task_id="{task_id}" details="1"/>')
        report_node = root.find(".//task/last_report/report")
        if report_node is None:
            return ""
        return (report_node.get("id") or "").strip()

    def _write_csv_from_report(
        self,
        report_root: ElementTree.Element,
        out: Path,
    ) -> None:
        inner_report = report_root.find("./report/report")
        if inner_report is None:
            raise RunnerExecutionError(
                "Greenbone report XML did not contain nested report data",
                context={"tool": self.tool_name},
            )

        with out.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow(
                [
                    "IP",
                    "Hostname",
                    "Port",
                    "NVT Name",
                    "CVSS",
                    "Severity",
                    "Summary",
                    "Solution",
                    "CVEs",
                    "NVT OID",
                    "Specific Result",
                ]
            )

            for result in inner_report.findall("./results/result"):
                host = (result.findtext("host") or "").strip()
                port = (result.findtext("port") or "").strip()
                nvt = result.find("nvt")
                if nvt is None:
                    continue

                nvt_name = (
                    result.findtext("name") or nvt.findtext("name") or "Unknown vulnerability"
                ).strip()
                cvss = (nvt.findtext("cvss_base") or "0").strip()
                severity = (result.findtext("threat") or "Info").strip()
                description = (result.findtext("description") or "").strip()
                solution = (nvt.findtext("solution") or "").strip()
                oid = (nvt.get("oid") or "").strip()
                cves = ",".join(
                    sorted(
                        {
                            (ref.get("id") or "").strip()
                            for ref in nvt.findall("./refs/ref")
                            if (ref.get("type") or "").strip().lower() == "cve"
                            and (ref.get("id") or "").strip()
                        }
                    )
                )

                writer.writerow(
                    [
                        host,
                        "",
                        port,
                        nvt_name,
                        cvss,
                        severity,
                        description,
                        solution,
                        cves,
                        oid,
                        description,
                    ]
                )

    def execute(self, targets: list[str], output_dir: Path) -> list[Path]:
        output_dir.mkdir(parents=True, exist_ok=True)

        issues = self._runtime_issues()
        if issues:
            raise RunnerExecutionError(
                f"Greenbone is not configured correctly: {'; '.join(issues)}",
                context={"tool": self.tool_name},
            )

        run_id = self.context.run_metadata.run_id
        csv_out = output_dir / f"openvas_{run_id}.csv"
        xml_out = output_dir / f"openvas_{run_id}.xml"

        config_id, port_list_id, scanner_id = self._wait_until_initialized()

        target_name = f"pipeline-target-{run_id}"
        task_name = f"pipeline-task-{run_id}"

        target_root = self._run_xml(
            self._build_target_xml(
                name=target_name,
                targets=targets,
                port_list_id=port_list_id,
            )
        )
        target_id = (target_root.get("id") or "").strip()
        if not target_id:
            raise RunnerExecutionError(
                "Greenbone did not return a target id",
                context={"tool": self.tool_name},
            )

        task_root = self._run_xml(
            self._build_task_xml(
                name=task_name,
                target_id=target_id,
                config_id=config_id,
                scanner_id=scanner_id,
            )
        )
        task_id = (task_root.get("id") or "").strip()
        if not task_id:
            raise RunnerExecutionError(
                "Greenbone did not return a task id",
                context={"tool": self.tool_name},
            )

        start_root = self._run_xml(f'<start_task task_id="{task_id}"/>')
        report_id = self._report_id_from_start_response(start_root)

        self._wait_for_task_completion(task_id)

        if not report_id:
            report_id = self._report_id_for_task(task_id)

        if not report_id:
            raise RunnerExecutionError(
                "Greenbone did not return a report id for the completed task",
                context={"tool": self.tool_name, "task_id": task_id},
            )

        report_root = self._run_xml(
            f'<get_reports report_id="{report_id}" ignore_pagination="1"/>',
            timeout=int(self.tool_config.get("report_download_timeout", 300)),
        )

        xml_out.write_text(
            ElementTree.tostring(report_root, encoding="unicode"),
            encoding="utf-8",
        )
        self._write_csv_from_report(report_root, csv_out)

        LOG.info("Greenbone runner produced %s", csv_out)
        return [csv_out]
