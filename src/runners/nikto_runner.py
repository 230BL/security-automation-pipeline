"""Nikto runner for web server misconfiguration checks.

Output format: XML (``-Format xml``).

Rationale:
- Nikto's JSON report plugin is broken in current portable builds.
- The XML reporter works correctly.
- Some Nikto installs may write banner/debug text before or after the XML
  document. This runner sanitizes and validates the XML before returning
  artifacts to the parser.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from defusedxml.ElementTree import ParseError, parse

from src.orchestrator.exceptions import RunnerExecutionError
from src.runners.base import BaseRunner

LOG = logging.getLogger(__name__)

_EMPTY_XML = """<?xml version="1.0" ?>
<niktoscan>
  <niktoscan>
  </niktoscan>
</niktoscan>
"""

_XML_DECL_RE = re.compile(r"<\?xml\b")
_SINGULAR_ROOT_RE = re.compile(r"<niktoscan\b")
_PLURAL_ROOT_RE = re.compile(r"<niktoscans\b")


def _looks_like_web_target(target: str) -> bool:
    value = str(target).strip().lower()
    return value.startswith("http://") or value.startswith("https://")


def _sanitize_nikto_xml(raw_text: str) -> str:
    """Extract the first complete Nikto XML document from raw output.

    Supports both observed outer roots:
    - <niktoscan> ... </niktoscan>
    - <niktoscans> ... </niktoscans>
    """
    text = (raw_text or "").replace("\r\n", "\n").strip()
    if not text:
        return ""

    xml_match = _XML_DECL_RE.search(text)
    singular_match = _SINGULAR_ROOT_RE.search(text)
    plural_match = _PLURAL_ROOT_RE.search(text)

    start_candidates = [
        match.start() for match in (xml_match, singular_match, plural_match) if match is not None
    ]
    if not start_candidates:
        return ""

    text = text[min(start_candidates) :]

    singular_match = _SINGULAR_ROOT_RE.search(text)
    plural_match = _PLURAL_ROOT_RE.search(text)

    singular_index = singular_match.start() if singular_match else -1
    plural_index = plural_match.start() if plural_match else -1

    if plural_index != -1 and (singular_index == -1 or plural_index < singular_index):
        closing_tag = "</niktoscans>"
    else:
        closing_tag = "</niktoscan>"

    close_index = text.rfind(closing_tag)
    if close_index == -1:
        return text.strip() + "\n"

    text = text[: close_index + len(closing_tag)]
    return text.strip() + "\n"


class NiktoRunner(BaseRunner):
    """Run Nikto and store XML artifacts compatible with ``parse_nikto_xml``."""

    tool_name = "nikto"

    def __init__(
        self,
        context: Any,
        config: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(context, config)

        cfg = self.config or {}
        nikto_section = cfg.get("nikto")
        if isinstance(nikto_section, dict):
            self.tool_config: dict[str, Any] = nikto_section
        else:
            self.tool_config = cfg

    def health_check(self) -> bool:
        return self._resolve_nikto_command(strict=False) is not None

    def _resolve_nikto_command(self, strict: bool = False) -> list[str] | None:
        configured_value = self.tool_config.get("executable") or self.tool_config.get("path") or ""
        configured = str(configured_value).strip()

        resolved_executable: str | None = None
        source = "PATH"

        if configured:
            expanded = os.path.expanduser(configured)
            source = configured

            if os.path.sep in expanded or expanded.startswith("."):
                if Path(expanded).exists():
                    resolved_executable = str(Path(expanded))
            else:
                resolved_executable = shutil.which(expanded)

            if not resolved_executable:
                message = f"Nikto executable not found: {configured}"
                if strict:
                    raise RunnerExecutionError(
                        message,
                        context={"configured_executable": configured},
                    )
                LOG.warning(message)
                return None
        else:
            resolved_executable = shutil.which("nikto")

        if not resolved_executable:
            if strict:
                raise RunnerExecutionError("Nikto executable not found")
            return None

        if resolved_executable.lower().endswith(".pl"):
            interpreter_name = str(self.tool_config.get("interpreter") or "perl").strip()
            perl = shutil.which(interpreter_name)
            if not perl:
                message = (
                    f"Perl interpreter '{interpreter_name}' not found for "
                    f"Nikto script: {resolved_executable}"
                )
                if strict:
                    raise RunnerExecutionError(
                        message,
                        context={
                            "configured_executable": configured or resolved_executable,
                            "resolved_executable": resolved_executable,
                            "interpreter": interpreter_name,
                        },
                    )
                LOG.warning(message)
                return None
            LOG.info(
                "Resolved Nikto command from %s: %s %s",
                source,
                perl,
                resolved_executable,
            )
            return [perl, resolved_executable]

        LOG.info("Resolved Nikto executable from %s: %s", source, resolved_executable)
        return [resolved_executable]

    def get_version(self) -> str:
        cmd = self._resolve_nikto_command(strict=False)
        if not cmd:
            return "stub"

        try:
            result = subprocess.run(
                [*cmd, "-Version"],
                capture_output=True,
                text=True,
                shell=False,
                timeout=15,
                check=False,
            )
            output = (result.stdout or result.stderr or "").strip()
            if output:
                return output.splitlines()[0]
        except Exception:
            return "nikto"

        return "nikto"

    def execute(self, targets: list[str], output_dir: Path) -> list[Path]:
        artifacts: list[Path] = []
        timeout = int(self.tool_config.get("global_timeout", 3600))
        per_host = int(self.tool_config.get("timeout_per_host", 300))
        nikto_cmd = self._resolve_nikto_command(strict=True)

        if nikto_cmd is None:
            raise RunnerExecutionError("Nikto executable could not be resolved")

        output_dir.mkdir(parents=True, exist_ok=True)

        for idx, target in enumerate(targets):
            out = output_dir / f"nikto_{idx}.xml"
            stdout_log = output_dir / f"nikto_{idx}.stdout.log"
            stderr_log = output_dir / f"nikto_{idx}.stderr.log"

            if out.exists():
                out.unlink()

            if not _looks_like_web_target(target):
                LOG.warning(
                    "Nikto skipping non-web target '%s' (needs http:// or https://)",
                    target,
                )
                out.write_text(_EMPTY_XML, encoding="utf-8")
                artifacts.append(out)
                continue

            cmd_args = [
                *nikto_cmd,
                "-h",
                target,
                "-Format",
                "xml",
                "-o",
                str(out),
                "-maxtime",
                f"{per_host}s",
                "-nointeractive",
            ]
            LOG.info("Running: %s", " ".join(cmd_args)[:500])

            result = subprocess.run(
                cmd_args,
                capture_output=True,
                text=True,
                shell=False,
                timeout=timeout,
                check=False,
            )

            stdout_text = result.stdout or ""
            stderr_text = result.stderr or ""

            stdout_log.write_text(stdout_text, encoding="utf-8")
            stderr_log.write_text(stderr_text, encoding="utf-8")

            out_content = out.read_text(encoding="utf-8") if out.exists() else ""
            sanitized_xml = _sanitize_nikto_xml(out_content)

            if sanitized_xml and sanitized_xml != out_content:
                LOG.warning(
                    "Nikto output for %s contained non-XML text; sanitized artifact",
                    target,
                )
                out.write_text(sanitized_xml, encoding="utf-8")
                out_content = sanitized_xml

            produced_real_output = out_content.strip() not in {"", _EMPTY_XML.strip()}

            if result.returncode != 0 and not produced_real_output:
                raise RunnerExecutionError(
                    f"Nikto failed (rc={result.returncode}): "
                    f"{stderr_text.strip()[:200] or stdout_text.strip()[:200]}",
                    context={
                        "target": target,
                        "artifact": str(out),
                        "stdout_log": str(stdout_log),
                        "stderr_log": str(stderr_log),
                        "stdout": stdout_text[:1000],
                        "stderr": stderr_text[:1000],
                    },
                )

            if not produced_real_output:
                LOG.warning(
                    "Nikto completed for %s without XML output; keeping empty artifact",
                    target,
                )
                out.write_text(_EMPTY_XML, encoding="utf-8")
                artifacts.append(out)
                continue

            try:
                parse(out)
            except ParseError as exc:
                raise RunnerExecutionError(
                    f"Nikto produced malformed XML for {target}: {exc}",
                    context={
                        "target": target,
                        "artifact": str(out),
                        "stdout_log": str(stdout_log),
                        "stderr_log": str(stderr_log),
                        "stdout": stdout_text[:1000],
                        "stderr": stderr_text[:1000],
                        "artifact_preview": out.read_text(encoding="utf-8")[:1500],
                    },
                ) from exc

            artifacts.append(out)

        return artifacts
