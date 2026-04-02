"""Wazuh runner (data retrieval only).

This runner **does not** deploy agents. It retrieves JSON exports either:
- from a local evidence drop directory (Phase 1), or
- from the Wazuh API (Phase 2+), if configured.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

import requests

from src.orchestrator.exceptions import RunnerExecutionError
from src.runners.base import BaseRunner
from src.utils.redaction import redact_dict

LOG = logging.getLogger(__name__)


class WazuhRunner(BaseRunner):
    tool_name = "wazuh"

    def __init__(self, context: Any, config: dict[str, Any] | None = None) -> None:
        super().__init__(context, config)
        self.tool_config = self.config.get("wazuh", {})

    def health_check(self) -> bool:
        return True

    def get_version(self) -> str:
        return "api-or-drop"

    def execute(self, targets: list[str], output_dir: Path) -> list[Path]:
        mode = str(self.tool_config.get("mode", "drop")).lower()
        if mode == "api":
            return self._fetch_api(output_dir)
        return self._collect_drop(output_dir)

    def _collect_drop(self, output_dir: Path) -> list[Path]:
        drop = Path(self.tool_config.get("drop_dir", "evidence/raw/wazuh"))
        drop.mkdir(parents=True, exist_ok=True)
        files = list(drop.rglob("*.json"))
        if not files:
            stub = output_dir / "wazuh_empty_findings.json"
            stub.write_text(
                json.dumps({"data": {"affected_items": []}}, indent=2), encoding="utf-8"
            )
            return [stub]
        return files

    def _fetch_api(self, output_dir: Path) -> list[Path]:
        url = str(self.tool_config.get("api_url", os.environ.get("WAZUH_URL", ""))).rstrip("/")
        token = str(self.tool_config.get("api_token", os.environ.get("WAZUH_TOKEN", "")))
        verify_tls = bool(self.tool_config.get("verify_tls", False))
        if not url or not token:
            raise RunnerExecutionError("Wazuh API mode requires api_url and api_token")

        session = requests.Session()
        session.headers["Authorization"] = f"Bearer {token}"
        timeout = int(self.tool_config.get("global_timeout", 30))

        endpoints = {
            "vulnerabilities": f"{url}/vulnerability",
            "sca": f"{url}/sca",
        }
        artifacts: list[Path] = []
        for name, ep in endpoints.items():
            try:
                r = session.get(ep, timeout=timeout, verify=verify_tls)
                r.raise_for_status()
                data = r.json()
                data = redact_dict(data) if isinstance(data, dict) else data
                out = output_dir / f"wazuh_{name}.json"
                out.write_text(json.dumps(data, indent=2), encoding="utf-8")
                artifacts.append(out)
            except Exception as exc:
                raise RunnerExecutionError(f"Wazuh API fetch failed for {name}: {exc}") from exc
        return artifacts
