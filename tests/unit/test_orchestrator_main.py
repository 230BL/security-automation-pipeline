"""Unit tests for scripts/run_pipeline.py."""

from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from scripts import run_pipeline as rp
from src.orchestrator.exceptions import RunnerExecutionError


class _DummyRunMetadata:
    def __init__(self, run_id: str = "RUN-UNIT") -> None:
        self.run_id = run_id

    def to_dict(self) -> dict[str, str]:
        return {"run_id": self.run_id}


def _make_ctx(targets: list[str]) -> Any:
    return SimpleNamespace(
        validated_targets=targets,
        manifest=SimpleNamespace(assessment_name="Lab Assessment"),
        run_metadata=_DummyRunMetadata(),
    )


class _RecordingState:
    instances: list[_RecordingState] = []

    def __init__(self, run_id: str, state_dir: Path) -> None:
        self.run_id = run_id
        self.state_dir = state_dir
        self.events: list[tuple[str, str, Any]] = []
        self.completed: set[str] = set()
        self.__class__.instances.append(self)

    def is_complete(self, phase_name: str) -> bool:
        return phase_name in self.completed

    def mark_started(self, phase_name: str) -> None:
        self.events.append(("started", phase_name, None))

    def mark_skipped(self, phase_name: str, reason: str) -> None:
        self.events.append(("skipped", phase_name, reason))

    def mark_complete(self, phase_name: str, artifacts: list[str] | None = None) -> None:
        self.completed.add(phase_name)
        self.events.append(("complete", phase_name, artifacts or []))

    def mark_failed(self, phase_name: str, reason: str) -> None:
        self.events.append(("failed", phase_name, reason))


def _patch_common(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    profile_cfg: dict[str, Any],
    ctx: Any,
) -> Path:
    profile_path = tmp_path / "profile.yml"
    profile_path.write_text("profile: test\n", encoding="utf-8")

    _RecordingState.instances.clear()

    monkeypatch.setattr(rp, "ROOT", tmp_path)
    monkeypatch.setattr(rp, "RunState", _RecordingState)
    monkeypatch.setattr(rp, "setup_logging", lambda *_a, **_k: None)
    monkeypatch.setattr(rp, "run_gate", lambda **_kwargs: ctx)
    monkeypatch.setattr(rp, "normalize", lambda findings, **_kwargs: findings)
    monkeypatch.setattr(rp, "validate_batch", lambda _findings: None)
    monkeypatch.setattr(rp, "score_batch", lambda findings, **_kwargs: findings)
    monkeypatch.setattr(rp, "deduplicate", lambda findings: findings)
    monkeypatch.setattr(rp, "build_manifest_summary", lambda _manifest: {"ok": True})
    monkeypatch.setattr(rp, "generate_reports", lambda *_a, **_k: None)
    monkeypatch.setattr(rp, "create_tickets", lambda *_a, **_k: None)
    monkeypatch.setattr(rp, "hash_file", lambda _path: "dummyhash")

    def fake_load_yaml(path: Path) -> dict[str, Any]:
        if path == profile_path:
            return profile_cfg
        if path.name == "tools.yml":
            return {"tool_defaults": {}}
        if path.name == "orchestrator.yml":
            return {}
        return {}

    monkeypatch.setattr(rp, "_load_yaml", fake_load_yaml)
    return profile_path


def test_load_yaml_reads_mapping(tmp_path: Path) -> None:
    path = tmp_path / "config.yml"
    path.write_text("key: value\ncount: 2\n", encoding="utf-8")
    assert rp._load_yaml(path) == {"key": "value", "count": 2}


def test_load_yaml_empty_returns_empty_dict(tmp_path: Path) -> None:
    path = tmp_path / "config.yml"
    path.write_text("", encoding="utf-8")
    assert rp._load_yaml(path) == {}


def test_load_yaml_non_mapping_returns_empty(tmp_path: Path) -> None:
    path = tmp_path / "config.yml"
    path.write_text("- one\n- two\n", encoding="utf-8")
    assert rp._load_yaml(path) == {}


def test_collect_runner_targets_routes_correctly() -> None:
    ctx = _make_ctx(
        [
            "192.168.56.10",
            "http://example.local",
            "https://example.local",
            "192.168.56.10",
        ]
    )

    assert rp._collect_runner_targets(ctx, "zap") == [
        "http://example.local",
        "https://example.local",
    ]
    assert rp._collect_runner_targets(ctx, "nikto") == [
        "http://example.local",
        "https://example.local",
    ]
    assert rp._collect_runner_targets(ctx, "nmap") == ["192.168.56.10"]
    assert rp._collect_runner_targets(ctx, "nuclei") == [
        "192.168.56.10",
        "http://example.local",
        "https://example.local",
    ]


def test_parse_artifacts_raises_for_missing_artifact(tmp_path: Path) -> None:
    missing = tmp_path / "missing.xml"

    with pytest.raises(
        RunnerExecutionError,
        match="Runner reported an artifact path that does not exist",
    ):
        rp._parse_artifacts("nmap", [missing])


def test_parse_artifacts_raises_for_empty_artifact(tmp_path: Path) -> None:
    empty = tmp_path / "empty.xml"
    empty.write_text("", encoding="utf-8")

    with pytest.raises(RunnerExecutionError, match="Runner produced an empty artifact"):
        rp._parse_artifacts("nmap", [empty])


def test_parse_artifacts_wazuh_combines_both_parsers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifact = tmp_path / "wazuh.json"
    artifact.write_text('{"ok": true}', encoding="utf-8")

    monkeypatch.setattr(
        rp,
        "parse_wazuh_vulnerabilities",
        lambda _path: [{"id": "vuln-1"}],
    )
    monkeypatch.setattr(
        rp,
        "parse_wazuh_sca",
        lambda _path: [{"id": "sca-1"}],
    )

    findings = rp._parse_artifacts("wazuh", [artifact])

    assert findings == [{"id": "vuln-1"}, {"id": "sca-1"}]


def test_parse_artifacts_wraps_parser_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifact = tmp_path / "nmap.xml"
    artifact.write_text("<xml/>", encoding="utf-8")

    def boom(_path: Path) -> list[dict[str, str]]:
        raise ValueError("boom")

    monkeypatch.setattr(rp, "parse_nmap_xml", boom)

    with pytest.raises(
        RunnerExecutionError,
        match="Failed to parse artifact for tool 'nmap'",
    ):
        rp._parse_artifacts("nmap", [artifact])


def test_parse_artifacts_blocks_scoutsuite_until_real_parser_exists(
    tmp_path: Path,
) -> None:
    artifact = tmp_path / "scoutsuite.json"
    artifact.write_text('{"ok": true}', encoding="utf-8")

    with pytest.raises(
        RunnerExecutionError,
        match="ScoutSuite parsing is not implemented yet",
    ):
        rp._parse_artifacts("scoutsuite", [artifact])


def test_map_defectdojo_environment_defaults_and_maps_values() -> None:
    assert rp._map_defectdojo_environment("lab") == "Development"
    assert rp._map_defectdojo_environment("prod") == "Production"
    assert rp._map_defectdojo_environment("testing") == "Testing"
    assert rp._map_defectdojo_environment("unknown") == "Development"


def test_main_dry_run_calls_gate_and_logging(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = _make_ctx(["192.168.56.10"])
    profile_path = tmp_path / "profile.yml"
    profile_path.write_text("profile: test\n", encoding="utf-8")

    calls: dict[str, Any] = {}

    def fake_load_yaml(path: Path) -> dict[str, Any]:
        if path == profile_path:
            return {
                "run_profile": {
                    "name": "lab_poc",
                    "environment": "lab",
                },
                "phases": [],
            }
        if path.name == "tools.yml":
            return {"tool_defaults": {}}
        if path.name == "orchestrator.yml":
            return {}
        return {}

    def fake_run_gate(**kwargs: Any) -> Any:
        calls["gate"] = kwargs
        return ctx

    def fake_setup_logging(run_id: str) -> None:
        calls["run_id"] = run_id

    monkeypatch.setattr(rp, "ROOT", tmp_path)
    monkeypatch.setattr(rp, "_load_yaml", fake_load_yaml)
    monkeypatch.setattr(rp, "run_gate", fake_run_gate)
    monkeypatch.setattr(rp, "setup_logging", fake_setup_logging)

    assert rp.main(profile_path, dry_run=True) == 0
    assert calls["run_id"] == "RUN-UNIT"
    assert calls["gate"]["workflow"] == "lab_poc"
    assert calls["gate"]["environment"] == "lab"


def test_main_skips_phase_for_disallowed_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = _make_ctx(["192.168.56.10"])
    profile_cfg = {
        "run_profile": {
            "name": "lab_poc",
            "environment": "lab",
        },
        "phases": [
            {
                "name": "cloud_only",
                "enabled": True,
                "allowed_environments": ["production"],
                "runners": ["nmap"],
            }
        ],
        "workflow": {},
    }

    profile_path = _patch_common(monkeypatch, tmp_path, profile_cfg, ctx)
    monkeypatch.setattr(rp, "_runner_map", lambda: {"nmap": object})

    assert rp.main(profile_path) == 0

    state = _RecordingState.instances[-1]
    assert ("started", "cloud_only", None) in state.events
    assert any(event[0] == "skipped" and event[1] == "cloud_only" for event in state.events)


def test_main_skips_targeted_runner_when_no_matching_targets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = _make_ctx(["192.168.56.10"])
    profile_cfg = {
        "run_profile": {
            "name": "lab_poc",
            "environment": "lab",
        },
        "phases": [
            {
                "name": "web_phase",
                "enabled": True,
                "runners": ["zap"],
            }
        ],
        "workflow": {},
    }

    profile_path = _patch_common(monkeypatch, tmp_path, profile_cfg, ctx)

    class _TrackingRunner:
        constructed = 0
        run_called = 0

        def __init__(self, *_args: Any, **_kwargs: Any) -> None:
            type(self).constructed += 1

        def run(self, _targets: list[str], _out_dir: Path) -> list[Path]:
            type(self).run_called += 1
            return []

    monkeypatch.setattr(rp, "_runner_map", lambda: {"zap": _TrackingRunner})

    assert rp.main(profile_path) == 0
    assert _TrackingRunner.constructed == 1
    assert _TrackingRunner.run_called == 0

    state = _RecordingState.instances[-1]
    assert ("complete", "web_phase", []) in state.events


def test_main_fails_and_marks_phase_failed_when_runner_produces_no_artifacts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = _make_ctx(["192.168.56.10"])
    profile_cfg = {
        "run_profile": {
            "name": "lab_poc",
            "environment": "lab",
        },
        "phases": [
            {
                "name": "service_validation",
                "enabled": True,
                "runners": ["nmap"],
            }
        ],
        "workflow": {},
    }

    profile_path = _patch_common(monkeypatch, tmp_path, profile_cfg, ctx)

    class _EmptyRunner:
        def __init__(self, *_args: Any, **_kwargs: Any) -> None:
            pass

        def run(self, _targets: list[str], _out_dir: Path) -> list[Path]:
            return []

    monkeypatch.setattr(rp, "_runner_map", lambda: {"nmap": _EmptyRunner})

    with pytest.raises(RunnerExecutionError, match="nmap produced no artifacts"):
        rp.main(profile_path)

    state = _RecordingState.instances[-1]
    assert any(event[0] == "failed" and event[1] == "service_validation" for event in state.events)


def test_main_writes_defectdojo_payload_and_imports_results(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = _make_ctx(["192.168.56.10"])
    profile_cfg = {
        "run_profile": {
            "name": "lab_poc",
            "environment": "lab",
        },
        "phases": [
            {
                "name": "service_validation",
                "enabled": True,
                "runners": ["nmap"],
            }
        ],
        "workflow": {
            "deduplicate": False,
            "import_defectdojo": True,
            "create_tickets": False,
            "index_opensearch": False,
        },
    }

    profile_path = _patch_common(monkeypatch, tmp_path, profile_cfg, ctx)

    class _ArtifactRunner:
        def __init__(self, *_args: Any, **_kwargs: Any) -> None:
            pass

        def run(self, _targets: list[str], out_dir: Path) -> list[Path]:
            out_dir.mkdir(parents=True, exist_ok=True)
            artifact = out_dir / "nmap_RUN-UNIT.xml"
            artifact.write_text("<nmaprun/>", encoding="utf-8")
            return [artifact]

    class _FakeDojo:
        instances: list[_FakeDojo] = []

        def __init__(self, url: str, token: str) -> None:
            self.url = url
            self.token = token
            self.calls: list[dict[str, Any]] = []
            self.__class__.instances.append(self)

        def import_tool_results(self, **kwargs: Any) -> None:
            self.calls.append(kwargs)

    monkeypatch.setattr(rp, "_runner_map", lambda: {"nmap": _ArtifactRunner})
    monkeypatch.setattr(
        rp,
        "_parse_artifacts",
        lambda _tool, _artifacts: [
            {
                "title": "Open port 80",
                "severity": "Low",
                "description": "Service exposed",
                "endpoint": "http://192.168.56.10:80",
                "cve": "",
                "remediation": "Close the port",
                "tags": ["nmap"],
            }
        ],
    )
    monkeypatch.setattr(rp, "DefectDojoClient", _FakeDojo)

    monkeypatch.setenv("DEFECTDOJO_URL", "http://localhost:8080")
    monkeypatch.setenv("DEFECTDOJO_TOKEN", "token")

    assert rp.main(profile_path) == 0

    import_file = tmp_path / "evidence" / "normalized" / "RUN-UNIT" / "generic_findings.json"
    assert import_file.exists()

    payload = json.loads(import_file.read_text(encoding="utf-8"))
    assert payload["name"] == "Security Automation Pipeline"
    assert len(payload["findings"]) == 1
    assert payload["findings"][0]["title"] == "Open port 80"
    assert payload["findings"][0]["tags"] == ["nmap"]
    assert payload["findings"][0]["references"] == "http://192.168.56.10:80"

    dojo = _FakeDojo.instances[-1]
    assert dojo.url == "http://localhost:8080"
    assert dojo.token == os.environ["DEFECTDOJO_TOKEN"]
    assert dojo.calls[0]["product_name"] == "Lab Assessment"
    assert dojo.calls[0]["engagement_name"] == "lab_poc"
    assert dojo.calls[0]["tool"] == "generic"
    assert dojo.calls[0]["environment"] == "Development"
