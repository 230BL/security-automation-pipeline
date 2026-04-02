#!/usr/bin/env python3
"""Main orchestrator for the vulnerability-management pipeline.

Enforces governance gates, runs approved phases, normalizes results,
and optionally pushes to DefectDojo + OpenSearch.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from datetime import date as _date
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.integrations.defectdojo_client import DefectDojoClient  # noqa: E402
from src.integrations.opensearch_client import OpenSearchClient  # noqa: E402
from src.integrations.ticket_client import create_tickets  # noqa: E402
from src.orchestrator.gate import run_gate  # noqa: E402
from src.orchestrator.run_state import RunState  # noqa: E402
from src.parsers.lynis_dat import parse_lynis_dat  # noqa: E402
from src.parsers.nikto_json import parse_nikto_json  # noqa: E402
from src.parsers.nmap_xml import parse_nmap_xml  # noqa: E402
from src.parsers.normalize import normalize  # noqa: E402
from src.parsers.nuclei_jsonl import parse_nuclei_jsonl  # noqa: E402
from src.parsers.openvas_csv import parse_openvas_csv  # noqa: E402
from src.parsers.prowler_json import parse_prowler_json  # noqa: E402
from src.parsers.schema import validate_batch  # noqa: E402
from src.parsers.wazuh_json import parse_wazuh_sca, parse_wazuh_vulnerabilities  # noqa: E402
from src.parsers.zap_xml import parse_zap_xml  # noqa: E402
from src.reporting.executive import build_manifest_summary  # noqa: E402
from src.reporting.generator import generate_reports  # noqa: E402
from src.runners.greenbone_runner import GreenboneRunner  # noqa: E402
from src.runners.inventory_runner import InventoryRunner  # noqa: E402
from src.runners.lynis_runner import LynisRunner  # noqa: E402
from src.runners.nikto_runner import NiktoRunner  # noqa: E402
from src.runners.nmap_runner import NmapRunner  # noqa: E402
from src.runners.nuclei_runner import NucleiRunner  # noqa: E402
from src.runners.osquery_runner import OsqueryRunner  # noqa: E402
from src.runners.prowler_runner import ProwlerRunner  # noqa: E402
from src.runners.scoutsuite_runner import ScoutSuiteRunner  # noqa: E402
from src.runners.wazuh_runner import WazuhRunner  # noqa: E402
from src.runners.zap_runner import ZapRunner  # noqa: E402
from src.scoring.dedup import deduplicate  # noqa: E402
from src.scoring.risk_scorer import score_batch  # noqa: E402
from src.utils.hashing import hash_file  # noqa: E402
from src.utils.logging_setup import setup_logging  # noqa: E402

LOG = logging.getLogger("pipeline")


def _load_yaml(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return data if isinstance(data, dict) else {}


def _runner_map() -> dict[str, Any]:
    return {
        "inventory": InventoryRunner,
        "osquery": OsqueryRunner,
        "wazuh": WazuhRunner,
        "nmap": NmapRunner,
        "greenbone": GreenboneRunner,
        "lynis": LynisRunner,
        "zap": ZapRunner,
        "nikto": NiktoRunner,
        "nuclei": NucleiRunner,
        "prowler": ProwlerRunner,
        "scoutsuite": ScoutSuiteRunner,
    }


def _is_web_target(target: str) -> bool:
    value = str(target).strip().lower()
    return value.startswith("http://") or value.startswith("https://")


def _dedupe_targets(targets: list[str]) -> list[str]:
    seen: set[str] = set()
    unique: list[str] = []
    for target in targets:
        value = str(target).strip()
        if not value:
            continue
        key = value.lower()
        if key in seen:
            continue
        seen.add(key)
        unique.append(value)
    return unique


def _collect_runner_targets(ctx: Any, runner_name: str) -> list[str]:
    base_targets = _dedupe_targets(list(ctx.validated_targets))
    web_targets = [target for target in base_targets if _is_web_target(target)]

    if runner_name in {"zap", "nikto", "nuclei"}:
        return web_targets

    return [target for target in base_targets if not _is_web_target(target)]


def _parse_artifacts(tool: str, artifacts: list[Path]) -> list[Any]:
    findings = []
    for a in artifacts:
        if not a.exists() or a.stat().st_size == 0:
            continue
        if tool == "nmap":
            findings += parse_nmap_xml(a)
        elif tool == "greenbone":
            findings += parse_openvas_csv(a)
        elif tool == "zap":
            findings += parse_zap_xml(a)
        elif tool == "nikto":
            findings += parse_nikto_json(a)
        elif tool == "wazuh":
            findings += parse_wazuh_vulnerabilities(a)
            findings += parse_wazuh_sca(a)
        elif tool == "prowler":
            findings += parse_prowler_json(a)
        elif tool == "scoutsuite":
            findings += parse_prowler_json(a)
        elif tool == "lynis":
            findings += parse_lynis_dat(a)
        elif tool == "nuclei":
            findings += parse_nuclei_jsonl(a)
    return findings


def _map_defectdojo_environment(environment: str) -> str:
    value = (environment or "").strip().lower()
    mapping = {
        "lab": "Development",
        "dev": "Development",
        "development": "Development",
        "test": "Testing",
        "testing": "Testing",
        "stage": "Staging",
        "staging": "Staging",
        "prod": "Production",
        "production": "Production",
    }
    return mapping.get(value, "Development")


def main(profile: Path, dry_run: bool = False) -> int:
    profile_cfg = _load_yaml(profile)
    run_profile = profile_cfg.get("run_profile", profile_cfg)

    workflow = str(run_profile.get("name", "lab_poc"))
    environment = str(run_profile.get("environment", "lab"))

    tools_cfg = _load_yaml(ROOT / "config" / "tools.yml").get("tool_defaults", {})

    ctx = run_gate(
        manifest_path=ROOT / "scope" / "scope_manifest.yml",
        base_dir=ROOT,
        workflow=workflow,
        environment=environment,
        executor=os.environ.get("USER", os.environ.get("USERNAME", "unknown")),
        config=_load_yaml(ROOT / "config" / "orchestrator.yml"),
    )

    setup_logging(ctx.run_metadata.run_id)

    if dry_run:
        LOG.info("Dry-run gate passed for %s", ctx.run_metadata.run_id)
        return 0

    run_id = ctx.run_metadata.run_id
    state = RunState(run_id=run_id, state_dir=ROOT / "evidence" / "state")
    raw_dir = ROOT / "evidence" / "raw" / run_id
    norm_dir = ROOT / "evidence" / "normalized" / run_id
    raw_dir.mkdir(parents=True, exist_ok=True)
    norm_dir.mkdir(parents=True, exist_ok=True)

    all_findings = []

    for phase in profile_cfg.get("phases", []):
        if not phase.get("enabled", False):
            continue

        phase_name = str(phase["name"])
        if state.is_complete(phase_name):
            continue

        state.mark_started(phase_name)

        allowed_envs = phase.get("allowed_environments")
        if allowed_envs and environment not in allowed_envs:
            state.mark_skipped(phase_name, f"env '{environment}' not in {allowed_envs}")
            continue

        phase_out = raw_dir / phase_name
        phase_out.mkdir(parents=True, exist_ok=True)
        artifacts_all: list[str] = []

        for runner_name in phase.get("runners", []):
            runner_name_str = str(runner_name)
            runner_cls = _runner_map().get(runner_name_str)
            if runner_cls is None:
                raise RuntimeError(f"Unknown runner: {runner_name_str}")

            runner = runner_cls(ctx, tools_cfg)
            out_dir = phase_out / runner_name_str
            runner_targets = _collect_runner_targets(ctx, runner_name_str)
            artifacts = runner.run(runner_targets, out_dir)
            artifacts_all += [str(p) for p in artifacts]
            all_findings += _parse_artifacts(runner_name_str, artifacts)

        state.mark_complete(phase_name, artifacts=artifacts_all)

    normalized = normalize(all_findings, run_id=run_id, environment=environment)
    validate_batch(normalized)

    scored = score_batch(
        normalized,
        asset_context=None,
        policy_path=ROOT / "policy" / "risk_policy.yml",
    )

    if bool(profile_cfg.get("workflow", {}).get("deduplicate", True)):
        scored = deduplicate(scored)

    findings_path = norm_dir / "findings.json"
    findings_path.write_text(json.dumps(scored, indent=2, default=str), encoding="utf-8")
    (norm_dir / "findings.sha256").write_text(hash_file(findings_path), encoding="utf-8")

    manifest_summary = build_manifest_summary(ctx.manifest)
    generate_reports(
        scored,
        run_id=run_id,
        manifest_summary=manifest_summary,
        output_dir=ROOT / "evidence" / "reports",
    )

    wf = profile_cfg.get("workflow", {})

    if wf.get("create_tickets", False):
        create_tickets(
            scored,
            rules_path=ROOT / "policy" / "ticket_rules.yml",
            output_path=norm_dir / "tickets.json",
        )

    if wf.get("index_opensearch", False):
        client = OpenSearchClient(
            host=os.environ.get("OPENSEARCH_HOST", "localhost"),
            port=int(os.environ.get("OPENSEARCH_PORT", "9200")),
            http_auth=(
                os.environ.get("OPENSEARCH_USER", "admin"),
                os.environ.get("OPENSEARCH_PASSWORD", "admin"),
            ),
        )
        if client.health_check():
            client.index_findings(scored, run_id=run_id)
            client.index_run_metadata(run_id, ctx.run_metadata.to_dict(), finding_count=len(scored))

    if wf.get("import_defectdojo", False):
        dojo_url = os.environ.get("DEFECTDOJO_URL", "")
        dojo_token = os.environ.get("DEFECTDOJO_TOKEN", "")
        if dojo_url and dojo_token:
            dojo = DefectDojoClient(dojo_url, dojo_token)
            import_file = norm_dir / "generic_findings.json"

            dojo_findings = []
            for f in scored:
                tags = f.get("tags", [])
                if not isinstance(tags, list):
                    tags = [str(tags)] if tags else []
                else:
                    tags = [str(tag) for tag in tags if tag is not None]

                references = f.get("endpoint") or ""
                if isinstance(references, (list, dict)):
                    references = json.dumps(references, default=str)
                else:
                    references = str(references)

                dojo_findings.append(
                    {
                        "title": str(f.get("title", "")),
                        "severity": str(f.get("composite_severity") or f.get("severity", "Info")),
                        "description": str(f.get("description", "")),
                        "date": _date.today().isoformat(),
                        "cve": str(f.get("cve") or ""),
                        "mitigation": str(f.get("remediation") or ""),
                        "references": references,
                        "tags": tags,
                    }
                )

            payload = {
                "name": "Security Automation Pipeline",
                "findings": dojo_findings,
            }
            import_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")

            dojo_environment = _map_defectdojo_environment(environment)
            dojo.import_tool_results(
                product_name=ctx.manifest.assessment_name,
                engagement_name=workflow,
                tool="generic",
                file_path=import_file,
                environment=dojo_environment,
            )

    LOG.info("Pipeline complete run_id=%s findings=%d", run_id, len(scored))
    return 0


def cli() -> None:
    p = argparse.ArgumentParser(description="Run the gated security automation pipeline")
    p.add_argument(
        "--profile",
        default="config/profiles/lab_poc.yml",
        help="Path to workflow profile YAML (relative to project root)",
    )
    p.add_argument("--dry-run", action="store_true", help="Validate governance gate only")
    args = p.parse_args()
    raise SystemExit(main(profile=ROOT / args.profile, dry_run=args.dry_run))


if __name__ == "__main__":
    cli()
