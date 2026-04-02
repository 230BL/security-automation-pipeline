"""Report generator using Jinja2 templates.

Generates executive and technical reports as Markdown from normalized,
scored, and deduplicated findings.
"""

from __future__ import annotations

import logging
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

LOG = logging.getLogger(__name__)


def generate_reports(
    findings: list[dict[str, Any]],
    run_id: str,
    manifest_summary: dict[str, Any],
    templates_dir: Path = Path("reports/templates"),
    output_dir: Path = Path("evidence/reports"),
) -> dict[str, Path]:
    """Generate executive and technical reports."""
    output_dir.mkdir(parents=True, exist_ok=True)

    env = Environment(
        loader=FileSystemLoader(str(templates_dir)),
        autoescape=select_autoescape(
            enabled_extensions=("html", "xml", "md"),
            default_for_string=False,
        ),
        trim_blocks=True,
        lstrip_blocks=True,
    )

    severity_counts = Counter(
        f.get("composite_severity", f.get("severity", "Info")) for f in findings
    )
    tool_counts = Counter(f.get("tool", "unknown") for f in findings)
    asset_counts = Counter(f.get("asset_id", "unknown") for f in findings)

    top_findings = sorted(
        [f for f in findings if f.get("composite_severity") in ("Critical", "High")],
        key=lambda x: float(x.get("composite_score", 0) or 0),
        reverse=True,
    )[:20]

    context = {
        "run_id": run_id,
        "generated_at": datetime.now(UTC).isoformat(),
        "manifest": manifest_summary,
        "total_findings": len(findings),
        "severity_counts": dict(severity_counts),
        "tool_counts": dict(tool_counts),
        "asset_counts": dict(asset_counts),
        "top_findings": top_findings,
        "findings": findings,
        "findings_by_severity": _group_by_severity(findings),
    }

    reports: dict[str, Path] = {}

    exec_template = env.get_template("executive.md.j2")
    exec_path = output_dir / f"{run_id}_executive.md"
    exec_path.write_text(exec_template.render(**context), encoding="utf-8")
    reports["executive"] = exec_path
    LOG.info("Generated executive report: %s", exec_path)

    tech_template = env.get_template("technical.md.j2")
    tech_path = output_dir / f"{run_id}_technical.md"
    tech_path.write_text(tech_template.render(**context), encoding="utf-8")
    reports["technical"] = tech_path
    LOG.info("Generated technical report: %s", tech_path)

    return reports


def _group_by_severity(findings: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {
        "Critical": [],
        "High": [],
        "Medium": [],
        "Low": [],
        "Info": [],
    }
    for f in findings:
        sev = str(f.get("composite_severity", f.get("severity", "Info")))
        grouped.setdefault(sev, []).append(f)
    return grouped
