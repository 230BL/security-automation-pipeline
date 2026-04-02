"""Core data models for the pipeline.

All models use dataclasses with explicit types.
Factory methods validate required fields and raise ScopeManifestError on
missing or invalid data.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import yaml

from src.orchestrator.exceptions import ScopeManifestError


@dataclass(frozen=True)
class MaintenanceWindow:
    """A named maintenance window with start and end times."""

    name: str
    start: datetime
    end: datetime

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> MaintenanceWindow:
        required = ["name", "start", "end"]
        for key in required:
            if key not in data:
                raise ScopeManifestError(f"Maintenance window missing field: {key}")
        return cls(
            name=str(data["name"]),
            start=_parse_datetime(data["start"]),
            end=_parse_datetime(data["end"]),
        )

    def is_open(self, now: datetime | None = None) -> bool:
        now = now or datetime.now(UTC)
        return self.start <= now <= self.end


@dataclass(frozen=True)
class WebContext:
    """Web application test context for staging/lab checks."""

    url: str
    auth_type: str | None = None
    credential_ref: str | None = None
    openapi_spec: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> WebContext:
        if "url" not in data:
            raise ScopeManifestError("Web context missing field: url")
        return cls(
            url=str(data["url"]),
            auth_type=data.get("auth_type"),
            credential_ref=data.get("credential_ref"),
            openapi_spec=data.get("openapi_spec"),
        )


@dataclass(frozen=True)
class AssetClass:
    """A group of targets sharing environment, credentials, and allowed tools."""

    name: str
    environment: str
    allowed_tools: list[str]
    maintenance_window: str
    auth_method: str | None = None
    credential_ref: str | None = None
    cidrs: list[str] = field(default_factory=list)
    hostnames: list[str] = field(default_factory=list)
    accounts: list[str] = field(default_factory=list)
    tenant_id: str | None = None
    regions: list[str] = field(default_factory=list)
    web_contexts: list[WebContext] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AssetClass:
        required = ["class", "environment", "allowed_tools", "maintenance_window"]
        for key in required:
            if key not in data:
                raise ScopeManifestError(f"Asset class missing field: {key}")

        allowed_tools = data["allowed_tools"]
        if not isinstance(allowed_tools, list) or not all(
            isinstance(x, str) for x in allowed_tools
        ):
            raise ScopeManifestError("Asset class allowed_tools must be a list[str]")

        return cls(
            name=str(data["class"]),
            environment=str(data["environment"]),
            allowed_tools=list(allowed_tools),
            maintenance_window=str(data["maintenance_window"]),
            auth_method=data.get("auth_method"),
            credential_ref=data.get("credential_ref"),
            cidrs=[str(x) for x in data.get("cidrs", [])],
            hostnames=[str(x) for x in data.get("hostnames", [])],
            accounts=[str(x) for x in data.get("accounts", [])],
            tenant_id=data.get("tenant_id"),
            regions=[str(x) for x in data.get("regions", [])],
            web_contexts=[WebContext.from_dict(w) for w in data.get("web_contexts", [])],
        )

    def all_targets(self) -> list[str]:
        targets: list[str] = []
        targets.extend(self.cidrs)
        targets.extend(self.hostnames)
        targets.extend(self.accounts)
        if self.tenant_id:
            targets.append(self.tenant_id)
        targets.extend(
            str(web_ctx.url).strip() for web_ctx in self.web_contexts if str(web_ctx.url).strip()
        )
        return targets


@dataclass(frozen=True)
class Authorization:
    """Authorization record from the scope manifest."""

    signed_scope_pdf: str
    authorizing_official: str
    date_signed: str
    scope_hash_algorithm: str
    scope_pdf_hash: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Authorization:
        required = [
            "signed_scope_pdf",
            "authorizing_official",
            "date_signed",
            "scope_hash_algorithm",
            "scope_pdf_hash",
        ]
        for key in required:
            if key not in data:
                raise ScopeManifestError(f"Authorization missing field: {key}")
        return cls(**{k: str(data[k]) for k in required})


@dataclass(frozen=True)
class EvidenceHandling:
    """Evidence classification and retention rules."""

    classification: str
    retention_days: int
    encrypt_at_rest: bool
    redact_secrets: bool
    redact_pii: bool

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EvidenceHandling:
        return cls(
            classification=str(data.get("classification", "internal_confidential")),
            retention_days=int(data.get("retention_days", 395)),
            encrypt_at_rest=bool(data.get("encrypt_at_rest", True)),
            redact_secrets=bool(data.get("redact_secrets", True)),
            redact_pii=bool(data.get("redact_pii", True)),
        )


@dataclass(frozen=True)
class EmergencyContact:
    """Emergency stop contact."""

    name: str
    email: str
    phone: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EmergencyContact:
        for key in ("name", "email"):
            if key not in data:
                raise ScopeManifestError(f"Emergency contact missing field: {key}")
        return cls(
            name=str(data["name"]),
            email=str(data["email"]),
            phone=str(data.get("phone", "")),
        )


@dataclass(frozen=True)
class RulesOfEngagement:
    """Operational rules for the assessment."""

    prohibited: list[str]
    max_concurrent_hosts_per_class: int
    stop_on_service_degradation: bool
    stop_on_scope_mismatch: bool

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RulesOfEngagement:
        return cls(
            prohibited=[str(x) for x in data.get("prohibited", [])],
            max_concurrent_hosts_per_class=int(data.get("max_concurrent_hosts_per_class", 5)),
            stop_on_service_degradation=bool(data.get("stop_on_service_degradation", True)),
            stop_on_scope_mismatch=bool(data.get("stop_on_scope_mismatch", True)),
        )


@dataclass
class ScopeManifest:
    """Complete scope manifest loaded from YAML."""

    version: str
    organization: str
    assessment_name: str
    authorization: Authorization
    maintenance_windows: list[MaintenanceWindow]
    asset_classes: list[AssetClass]
    exclusions_cidrs: list[str]
    exclusions_hostnames: list[str]
    approved_workflows: list[str]
    rules_of_engagement: RulesOfEngagement
    evidence_handling: EvidenceHandling
    emergency_contacts: list[EmergencyContact]
    allowlist_file: str
    max_target_count: int

    @classmethod
    def from_yaml(cls, path: Path) -> ScopeManifest:
        if not path.exists():
            raise ScopeManifestError(f"Scope manifest not found: {path}")

        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ScopeManifestError("Scope manifest is not a valid YAML mapping")

        required_top = [
            "version",
            "organization",
            "assessment_name",
            "authorization",
            "assessment_window",
            "targets",
            "approved_workflows",
            "rules_of_engagement",
            "evidence_handling",
            "emergency_contacts",
        ]
        for key in required_top:
            if key not in data:
                raise ScopeManifestError(f"Scope manifest missing top-level field: {key}")

        targets = data["targets"]
        if not isinstance(targets, dict):
            raise ScopeManifestError("targets must be a mapping")

        window = data["assessment_window"]
        if not isinstance(window, dict):
            raise ScopeManifestError("assessment_window must be a mapping")

        exclusions = data.get("exclusions", {})
        if exclusions is None:
            exclusions = {}
        if not isinstance(exclusions, dict):
            raise ScopeManifestError("exclusions must be a mapping")

        maintenance_windows = window.get("maintenance_windows", [])
        if maintenance_windows is None:
            maintenance_windows = []
        if not isinstance(maintenance_windows, list):
            raise ScopeManifestError("assessment_window.maintenance_windows must be a list")

        asset_classes = targets.get("asset_classes", [])
        if asset_classes is None:
            asset_classes = []
        if not isinstance(asset_classes, list):
            raise ScopeManifestError("targets.asset_classes must be a list")

        approved_workflows = data["approved_workflows"]
        if not isinstance(approved_workflows, list) or not all(
            isinstance(x, str) for x in approved_workflows
        ):
            raise ScopeManifestError("approved_workflows must be a list[str]")

        contacts = data["emergency_contacts"]
        if not isinstance(contacts, list):
            raise ScopeManifestError("emergency_contacts must be a list")

        return cls(
            version=str(data["version"]),
            organization=str(data["organization"]),
            assessment_name=str(data["assessment_name"]),
            authorization=Authorization.from_dict(data["authorization"]),
            maintenance_windows=[MaintenanceWindow.from_dict(w) for w in maintenance_windows],
            asset_classes=[AssetClass.from_dict(ac) for ac in asset_classes],
            exclusions_cidrs=[str(x) for x in exclusions.get("cidrs", [])],
            exclusions_hostnames=[str(x) for x in exclusions.get("hostnames", [])],
            approved_workflows=[str(x) for x in approved_workflows],
            rules_of_engagement=RulesOfEngagement.from_dict(data["rules_of_engagement"]),
            evidence_handling=EvidenceHandling.from_dict(data["evidence_handling"]),
            emergency_contacts=[EmergencyContact.from_dict(c) for c in contacts],
            allowlist_file=str(targets.get("allowlist_file", "scope/allowlist.txt")),
            max_target_count=int(targets.get("max_target_count", 250)),
        )

    def get_window(self, name: str) -> MaintenanceWindow | None:
        for w in self.maintenance_windows:
            if w.name == name:
                return w
        return None

    def all_targets(self) -> list[str]:
        targets: list[str] = []
        for ac in self.asset_classes:
            targets.extend(ac.all_targets())
        return targets

    def all_exclusions(self) -> list[str]:
        exclusions: list[str] = []
        exclusions.extend(self.exclusions_cidrs)
        exclusions.extend(self.exclusions_hostnames)
        return exclusions


@dataclass
class RunMetadata:
    """Metadata for a single pipeline run."""

    run_id: str = field(
        default_factory=lambda: (
            f"RUN-{datetime.now(UTC).strftime('%Y%m%d-%H%M%S')}-{uuid4().hex[:8]}"
        )
    )
    scope_hash: str = ""
    allowlist_hash: str = ""
    workflow: str = ""
    environment: str = ""
    executor: str = ""
    start_time: datetime = field(default_factory=lambda: datetime.now(UTC))
    end_time: datetime | None = None
    status: str = "INITIALIZED"
    phases_completed: list[str] = field(default_factory=list)
    artifact_paths: list[str] = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "scope_hash": self.scope_hash,
            "allowlist_hash": self.allowlist_hash,
            "workflow": self.workflow,
            "environment": self.environment,
            "executor": self.executor,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "status": self.status,
            "phases_completed": self.phases_completed,
            "artifact_paths": self.artifact_paths,
            "error": self.error,
        }


def _parse_datetime(value: Any) -> datetime:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value
    if isinstance(value, str):
        from dateutil.parser import parse as dateutil_parse

        dt = dateutil_parse(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt
    raise ScopeManifestError(f"Cannot parse datetime from: {value}")
