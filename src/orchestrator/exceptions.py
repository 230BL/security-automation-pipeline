"""Pipeline exception hierarchy.

Every failure mode has a distinct exception so callers can handle
scope violations, tool failures, and data errors independently.
No generic exceptions are used in the pipeline.
"""

from __future__ import annotations

from typing import Any


class PipelineError(Exception):
    """Base for all pipeline errors."""

    def __init__(self, message: str, context: dict[str, Any] | None = None) -> None:
        self.context = context or {}
        super().__init__(message)


# ── Governance gate errors ──────────────────────────────────────────


class ScopeError(PipelineError):
    """Base for scope-related failures."""


class ScopeSignatureError(ScopeError):
    """Signed scope document missing or signature verification failed."""


class ScopeHashMismatchError(ScopeError):
    """Scope manifest hash does not match the approval record."""


class ScopeManifestError(ScopeError):
    """Scope manifest is malformed or missing required fields."""


class AllowlistError(PipelineError):
    """Base for allowlist-related failures."""


class AllowlistLoadError(AllowlistError):
    """Allowlist file cannot be loaded or parsed."""


class TargetOutOfScopeError(AllowlistError):
    """One or more targets are not present in the approved allowlist."""

    def __init__(self, out_of_scope_targets: set[str], message: str = "") -> None:
        self.out_of_scope_targets = out_of_scope_targets
        msg = message or f"Targets outside allowlist: {out_of_scope_targets}"
        super().__init__(msg, context={"out_of_scope": sorted(out_of_scope_targets)})


class MaintenanceWindowError(PipelineError):
    """Maintenance window is not currently open or not defined."""


class WorkflowNotApprovedError(PipelineError):
    """Requested workflow type is not in the approved list."""


class EnvironmentMismatchError(PipelineError):
    """Environment label does not match what is approved for this step."""


class CredentialError(PipelineError):
    """Credential missing, expired, or overprivileged."""


# ── Runner errors ───────────────────────────────────────────────────


class RunnerError(PipelineError):
    """Base for tool runner failures."""


class RunnerExecutionError(RunnerError):
    """Tool process exited with an error or timed out."""


class RunnerHealthError(RunnerError):
    """Tool health check failed before or during execution."""


class RunnerOutputError(RunnerError):
    """Tool produced no output or output is unreadable."""


class RateLimitExceededError(RunnerError):
    """Rate limit threshold was reached during scanning."""


class TargetExpansionError(RunnerError):
    """Scanner attempted to expand beyond the approved target count."""


class ServiceDegradationError(RunnerError):
    """Target service showed signs of degradation during scanning."""


# ── Parser errors ───────────────────────────────────────────────────


class ParserError(PipelineError):
    """Base for parsing failures."""


class ParserSchemaError(ParserError):
    """Parsed output does not conform to the normalized finding schema."""


class ParserEmptyResultError(ParserError):
    """Parser produced zero findings from a non-empty input file."""


# ── Integration errors ──────────────────────────────────────────────


class IntegrationError(PipelineError):
    """Base for external service integration failures."""


class DefectDojoError(IntegrationError):
    """DefectDojo API call failed."""


class OpenSearchError(IntegrationError):
    """OpenSearch indexing or query failed."""


class VaultError(IntegrationError):
    """Secrets vault access failed."""


class TicketError(IntegrationError):
    """Ticket system integration failed."""


# ── Run state errors ────────────────────────────────────────────────


class RunStateError(PipelineError):
    """Run state file is corrupted or inconsistent."""


class EmergencyStopError(PipelineError):
    """Emergency stop was triggered. All execution must halt immediately."""
