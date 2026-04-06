from __future__ import annotations

from src.orchestrator.exceptions import PipelineError, TargetOutOfScopeError


def test_pipeline_error_defaults_context_to_empty_dict() -> None:
    err = PipelineError("boom")
    assert str(err) == "boom"
    assert err.context == {}


def test_pipeline_error_stores_explicit_context() -> None:
    err = PipelineError("boom", context={"tool": "nmap"})
    assert str(err) == "boom"
    assert err.context == {"tool": "nmap"}


def test_target_out_of_scope_error_builds_default_message_and_context() -> None:
    err = TargetOutOfScopeError({"10.0.0.1", "10.0.0.2"})

    assert "Targets outside allowlist" in str(err)
    assert err.out_of_scope_targets == {"10.0.0.1", "10.0.0.2"}
    assert err.context == {"out_of_scope": ["10.0.0.1", "10.0.0.2"]}


def test_target_out_of_scope_error_uses_custom_message() -> None:
    err = TargetOutOfScopeError({"10.0.0.1"}, message="custom scope failure")

    assert str(err) == "custom scope failure"
    assert err.context == {"out_of_scope": ["10.0.0.1"]}
