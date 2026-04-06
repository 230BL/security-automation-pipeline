from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from src.orchestrator.exceptions import (
    ScopeHashMismatchError,
    ScopeManifestError,
)
from src.orchestrator.manifest import (
    load_manifest,
    verify_manifest_hash,
    verify_scope_pdf_hash,
)
from src.orchestrator.models import ScopeManifest


def test_manifest_loads_valid(fixtures: Path) -> None:
    manifest = ScopeManifest.from_yaml(fixtures / "scope" / "valid_manifest.yml")

    assert manifest.assessment_name == "Test Assessment"
    assert len(manifest.asset_classes) == 1


def test_manifest_missing_fields_raises(fixtures: Path) -> None:
    with pytest.raises(ScopeManifestError):
        ScopeManifest.from_yaml(fixtures / "scope" / "invalid_manifest.yml")


def test_load_manifest_returns_scope_manifest(fixtures: Path) -> None:
    manifest = load_manifest(fixtures / "scope" / "valid_manifest.yml")

    assert isinstance(manifest, ScopeManifest)
    assert manifest.assessment_name == "Test Assessment"
    assert manifest.organization == "Test Org"


def test_verify_manifest_hash_success(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    manifest_path = tmp_path / "scope_manifest.yml"
    manifest_path.write_text("name: test\n", encoding="utf-8")

    monkeypatch.setattr(
        "src.orchestrator.manifest.hash_file",
        lambda path: "expected-hash",
    )

    assert verify_manifest_hash(manifest_path, "expected-hash") is True


def test_verify_manifest_hash_mismatch_raises_with_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest_path = tmp_path / "scope_manifest.yml"
    manifest_path.write_text("name: test\n", encoding="utf-8")

    monkeypatch.setattr(
        "src.orchestrator.manifest.hash_file",
        lambda path: "actual-hash",
    )

    with pytest.raises(ScopeHashMismatchError) as exc:
        verify_manifest_hash(manifest_path, "expected-hash")

    assert "Scope manifest hash mismatch" in str(exc.value)
    assert exc.value.context == {
        "expected": "expected-hash",
        "actual": "actual-hash",
    }


def test_verify_scope_pdf_hash_missing_file_raises(tmp_path: Path) -> None:
    manifest = SimpleNamespace(
        authorization=SimpleNamespace(
            signed_scope_pdf="missing.pdf",
            scope_pdf_hash="expected-pdf-hash",
            scope_hash_algorithm="sha256",
        )
    )

    with pytest.raises(ScopeManifestError, match="Signed scope PDF not found"):
        verify_scope_pdf_hash(manifest, tmp_path)


def test_verify_scope_pdf_hash_success_uses_expected_algorithm(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pdf_path = tmp_path / "signed_scope.pdf"
    pdf_path.write_text("pdf-bytes", encoding="utf-8")

    manifest = SimpleNamespace(
        authorization=SimpleNamespace(
            signed_scope_pdf="signed_scope.pdf",
            scope_pdf_hash="expected-pdf-hash",
            scope_hash_algorithm="sha256",
        )
    )

    calls: list[tuple[Path, str]] = []

    def fake_hash_file(path: Path, algorithm: str = "sha256") -> str:
        calls.append((path, algorithm))
        return "expected-pdf-hash"

    monkeypatch.setattr("src.orchestrator.manifest.hash_file", fake_hash_file)

    assert verify_scope_pdf_hash(manifest, tmp_path) is True
    assert calls == [(pdf_path, "sha256")]


def test_verify_scope_pdf_hash_mismatch_raises_with_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pdf_path = tmp_path / "signed_scope.pdf"
    pdf_path.write_text("pdf-bytes", encoding="utf-8")

    manifest = SimpleNamespace(
        authorization=SimpleNamespace(
            signed_scope_pdf="signed_scope.pdf",
            scope_pdf_hash="expected-pdf-hash",
            scope_hash_algorithm="sha256",
        )
    )

    monkeypatch.setattr(
        "src.orchestrator.manifest.hash_file",
        lambda path, algorithm="sha256": "actual-pdf-hash",
    )

    with pytest.raises(ScopeHashMismatchError) as exc:
        verify_scope_pdf_hash(manifest, tmp_path)

    assert "Scope PDF hash mismatch" in str(exc.value)
    assert exc.value.context == {
        "expected": "expected-pdf-hash",
        "actual": "actual-pdf-hash",
    }
