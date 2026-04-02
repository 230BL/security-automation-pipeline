"""Scope manifest loading and hash verification."""

from __future__ import annotations

import logging
from pathlib import Path

from src.orchestrator.exceptions import ScopeHashMismatchError, ScopeManifestError
from src.orchestrator.models import ScopeManifest
from src.utils.hashing import hash_file

LOG = logging.getLogger(__name__)


def load_manifest(path: Path) -> ScopeManifest:
    """Load and validate the scope manifest from YAML."""
    manifest = ScopeManifest.from_yaml(path)
    LOG.info(
        "Loaded scope manifest: %s (%s) with %d asset classes",
        manifest.assessment_name,
        manifest.organization,
        len(manifest.asset_classes),
    )
    return manifest


def verify_manifest_hash(manifest_path: Path, expected_hash: str) -> bool:
    """Verify the scope manifest file hash matches the expected value."""
    actual = hash_file(manifest_path)
    if actual != expected_hash:
        raise ScopeHashMismatchError(
            f"Scope manifest hash mismatch: expected {expected_hash}, got {actual}",
            context={"expected": expected_hash, "actual": actual},
        )
    LOG.info("Scope manifest hash verified: %s", actual[:16] + "...")
    return True


def verify_scope_pdf_hash(manifest: ScopeManifest, base_dir: Path) -> bool:
    """Verify the signed scope PDF hash from the authorization record."""
    pdf_path = base_dir / manifest.authorization.signed_scope_pdf
    if not pdf_path.exists():
        raise ScopeManifestError(f"Signed scope PDF not found: {pdf_path}")

    expected = manifest.authorization.scope_pdf_hash
    algorithm = manifest.authorization.scope_hash_algorithm
    actual = hash_file(pdf_path, algorithm)

    if actual != expected:
        raise ScopeHashMismatchError(
            f"Scope PDF hash mismatch: expected {expected}, got {actual}",
            context={"expected": expected, "actual": actual},
        )

    LOG.info("Signed scope PDF hash verified")
    return True
