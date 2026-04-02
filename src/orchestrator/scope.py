"""Scope document signature verification.

Uses GPG detached signatures to verify the scope manifest was signed
by an authorized official. Lab mode is available but must be explicitly
enabled and always logs a warning.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from pathlib import Path

from src.orchestrator.exceptions import ScopeSignatureError

LOG = logging.getLogger(__name__)


def verify_scope_signature(
    manifest_path: Path,
    signature_path: Path,
    keyring_path: Path,
) -> bool:
    """Verify GPG detached signature on the scope manifest."""
    if not manifest_path.exists():
        raise ScopeSignatureError(f"Scope manifest not found: {manifest_path}")
    if not signature_path.exists():
        raise ScopeSignatureError(f"Scope signature not found: {signature_path}")
    if not keyring_path.exists():
        raise ScopeSignatureError(f"Signer keyring not found: {keyring_path}")

    gpg_exe = shutil.which("gpg")
    if not gpg_exe:
        raise ScopeSignatureError("gpg not found in PATH")

    try:
        result = subprocess.run(
            [
                "--no-default-keyring",
                "--keyring",
                str(keyring_path),
                "--verify",
                str(signature_path),
                str(manifest_path),
            ],
            capture_output=True,
            text=True,
            shell=False,
            timeout=30,
            executable=gpg_exe,
        )
    except subprocess.TimeoutExpired as exc:
        raise ScopeSignatureError(
            "GPG verification timed out", context={"timeout_seconds": 30}
        ) from exc
    except FileNotFoundError as exc:
        raise ScopeSignatureError("gpg not found in PATH") from exc

    if result.returncode != 0:
        LOG.error("GPG verification failed: %s", result.stderr.strip())
        raise ScopeSignatureError(
            f"Scope manifest signature verification failed: {result.stderr.strip()}",
            context={"stderr": result.stderr.strip(), "stdout": result.stdout.strip()},
        )

    LOG.info("Scope manifest signature verified successfully")
    return True


def verify_scope_lab_mode(
    manifest_path: Path,
    lab_mode_enabled: bool = False,
) -> bool:
    """Lab-mode scope check: verifies file exists but skips signature."""
    if not lab_mode_enabled:
        raise ScopeSignatureError(
            "Lab mode not enabled. Cannot skip signature verification. "
            "Set lab_mode: true in config/orchestrator.yml for Phase 1 only."
        )

    if not manifest_path.exists():
        raise ScopeSignatureError(f"Scope manifest not found: {manifest_path}")

    LOG.warning(
        "SCOPE SIGNATURE VERIFICATION SKIPPED - Lab mode enabled. "
        "This is acceptable for Phase 1 only. Do not use in production."
    )
    return True
