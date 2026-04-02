"""Secrets vault client.

Phase 1 (lab): reads from local YAML files (simulated vault).
Phase 2+: integrates with HashiCorp Vault HTTP API.

Secret values are never logged or included in repr/str output.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path

import yaml

from src.orchestrator.exceptions import CredentialError, VaultError

LOG = logging.getLogger(__name__)


@dataclass
class Credential:
    """A retrieved credential. Redacts its value in all representations."""

    ref: str
    username: str
    _password: str

    @property
    def password(self) -> str:
        return self._password

    def __repr__(self) -> str:
        return f"Credential(ref={self.ref!r}, username={self.username!r}, password='***')"

    def __str__(self) -> str:
        return f"Credential({self.ref}, user={self.username})"


class LocalVaultClient:
    """Lab-mode vault: reads credentials from a local YAML file."""

    def __init__(self, credentials_file: Path):
        if not credentials_file.exists():
            raise VaultError(f"Credentials file not found: {credentials_file}")
        data = yaml.safe_load(credentials_file.read_text(encoding="utf-8")) or {}
        if not isinstance(data, dict):
            raise VaultError(f"Credentials file must be a YAML mapping: {credentials_file}")
        self._credentials = data.get("credentials", data)
        if not isinstance(self._credentials, dict):
            raise VaultError("credentials must be a mapping")
        LOG.warning(
            "Using local vault (lab mode). Do not use in production. "
            "Integrate HashiCorp Vault for Phase 2+."
        )

    def get_credential(self, ref: str) -> Credential:
        cred = self._credentials.get(ref)
        if not cred:
            raise CredentialError(f"Credential not found: {ref}")
        if not isinstance(cred, dict):
            raise CredentialError(f"Credential {ref} is not a mapping")
        username = str(cred.get("username", ""))
        password = str(cred.get("password", ""))
        if not password:
            raise CredentialError(f"Credential {ref} has no password")
        return Credential(ref=ref, username=username, _password=password)


class HashiCorpVaultClient:
    """HashiCorp Vault client for Phase 2+ deployments."""

    def __init__(
        self,
        vault_url: str | None = None,
        vault_token: str | None = None,
        mount_path: str = "secret",
    ):
        import requests

        self._url = (vault_url or os.environ.get("VAULT_ADDR", "http://localhost:8200")).rstrip("/")
        self._token = vault_token or os.environ.get("VAULT_TOKEN", "")
        self._mount = mount_path
        self._session = requests.Session()
        if self._token:
            self._session.headers["X-Vault-Token"] = self._token
        if not self._token:
            raise VaultError("No Vault token provided")

    def get_credential(self, ref: str) -> Credential:
        import requests

        path = ref.replace("vault:", "").strip()
        if not path:
            raise CredentialError("Empty Vault credential ref")
        url = f"{self._url}/v1/{self._mount}/data/{path}"
        try:
            resp = self._session.get(url, timeout=10)
            resp.raise_for_status()
            data = resp.json().get("data", {}).get("data", {})
            username = str(data.get("username", ""))
            password = str(data.get("password", ""))
            if not password:
                raise CredentialError(f"Credential at {ref} has no password")
            return Credential(ref=ref, username=username, _password=password)
        except requests.RequestException as exc:
            raise VaultError(f"Failed to retrieve credential {ref}: {exc}") from exc


def get_vault_client(
    mode: str = "local",
    credentials_file: Path = Path("scope/credentials_map.yml"),
    vault_url: str | None = None,
    vault_token: str | None = None,
) -> LocalVaultClient | HashiCorpVaultClient:
    """Factory for vault clients."""
    if mode == "local":
        return LocalVaultClient(credentials_file)
    if mode == "hashicorp":
        return HashiCorpVaultClient(vault_url=vault_url, vault_token=vault_token)
    raise VaultError(f"Unknown vault mode: {mode}")
