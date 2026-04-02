"""Unit tests for src/integrations/vault_client.py."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml

from src.integrations.vault_client import (
    Credential,
    HashiCorpVaultClient,
    LocalVaultClient,
    get_vault_client,
)
from src.orchestrator.exceptions import CredentialError, VaultError


def test_credential_repr_and_str_redacts_password() -> None:
    c = Credential(ref="r1", username="u", _password="secret")
    assert "secret" not in repr(c)
    assert "***" in repr(c)
    assert "secret" not in str(c)
    assert c.password == "secret"


def test_local_vault_missing_file_raises() -> None:
    with pytest.raises(VaultError, match="not found"):
        LocalVaultClient(Path("/nonexistent/vault.yml"))


def test_local_vault_invalid_root_raises(tmp_path: Path) -> None:
    p = tmp_path / "c.yml"
    p.write_text("- not a mapping\n", encoding="utf-8")
    with pytest.raises(VaultError, match="mapping"):
        LocalVaultClient(p)


def test_local_vault_credentials_key_not_mapping_raises(tmp_path: Path) -> None:
    p = tmp_path / "c.yml"
    p.write_text(yaml.safe_dump({"credentials": "bad"}), encoding="utf-8")
    with pytest.raises(VaultError, match="mapping"):
        LocalVaultClient(p)


def test_local_vault_get_credential_success(tmp_path: Path) -> None:
    p = tmp_path / "c.yml"
    p.write_text(
        yaml.safe_dump(
            {
                "credentials": {
                    "db1": {"username": "u1", "password": "p1"},
                }
            }
        ),
        encoding="utf-8",
    )
    client = LocalVaultClient(p)
    cred = client.get_credential("db1")
    assert cred.username == "u1"
    assert cred.password == "p1"


def test_local_vault_missing_ref_raises(tmp_path: Path) -> None:
    p = tmp_path / "c.yml"
    p.write_text(yaml.safe_dump({"credentials": {}}), encoding="utf-8")
    client = LocalVaultClient(p)
    with pytest.raises(CredentialError, match="not found"):
        client.get_credential("nope")


def test_local_vault_non_password_raises(tmp_path: Path) -> None:
    p = tmp_path / "c.yml"
    p.write_text(
        yaml.safe_dump({"credentials": {"x": {"username": "u", "password": ""}}}),
        encoding="utf-8",
    )
    client = LocalVaultClient(p)
    with pytest.raises(CredentialError, match="no password"):
        client.get_credential("x")


def test_hashicorp_vault_no_token_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("VAULT_TOKEN", raising=False)
    with pytest.raises(VaultError, match="token"):
        HashiCorpVaultClient(vault_token="")


def test_hashicorp_vault_get_credential_success() -> None:
    session = MagicMock()
    resp = MagicMock()
    resp.json.return_value = {"data": {"data": {"username": "u", "password": "p"}}}
    resp.raise_for_status = MagicMock()
    session.get.return_value = resp

    client = HashiCorpVaultClient(vault_url="http://vault:8200", vault_token="tok")
    client._session = session

    cred = client.get_credential("vault:my/path")
    assert cred.username == "u"
    assert cred.password == "p"
    session.get.assert_called_once()


def test_hashicorp_empty_ref_raises() -> None:
    client = HashiCorpVaultClient(vault_token="tok")
    with pytest.raises(CredentialError, match="Empty"):
        client.get_credential("vault:")


def test_get_vault_client_factory(tmp_path: Path) -> None:
    p = tmp_path / "c.yml"
    p.write_text(
        yaml.safe_dump({"credentials": {"a": {"username": "u", "password": "p"}}}), encoding="utf-8"
    )
    local = get_vault_client("local", credentials_file=p)
    assert isinstance(local, LocalVaultClient)

    with patch("src.integrations.vault_client.HashiCorpVaultClient") as mock_h:
        mock_h.return_value = MagicMock()
        get_vault_client("hashicorp", vault_token="tok")
        mock_h.assert_called_once()

    with pytest.raises(VaultError, match="Unknown"):
        get_vault_client("other")
