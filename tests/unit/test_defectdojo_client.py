from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import requests

from src.integrations.defectdojo_client import SCAN_TYPE_MAP, DefectDojoClient
from src.orchestrator.exceptions import DefectDojoError


def _make_response(payload: dict[str, Any], raise_exc: Exception | None = None) -> MagicMock:
    resp = MagicMock()
    resp.json.return_value = payload
    if raise_exc is None:
        resp.raise_for_status.return_value = None
    else:
        resp.raise_for_status.side_effect = raise_exc
    return resp


def _write_dummy_file(tmp_path: Path) -> Path:
    p = tmp_path / "artifact.bin"
    p.write_bytes(b"dummy")
    return p


def test_scan_type_map_keys_are_exactly_expected() -> None:
    assert set(SCAN_TYPE_MAP.keys()) == {
        "nmap",
        "greenbone",
        "zap",
        "nikto",
        "wazuh",
        "wazuh_sca",
        "prowler",
        "nuclei",
        "lynis",
        "generic",
    }


def test_url_strips_trailing_and_handles_leading_slash() -> None:
    client = DefectDojoClient(base_url="http://example.com/", api_token="tkn")
    assert client._url("/products/") == "http://example.com/api/v2/products/"
    assert client._url("engagements/") == "http://example.com/api/v2/engagements/"


def test_get_or_create_product_returns_existing_id_when_results_non_empty(tmp_path: Path) -> None:
    client = DefectDojoClient(base_url="http://example.com/", api_token="tkn")
    with (
        patch.object(client.session, "get") as mock_get,
        patch.object(client.session, "post") as mock_post,
    ):
        mock_get.return_value = _make_response({"results": [{"id": 123}]})

        pid = client.get_or_create_product("My Product")
        assert pid == 123
        assert mock_post.call_count == 0


def test_get_or_create_product_posts_and_returns_new_id_when_results_empty(tmp_path: Path) -> None:
    client = DefectDojoClient(base_url="http://example.com/", api_token="tkn")
    with (
        patch.object(client.session, "get") as mock_get,
        patch.object(client.session, "post") as mock_post,
    ):
        mock_get.return_value = _make_response({"results": []})
        mock_post.return_value = _make_response({"id": 456})

        pid = client.get_or_create_product("New Product")
        assert pid == 456
        assert mock_post.call_count == 1


def test_get_or_create_product_raises_defectdojoerror_on_http_error() -> None:
    client = DefectDojoClient(base_url="http://example.com/", api_token="tkn")
    with patch.object(client.session, "get") as mock_get:
        mock_get.return_value = _make_response({}, raise_exc=requests.RequestException("boom"))
        with pytest.raises(DefectDojoError):
            client.get_or_create_product("Any Product")


def test_get_or_create_engagement_finds_existing_and_returns_id() -> None:
    client = DefectDojoClient(base_url="http://example.com/", api_token="tkn")
    with (
        patch.object(client.session, "get") as mock_get,
        patch.object(client.session, "post") as mock_post,
    ):
        mock_get.return_value = _make_response({"results": [{"id": 99}]})

        eid = client.get_or_create_engagement(product_id=1, name="Engagement A")
        assert eid == 99
        assert mock_post.call_count == 0


def test_get_or_create_engagement_posts_and_returns_new_id_when_results_empty() -> None:
    client = DefectDojoClient(base_url="http://example.com/", api_token="tkn")
    with (
        patch.object(client.session, "get") as mock_get,
        patch.object(client.session, "post") as mock_post,
    ):
        mock_get.return_value = _make_response({"results": []})
        mock_post.return_value = _make_response({"id": 111})

        eid = client.get_or_create_engagement(product_id=1, name="Engagement B")
        assert eid == 111
        assert mock_post.call_count == 1


def test_find_test_returns_id_when_results_non_empty() -> None:
    client = DefectDojoClient(base_url="http://example.com/", api_token="tkn")
    with patch.object(client.session, "get") as mock_get:
        mock_get.return_value = _make_response({"results": [{"id": 77}]})
        assert client.find_test(engagement_id=1, title="t", scan_type="scan") == 77


def test_find_test_returns_none_when_results_empty() -> None:
    client = DefectDojoClient(base_url="http://example.com/", api_token="tkn")
    with patch.object(client.session, "get") as mock_get:
        mock_get.return_value = _make_response({"results": []})
        assert client.find_test(engagement_id=1, title="t", scan_type="scan") is None


def test_import_scan_calls_import_scan_endpoint_when_find_test_returns_none(tmp_path: Path) -> None:
    client = DefectDojoClient(base_url="http://example.com/", api_token="tkn")
    artifact = _write_dummy_file(tmp_path)
    with (
        patch.object(client.session, "get") as mock_get,
        patch.object(client.session, "post") as mock_post,
    ):
        # find_test => no results
        mock_get.return_value = _make_response({"results": []})

        # import-scan/ => returns test_import
        mock_post.return_value = _make_response(
            {"test_import": {"findings_affected": {"created": 1}}}
        )

        client.import_scan(
            engagement_id=1,
            scan_type="Nmap Scan",
            file_path=artifact,
            test_title="t",
            environment="Development",
        )

        called_url = mock_post.call_args[0][0]
        assert "/import-scan/" in called_url


def test_import_scan_calls_reimport_scan_endpoint_when_find_test_returns_existing_id(
    tmp_path: Path,
) -> None:
    client = DefectDojoClient(base_url="http://example.com/", api_token="tkn")
    artifact = _write_dummy_file(tmp_path)
    with (
        patch.object(client.session, "get") as mock_get,
        patch.object(client.session, "post") as mock_post,
    ):
        # find_test => existing id
        mock_get.return_value = _make_response({"results": [{"id": 5}]})
        mock_post.return_value = _make_response(
            {"test_import": {"findings_affected": {"created": 1}}}
        )

        client.import_scan(
            engagement_id=1,
            scan_type="Nmap Scan",
            file_path=artifact,
            test_title="t",
            environment="Development",
        )

        called_url = mock_post.call_args[0][0]
        assert "/reimport-scan/" in called_url


def test_import_tool_results_raises_defectdojoerror_for_unknown_tool_key(tmp_path: Path) -> None:
    client = DefectDojoClient(base_url="http://example.com/", api_token="tkn")
    artifact = _write_dummy_file(tmp_path)
    with (
        patch.object(client.session, "get") as _mock_get,
        patch.object(client.session, "post") as _mock_post,
    ):
        with pytest.raises(DefectDojoError):
            client.import_tool_results(
                product_name="p",
                engagement_name="e",
                tool="unknown_tool",
                file_path=artifact,
                environment="Development",
            )


def test_import_tool_results_completes_successfully_for_known_tool_zap(tmp_path: Path) -> None:
    client = DefectDojoClient(base_url="http://example.com/", api_token="tkn")
    artifact = _write_dummy_file(tmp_path)

    def _get_side_effect(
        url: str, params: dict[str, Any] | None = None, timeout: int | None = None
    ) -> MagicMock:
        # Route based on URL endpoint
        if url.endswith("/products/"):
            return _make_response({"results": [{"id": 1}]})
        if url.endswith("/engagements/"):
            return _make_response({"results": [{"id": 2}]})
        if url.endswith("/tests/"):
            return _make_response({"results": []})
        return _make_response({"results": []})

    with (
        patch.object(client.session, "get", side_effect=_get_side_effect) as _mock_get,
        patch.object(
            client.session,
            "post",
            return_value=_make_response({"test_import": {"findings_affected": {"created": 1}}}),
        ) as mock_post,
    ):
        client.import_tool_results(
            product_name="p",
            engagement_name="e",
            tool="zap",
            file_path=artifact,
            environment="Development",
        )

        # For zap we expect first import (find_test returns None => import-scan/)
        called_url = mock_post.call_args[0][0]
        assert "/import-scan/" in called_url
