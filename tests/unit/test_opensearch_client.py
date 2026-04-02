"""Unit tests for src/integrations/opensearch_client.py (mocked OpenSearch)."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import pytest

from src.integrations.opensearch_client import OpenSearchClient
from src.orchestrator.exceptions import OpenSearchError


@pytest.fixture
def mock_os() -> MagicMock:
    client = MagicMock()
    client.indices.exists.return_value = False
    client.indices.create.return_value = {"acknowledged": True}
    return client


def test_index_name_format() -> None:
    dt = datetime(2026, 3, 15, tzinfo=UTC)
    assert OpenSearchClient._index_name("findings", dt) == "pipeline-findings-2026.03"


def test_ensure_index_creates_when_missing(mock_os: MagicMock) -> None:
    with patch.object(OpenSearchClient, "__init__", lambda self, *a, **k: None):
        c = OpenSearchClient.__new__(OpenSearchClient)
        c.client = mock_os
        c._ensure_index("pipeline-findings-2026.03", {"settings": {}})
    mock_os.indices.exists.assert_called_once()
    mock_os.indices.create.assert_called_once()


def test_ensure_index_wraps_exception(mock_os: MagicMock) -> None:
    mock_os.indices.exists.side_effect = RuntimeError("boom")
    with patch.object(OpenSearchClient, "__init__", lambda self, *a, **k: None):
        c = OpenSearchClient.__new__(OpenSearchClient)
        c.client = mock_os
        with pytest.raises(OpenSearchError):
            c._ensure_index("idx", {})


def test_index_findings_empty_returns_zero(mock_os: MagicMock) -> None:
    with patch.object(OpenSearchClient, "__init__", lambda self, *a, **k: None):
        c = OpenSearchClient.__new__(OpenSearchClient)
        c.client = mock_os
        with patch.object(c, "_ensure_index"):
            assert c.index_findings([], "RUN-1") == 0


def test_index_findings_bulk_success(mock_os: MagicMock) -> None:
    with patch("src.integrations.opensearch_client.helpers.bulk") as bulk:
        bulk.return_value = (2, [])
        with patch.object(OpenSearchClient, "__init__", lambda self, *a, **k: None):
            c = OpenSearchClient.__new__(OpenSearchClient)
            c.client = mock_os
            with patch.object(c, "_ensure_index"):
                n = c.index_findings(
                    [{"fingerprint": "a" * 64, "tool": "x", "severity": "High"}],
                    "RUN-1",
                )
        assert n == 2
        bulk.assert_called_once()


def test_index_findings_bulk_raises_opensearch_error(mock_os: MagicMock) -> None:
    with patch("src.integrations.opensearch_client.helpers.bulk") as bulk:
        bulk.side_effect = RuntimeError("network")
        with patch.object(OpenSearchClient, "__init__", lambda self, *a, **k: None):
            c = OpenSearchClient.__new__(OpenSearchClient)
            c.client = mock_os
            with patch.object(c, "_ensure_index"):
                with pytest.raises(OpenSearchError):
                    c.index_findings([{"fingerprint": "b" * 64}], "RUN")


def test_index_run_metadata(mock_os: MagicMock) -> None:
    with patch.object(OpenSearchClient, "__init__", lambda self, *a, **k: None):
        c = OpenSearchClient.__new__(OpenSearchClient)
        c.client = mock_os
        with patch.object(c, "_ensure_index"):
            c.index_run_metadata("RUN-1", {"workflow": "lab"}, finding_count=3)
    mock_os.index.assert_called_once()


def test_index_run_metadata_raises(mock_os: MagicMock) -> None:
    mock_os.index.side_effect = ValueError("bad")
    with patch.object(OpenSearchClient, "__init__", lambda self, *a, **k: None):
        c = OpenSearchClient.__new__(OpenSearchClient)
        c.client = mock_os
        with patch.object(c, "_ensure_index"):
            with pytest.raises(OpenSearchError):
                c.index_run_metadata("RUN-1", {}, 0)


def test_get_severity_counts(mock_os: MagicMock) -> None:
    mock_os.search.return_value = {
        "aggregations": {"severity_counts": {"buckets": [{"key": "High", "doc_count": 5}]}}
    }
    with patch.object(OpenSearchClient, "__init__", lambda self, *a, **k: None):
        c = OpenSearchClient.__new__(OpenSearchClient)
        c.client = mock_os
        with patch.object(
            OpenSearchClient, "_index_name", return_value="pipeline-findings-2026.03"
        ):
            counts = c.get_severity_counts("RUN-1")
    assert counts == {"High": 5}


def test_get_severity_counts_on_error_returns_empty(mock_os: MagicMock) -> None:
    mock_os.search.side_effect = Exception("x")
    with patch.object(OpenSearchClient, "__init__", lambda self, *a, **k: None):
        c = OpenSearchClient.__new__(OpenSearchClient)
        c.client = mock_os
        assert c.get_severity_counts() == {}


def test_health_check_green(mock_os: MagicMock) -> None:
    mock_os.cluster.health.return_value = {"status": "green"}
    with patch.object(OpenSearchClient, "__init__", lambda self, *a, **k: None):
        c = OpenSearchClient.__new__(OpenSearchClient)
        c.client = mock_os
        assert c.health_check() is True


def test_health_check_failure_returns_false(mock_os: MagicMock) -> None:
    mock_os.cluster.health.side_effect = ConnectionError("nope")
    with patch.object(OpenSearchClient, "__init__", lambda self, *a, **k: None):
        c = OpenSearchClient.__new__(OpenSearchClient)
        c.client = mock_os
        assert c.health_check() is False
