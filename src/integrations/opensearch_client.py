"""OpenSearch client for telemetry, findings indexing, and dashboards.

Index naming: pipeline-{type}-YYYY.MM (monthly rotation)
Types: findings, runs, metrics
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from opensearchpy import OpenSearch, helpers

from src.orchestrator.exceptions import OpenSearchError

LOG = logging.getLogger(__name__)

FINDING_INDEX_SETTINGS: dict[str, Any] = {
    "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0,
        "index.mapping.total_fields.limit": 500,
    },
    "mappings": {
        "properties": {
            "run_id": {"type": "keyword"},
            "tool": {"type": "keyword"},
            "asset_id": {"type": "keyword"},
            "severity": {"type": "keyword"},
            "composite_severity": {"type": "keyword"},
            "composite_score": {"type": "float"},
            "environment": {"type": "keyword"},
            "title": {
                "type": "text",
                "fields": {"keyword": {"type": "keyword", "ignore_above": 256}},
            },
            "fingerprint": {"type": "keyword"},
            "timestamp": {"type": "date"},
            "endpoint": {"type": "keyword"},
            "vuln_id": {"type": "keyword"},
            "cve": {"type": "keyword"},
            "cvss": {"type": "float"},
            "tags": {"type": "keyword"},
        }
    },
}

RUN_INDEX_SETTINGS: dict[str, Any] = {
    "settings": {"number_of_shards": 1, "number_of_replicas": 0},
    "mappings": {
        "properties": {
            "run_id": {"type": "keyword"},
            "scope_hash": {"type": "keyword"},
            "workflow": {"type": "keyword"},
            "environment": {"type": "keyword"},
            "executor": {"type": "keyword"},
            "status": {"type": "keyword"},
            "start_time": {"type": "date"},
            "end_time": {"type": "date"},
            "timestamp": {"type": "date"},
            "finding_count": {"type": "integer"},
            "phases_completed": {"type": "keyword"},
        }
    },
}


class OpenSearchClient:
    """Pipeline OpenSearch client for indexing and querying."""

    def __init__(
        self,
        host: str = "localhost",
        port: int = 9200,
        use_ssl: bool = False,
        verify_certs: bool = False,
        http_auth: tuple[str, str] | None = None,
    ):
        self.client = OpenSearch(
            hosts=[{"host": host, "port": port}],
            use_ssl=use_ssl,
            verify_certs=verify_certs,
            http_auth=http_auth,
        )

    @staticmethod
    def _index_name(prefix: str, dt: datetime | None = None) -> str:
        dt = dt or datetime.now(UTC)
        return f"pipeline-{prefix}-{dt.strftime('%Y.%m')}"

    def _ensure_index(self, index_name: str, settings: dict[str, Any]) -> None:
        try:
            if not self.client.indices.exists(index=index_name):
                self.client.indices.create(index=index_name, body=settings)
                LOG.info("Created index: %s", index_name)
        except Exception as exc:
            raise OpenSearchError(f"Failed to create index {index_name}: {exc}") from exc

    def index_findings(self, findings: list[dict[str, Any]], run_id: str) -> int:
        index_name = self._index_name("findings")
        self._ensure_index(index_name, FINDING_INDEX_SETTINGS)

        now = datetime.now(UTC).isoformat()
        actions: list[dict[str, Any]] = []
        for finding in findings:
            doc = {**finding, "timestamp": now}
            doc_id = f"{run_id}-{finding.get('fingerprint', '')}"
            actions.append({"_index": index_name, "_id": doc_id, "_source": doc})

        if not actions:
            return 0

        try:
            success, errors = helpers.bulk(self.client, actions, raise_on_error=False)
            if errors:
                LOG.warning("Bulk index had %d errors", len(errors))
            LOG.info("Indexed %d findings to %s", success, index_name)
            return int(success)
        except Exception as exc:
            raise OpenSearchError(f"Bulk index failed: {exc}") from exc

    def index_run_metadata(
        self, run_id: str, metadata: dict[str, Any], finding_count: int = 0
    ) -> None:
        index_name = self._index_name("runs")
        self._ensure_index(index_name, RUN_INDEX_SETTINGS)

        doc = {
            **metadata,
            "timestamp": datetime.now(UTC).isoformat(),
            "finding_count": finding_count,
        }
        try:
            self.client.index(index=index_name, id=run_id, body=doc)
            LOG.info("Indexed run metadata for %s", run_id)
        except Exception as exc:
            raise OpenSearchError(f"Failed to index run metadata: {exc}") from exc

    def get_severity_counts(self, run_id: str | None = None) -> dict[str, int]:
        index_pattern = self._index_name("findings") + "*"
        query: dict[str, Any] = {
            "size": 0,
            "aggs": {"severity_counts": {"terms": {"field": "severity", "size": 10}}},
        }
        if run_id:
            query["query"] = {"term": {"run_id": run_id}}

        try:
            result = self.client.search(index=index_pattern, body=query)
            buckets = result.get("aggregations", {}).get("severity_counts", {}).get("buckets", [])
            return {str(b["key"]): int(b["doc_count"]) for b in buckets}
        except Exception as exc:
            LOG.warning("Severity count query failed: %s", exc)
            return {}

    def health_check(self) -> bool:
        try:
            info = self.client.cluster.health()
            status = str(info.get("status", "unknown"))
            LOG.info("OpenSearch cluster health: %s", status)
            return status in ("green", "yellow")
        except Exception as exc:
            LOG.error("OpenSearch health check failed: %s", exc)
            return False
