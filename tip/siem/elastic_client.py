from __future__ import annotations

import logging
from datetime import datetime

import httpx

from tip.core.config import Settings

logger = logging.getLogger(__name__)


class ElasticClient:
    def __init__(self, settings: Settings) -> None:
        self.base_url = settings.elastic_url.rstrip("/")
        self.kibana_url = settings.elastic_kibana_url.rstrip("/")
        self.alerts_index = settings.elastic_alerts_index
        self.auth = (settings.elastic_username, settings.elastic_password)

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            auth=self.auth,
            headers={"Content-Type": "application/json", "kbn-xsrf": "true"},
            timeout=30,
        )

    def is_configured(self) -> bool:
        return bool(self.base_url and self.auth[0])

    async def get_alerts(self, since: datetime, size: int = 50) -> list[dict]:
        if not self.is_configured():
            return []
        since_str = since.strftime("%Y-%m-%dT%H:%M:%SZ")
        query = {
            "size": size,
            "sort": [{"@timestamp": {"order": "desc"}}],
            "query": {
                "range": {"@timestamp": {"gte": since_str}}
            },
        }
        try:
            async with self._client() as client:
                resp = await client.post(
                    f"{self.base_url}/{self.alerts_index}/_search",
                    json=query,
                )
                resp.raise_for_status()
                hits = resp.json().get("hits", {}).get("hits", [])
                return hits
        except Exception as exc:
            logger.error("Elastic get_alerts failed: %s", exc)
            return []

    async def update_alert(self, alert_id: str, update_body: dict) -> bool:
        try:
            async with self._client() as client:
                resp = await client.post(
                    f"{self.base_url}/{self.alerts_index}/_update/{alert_id}",
                    json=update_body,
                )
                return resp.status_code in (200, 201)
        except Exception as exc:
            logger.error("Elastic update_alert failed: %s", exc)
            return False

    async def search_ioc(self, value: str) -> list[dict]:
        """Search for an IOC value across common Elastic fields."""
        query = {
            "size": 10,
            "query": {
                "multi_match": {
                    "query": value,
                    "fields": [
                        "source.ip", "destination.ip", "dns.question.name",
                        "url.domain", "url.full", "process.hash.sha256",
                        "file.hash.sha256", "file.hash.md5",
                    ]
                }
            }
        }
        try:
            async with self._client() as client:
                resp = await client.post(
                    f"{self.base_url}/_search",
                    json=query,
                )
                resp.raise_for_status()
                return resp.json().get("hits", {}).get("hits", [])
        except Exception as exc:
            logger.error("Elastic search_ioc failed: %s", exc)
            return []

    async def health_check(self) -> bool:
        try:
            async with self._client() as client:
                resp = await client.get(self.base_url)
                return resp.status_code == 200
        except Exception:
            return False
