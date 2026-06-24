from __future__ import annotations

import logging
import subprocess
from datetime import datetime

import httpx

from tip.core.config import Settings

logger = logging.getLogger(__name__)


class SentinelClient:
    def __init__(self, settings: Settings) -> None:
        self.subscription_id = settings.sentinel_subscription_id
        self.resource_group = settings.sentinel_resource_group
        self.workspace_name = settings.sentinel_workspace_name
        self._static_token = settings.sentinel_token
        self.api_version = "2023-02-01"
        self._token: str | None = None

        self.base_url = (
            f"https://management.azure.com/subscriptions/{self.subscription_id}"
            f"/resourceGroups/{self.resource_group}"
            f"/providers/Microsoft.OperationalInsights/workspaces/{self.workspace_name}"
            f"/providers/Microsoft.SecurityInsights"
        )

    def is_configured(self) -> bool:
        return bool(self.subscription_id and self.resource_group and self.workspace_name)

    async def get_token(self) -> str:
        if self._static_token:
            return self._static_token
        if self._token:
            return self._token
        try:
            result = subprocess.run(
                ["az", "account", "get-access-token", "--resource", "https://management.azure.com/"],
                capture_output=True, text=True, timeout=15,
            )
            import json
            data = json.loads(result.stdout)
            self._token = data.get("accessToken", "")
            return self._token
        except Exception as exc:
            logger.error("Failed to get Sentinel token: %s", exc)
            return ""

    def _client(self, token: str) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            timeout=30,
        )

    async def get_incidents(self, since: datetime, top: int = 50) -> list[dict]:
        if not self.is_configured():
            return []
        token = await self.get_token()
        since_str = since.strftime("%Y-%m-%dT%H:%M:%SZ")
        params = {
            "$filter": f"properties/createdTimeUtc ge {since_str}",
            "$top": top,
            "api-version": self.api_version,
        }
        try:
            async with self._client(token) as client:
                resp = await client.get(f"{self.base_url}/incidents", params=params)
                resp.raise_for_status()
                return resp.json().get("value", [])
        except Exception as exc:
            logger.error("Sentinel get_incidents failed: %s", exc)
            return []

    async def get_incident(self, incident_id: str) -> dict:
        token = await self.get_token()
        try:
            async with self._client(token) as client:
                resp = await client.get(
                    f"{self.base_url}/incidents/{incident_id}",
                    params={"api-version": self.api_version},
                )
                resp.raise_for_status()
                return resp.json()
        except Exception as exc:
            logger.error("Sentinel get_incident failed: %s", exc)
            return {}

    async def get_incident_entities(self, incident_id: str) -> list[dict]:
        token = await self.get_token()
        try:
            async with self._client(token) as client:
                resp = await client.post(
                    f"{self.base_url}/incidents/{incident_id}/entities",
                    params={"api-version": self.api_version},
                    json={},
                )
                resp.raise_for_status()
                return resp.json().get("entities", [])
        except Exception as exc:
            logger.error("Sentinel get_incident_entities failed: %s", exc)
            return []

    async def update_incident_labels(self, incident_id: str, labels: list[str]) -> bool:
        token = await self.get_token()
        body = {
            "properties": {
                "labels": [{"labelName": label} for label in labels]
            }
        }
        try:
            async with self._client(token) as client:
                resp = await client.patch(
                    f"{self.base_url}/incidents/{incident_id}",
                    params={"api-version": self.api_version},
                    json=body,
                )
                return resp.status_code in (200, 204)
        except Exception as exc:
            logger.error("Sentinel update_incident_labels failed: %s", exc)
            return False

    async def health_check(self) -> bool:
        if not self.is_configured():
            return False
        try:
            token = await self.get_token()
            if not token:
                return False
            async with self._client(token) as client:
                resp = await client.get(
                    f"{self.base_url}/incidents",
                    params={"$top": 1, "api-version": self.api_version},
                )
                return resp.status_code == 200
        except Exception:
            return False
