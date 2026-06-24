from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone

from tip.core.models import IOC


class BaseFeed(ABC):
    name: str = "base"

    @abstractmethod
    async def fetch(self) -> list[IOC]:
        """Fetch IOCs from the feed. Returns normalised IOC objects."""
        ...

    @abstractmethod
    async def health_check(self) -> bool:
        """Return True if the feed API is reachable."""
        ...

    def get_lookback_since(self, days: int) -> datetime:
        """Return datetime N days ago in UTC."""
        return datetime.now(timezone.utc) - timedelta(days=days)

    def get_lookback_since_naive(self, days: int) -> datetime:
        """Return naive UTC datetime N days ago."""
        return datetime.utcnow() - timedelta(days=days)
