"""
External enrichment providers (VirusTotal, Shodan, ...).

An ``ExternalEnricher`` takes an IOC value + type and returns reputation/recon
context from a third-party service. They are optional: if no API key is
configured the enricher is simply skipped.

``ExternalEnrichmentManager`` fans an IOC out to every configured enricher that
supports its type and collects the results.
"""

from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod

from tip.core.models import IOC, ExternalEnrichmentResult, IOCType

logger = logging.getLogger(__name__)


class ExternalEnricher(ABC):
    name: str = "external"

    #: IOC types this enricher can look up.
    supported_types: frozenset[IOCType] = frozenset()

    @abstractmethod
    async def enrich(self, value: str, ioc_type: IOCType) -> ExternalEnrichmentResult | None:
        """Return enrichment context for an IOC, or None on error/no-data."""
        ...

    @abstractmethod
    async def health_check(self) -> bool:
        """Return True if the provider is reachable and the API key works."""
        ...

    def supports(self, ioc_type: IOCType) -> bool:
        return ioc_type in self.supported_types

    @property
    @abstractmethod
    def configured(self) -> bool:
        """True if an API key is present."""
        ...


class ExternalEnrichmentManager:
    """Runs an IOC through every applicable, configured enricher."""

    def __init__(self, enrichers: list[ExternalEnricher] | None = None) -> None:
        self.enrichers = [e for e in (enrichers or []) if e.configured]

    @property
    def active(self) -> bool:
        return len(self.enrichers) > 0

    async def enrich_value(self, value: str, ioc_type: IOCType) -> list[ExternalEnrichmentResult]:
        tasks = [e.enrich(value, ioc_type) for e in self.enrichers if e.supports(ioc_type)]
        if not tasks:
            return []
        results = await asyncio.gather(*tasks, return_exceptions=True)
        out: list[ExternalEnrichmentResult] = []
        for res in results:
            if isinstance(res, Exception):
                logger.warning("External enrichment error: %s", res)
            elif res is not None:
                out.append(res)
        return out

    async def enrich_iocs(self, iocs: list[IOC]) -> list[ExternalEnrichmentResult]:
        """Enrich a batch of IOCs, deduplicating by value."""
        seen: set[str] = set()
        out: list[ExternalEnrichmentResult] = []
        for ioc in iocs:
            if ioc.value in seen:
                continue
            seen.add(ioc.value)
            out.extend(await self.enrich_value(ioc.value, ioc.ioc_type))
        return out

    async def close(self) -> None:
        for e in self.enrichers:
            close = getattr(e, "close", None)
            if close:
                await close()
