from __future__ import annotations

import logging
from datetime import datetime

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from rich.console import Console

from tip.core.config import Settings
from tip.core.models import FeedIngestionResult
from tip.core.timeutil import utcnow
from tip.feeds.abusech_feed import AbuseCHFeed
from tip.feeds.base import BaseFeed
from tip.feeds.otx_feed import OTXFeed
from tip.misp.client import MISPClient
from tip.misp.dedup_cache import DedupCache
from tip.misp.normaliser import IOCNormaliser

logger = logging.getLogger(__name__)
console = Console()


class FeedScheduler:
    def __init__(
        self,
        settings: Settings,
        misp_client: MISPClient,
        dedup_cache: DedupCache,
    ) -> None:
        self.scheduler = AsyncIOScheduler(timezone="UTC")
        self.otx = OTXFeed(settings)
        self.abusech = AbuseCHFeed(settings)
        self.misp = misp_client
        self.cache = dedup_cache
        self.normaliser = IOCNormaliser()
        self.settings = settings

        # Runtime stats
        self._last_results: dict[str, FeedIngestionResult] = {}

    def start(self) -> None:
        self.scheduler.add_job(
            self._run_otx,
            "interval",
            minutes=self.settings.otx_schedule_minutes,
            id="otx_feed",
            next_run_time=datetime.now(),
        )
        self.scheduler.add_job(
            self._run_abusech,
            "interval",
            minutes=self.settings.abusech_schedule_minutes,
            id="abusech_feed",
            next_run_time=datetime.now(),
        )
        self.scheduler.start()
        console.print(
            "[green]Scheduler started.[/green] OTX every "
            f"{self.settings.otx_schedule_minutes}m, "
            f"Abuse.ch every {self.settings.abusech_schedule_minutes}m."
        )

    async def run_once(self, feed_name: str = "all") -> list[FeedIngestionResult]:
        """Run feeds once without starting the scheduler."""
        results = []
        if feed_name in ("otx", "all"):
            results.append(await self._run_feed(self.otx))
        if feed_name in ("abusech", "all"):
            results.append(await self._run_feed(self.abusech))
        return results

    async def _run_feed(self, feed: BaseFeed) -> FeedIngestionResult:
        started = utcnow()
        new, dupes, stored, errors = 0, 0, 0, 0
        error_msgs: list[str] = []

        try:
            raw_iocs = await feed.fetch()
        except Exception as exc:
            logger.error("Feed %s fetch raised: %s", feed.name, exc)
            return FeedIngestionResult(
                feed_name=feed.name,
                started_at=started,
                finished_at=utcnow(),
                errors=1,
                error_details=[str(exc)],
            )

        # Normalise — removes private IPs, bad hashes, etc.
        iocs = self.normaliser.normalise_batch(raw_iocs)
        total = len(iocs)

        for ioc in iocs:
            try:
                if await self.cache.exists(ioc.value, ioc.ioc_type):
                    dupes += 1
                    continue
                new += 1
                await self.misp.store_ioc(ioc)
                await self.cache.add(ioc.value, ioc.ioc_type)
                stored += 1
            except Exception as exc:
                errors += 1
                error_msgs.append(f"{ioc.value}: {exc}")
                if len(error_msgs) > 20:  # cap error log
                    error_msgs.append("... more errors truncated")
                    break

        result = FeedIngestionResult(
            feed_name=feed.name,
            started_at=started,
            finished_at=utcnow(),
            total_fetched=total,
            new_iocs=new,
            duplicate_iocs=dupes,
            stored_in_misp=stored,
            errors=errors,
            error_details=error_msgs,
        )
        self._last_results[feed.name] = result
        return result

    async def _run_otx(self) -> None:
        result = await self._run_feed(self.otx)
        console.log(
            f"[cyan]OTX[/cyan] {result.new_iocs} new, "
            f"{result.duplicate_iocs} dupes, "
            f"{result.errors} errors "
            f"({result.duration_seconds():.1f}s)"
        )

    async def _run_abusech(self) -> None:
        result = await self._run_feed(self.abusech)
        console.log(
            f"[cyan]Abuse.ch[/cyan] {result.new_iocs} new, "
            f"{result.duplicate_iocs} dupes, "
            f"{result.errors} errors "
            f"({result.duration_seconds():.1f}s)"
        )

    def get_last_results(self) -> dict[str, FeedIngestionResult]:
        return dict(self._last_results)

    def stop(self) -> None:
        if self.scheduler.running:
            self.scheduler.shutdown()
