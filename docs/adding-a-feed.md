# Adding a Custom Feed

This guide walks through adding a new IOC feed to the pipeline. We'll build a concrete example: a **CSV-based feed** that reads IOCs from a local file (useful for private intel lists).

## Step 1: Create the feed file

Create `tip/feeds/csv_feed.py`:

```python
from __future__ import annotations

import csv
import logging
from datetime import datetime
from pathlib import Path

from tip.core.config import Settings
from tip.core.models import IOC, IOCType, ThreatLevel
from tip.feeds.base import BaseFeed

logger = logging.getLogger(__name__)

# Map CSV type column values to IOCType
CSV_TYPE_MAP = {
    "ip": IOCType.IP,
    "domain": IOCType.DOMAIN,
    "url": IOCType.URL,
    "md5": IOCType.MD5,
    "sha256": IOCType.SHA256,
    "sha1": IOCType.SHA1,
}


class CSVFeed(BaseFeed):
    """
    Read IOCs from a local CSV file.

    Expected CSV format:
        value,type,threat_level,description,tags
        1.2.3.4,ip,high,C2 server,"apt28,c2"
        evil.com,domain,medium,Phishing domain,"phishing"
    """
    name = "csv"

    def __init__(self, settings: Settings) -> None:
        self.csv_path = getattr(settings, "csv_feed_path", "./feeds/iocs.csv")

    async def fetch(self) -> list[IOC]:
        path = Path(self.csv_path)
        if not path.exists():
            logger.warning("CSV feed file not found: %s", path)
            return []

        iocs: list[IOC] = []
        with open(path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                ioc = self._row_to_ioc(row)
                if ioc:
                    iocs.append(ioc)

        logger.info("CSV feed: loaded %d IOCs from %s", len(iocs), path)
        return iocs

    def _row_to_ioc(self, row: dict) -> IOC | None:
        value = row.get("value", "").strip()
        type_str = row.get("type", "").lower().strip()
        ioc_type = CSV_TYPE_MAP.get(type_str)

        if not value or ioc_type is None:
            return None

        tags_raw = row.get("tags", "")
        tags = [t.strip() for t in tags_raw.split(",") if t.strip()]

        try:
            threat_level = ThreatLevel(row.get("threat_level", "unknown").lower())
        except ValueError:
            threat_level = ThreatLevel.UNKNOWN

        now = datetime.utcnow()
        return IOC(
            value=value,
            ioc_type=ioc_type,
            source_feed="csv",
            threat_level=threat_level,
            tags=tags,
            description=row.get("description", ""),
            first_seen=now,
            last_seen=now,
            confidence=70,
            pulse_id=f"csv:{value}",
            raw=dict(row),
        )

    async def health_check(self) -> bool:
        return Path(self.csv_path).exists()
```

## Step 2: Add config (if your feed needs settings)

In `tip/core/config.py`, add to the `Settings` class:

```python
# CSV feed (custom example)
csv_feed_path: str = "./feeds/iocs.csv"
```

And add to `.env.example`:

```bash
TIP_CSV_FEED_PATH=./feeds/iocs.csv
```

## Step 3: Register in FeedScheduler

In `tip/feeds/feed_scheduler.py`, import and add your feed:

```python
from tip.feeds.csv_feed import CSVFeed

class FeedScheduler:
    def __init__(self, ...):
        ...
        self.csv = CSVFeed(settings)  # add this
    
    def start(self) -> None:
        ...
        self.scheduler.add_job(
            self._run_csv,
            "interval",
            minutes=30,  # or read from settings
            id="csv_feed",
            next_run_time=datetime.now(),
        )
    
    async def _run_csv(self) -> None:
        result = await self._run_feed(self.csv)
        console.log(f"CSV: {result.new_iocs} new, {result.errors} errors")
```

Also update `run_once()` to support the new feed:

```python
async def run_once(self, feed_name: str = "all") -> list[FeedIngestionResult]:
    results = []
    if feed_name in ("otx", "all"):
        results.append(await self._run_feed(self.otx))
    if feed_name in ("abusech", "all"):
        results.append(await self._run_feed(self.abusech))
    if feed_name in ("csv", "all"):          # add this
        results.append(await self._run_feed(self.csv))
    return results
```

And update the CLI choice:

```python
# In tip/cli.py, update the --feed option:
@click.option("--feed", type=click.Choice(["otx", "abusech", "csv", "all"]), ...)
```

## Step 4: Write tests

Create `tests/test_csv_feed.py`:

```python
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from tip.core.config import Settings
from tip.core.models import IOCType, ThreatLevel


def _settings(csv_path: str) -> Settings:
    s = Settings(misp_api_key="x", otx_api_key="x")
    object.__setattr__(s, "csv_feed_path", csv_path)
    return s


@pytest.mark.asyncio
async def test_csv_feed_loads_iocs():
    from tip.feeds.csv_feed import CSVFeed

    csv_content = "value,type,threat_level,description,tags\n1.2.3.4,ip,high,C2 server,apt28\nevil.com,domain,medium,Phishing,phishing\n"

    with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
        f.write(csv_content)
        path = f.name

    feed = CSVFeed(_settings(path))
    iocs = await feed.fetch()

    assert len(iocs) == 2
    ip_ioc = next(i for i in iocs if i.ioc_type == IOCType.IP)
    assert ip_ioc.value == "1.2.3.4"
    assert ip_ioc.threat_level == ThreatLevel.HIGH


@pytest.mark.asyncio
async def test_csv_feed_missing_file_returns_empty():
    from tip.feeds.csv_feed import CSVFeed

    feed = CSVFeed(_settings("/nonexistent/path/iocs.csv"))
    iocs = await feed.fetch()
    assert iocs == []


@pytest.mark.asyncio
async def test_csv_feed_health_check_false_for_missing():
    from tip.feeds.csv_feed import CSVFeed

    feed = CSVFeed(_settings("/does/not/exist.csv"))
    assert await feed.health_check() is False
```

## Step 5: Run the feed

```bash
tip feeds run --feed csv
```

---

## Feed implementation checklist

- [ ] `name` class attribute set (used in logs, MISP event titles, dedup cache)
- [ ] `fetch()` returns `list[IOC]` with all required fields populated
- [ ] `health_check()` returns `True`/`False` without raising
- [ ] `source_feed` set to a unique string for your feed
- [ ] `pulse_id` set to a unique ID per IOC (used for deduplication hint)
- [ ] Tests cover happy path, empty response, and error conditions

## Tips

- **Rate limiting:** Use `asyncio.sleep()` between API calls if the provider rate-limits you
- **Pagination:** Fetch all pages before returning; `BaseFeed` gives you `get_lookback_since()` helper
- **Authentication:** Store API keys as `Settings` fields with `TIP_` prefix
- **Errors:** Let exceptions bubble up from `fetch()` — `FeedScheduler._run_feed()` handles them
- **Dedup:** The dedup cache works on `(value, ioc_type)` pairs — you don't need to dedup in your feed
