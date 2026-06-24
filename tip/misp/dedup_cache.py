from __future__ import annotations

import asyncio
import logging
import sqlite3
from datetime import timedelta
from pathlib import Path

from tip.core.config import Settings
from tip.core.models import IOCType
from tip.core.timeutil import utcnow

logger = logging.getLogger(__name__)


class DedupCache:
    def __init__(self, settings: Settings) -> None:
        self.backend = settings.cache_backend
        self.ttl_days = settings.cache_ttl_days
        self._redis = None

        if self.backend == "sqlite":
            self._sqlite_path = settings.cache_sqlite_path
            self._init_sqlite(self._sqlite_path)
        else:
            self._init_redis(settings.redis_url)

    def _init_sqlite(self, path: str) -> None:
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._sqlite_path = path
        # Keep a persistent shared connection for :memory: (new conn = new empty DB)
        self._shared_conn: sqlite3.Connection | None = None
        if path == ":memory:":
            self._shared_conn = sqlite3.connect(":memory:", check_same_thread=False)
        conn = self._get_conn()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS ioc_cache (
                value     TEXT    NOT NULL,
                ioc_type  TEXT    NOT NULL,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires   TIMESTAMP NOT NULL,
                PRIMARY KEY (value, ioc_type)
            )
        """)
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_ioc_cache_lookup ON ioc_cache (value, ioc_type)"
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ioc_cache_expires ON ioc_cache (expires)")
        conn.commit()

    def _get_conn(self) -> sqlite3.Connection:
        if getattr(self, "_shared_conn", None) is not None:
            return self._shared_conn
        return sqlite3.connect(self._sqlite_path, check_same_thread=False)

    def _init_redis(self, url: str) -> None:
        try:
            import redis.asyncio as aioredis

            self._redis = aioredis.from_url(url, decode_responses=True)
        except ImportError as exc:
            raise RuntimeError(
                "Install redis-py for Redis cache backend: pip install redis"
            ) from exc

    def _cache_key(self, value: str, ioc_type: IOCType) -> str:
        return f"tip:ioc:{ioc_type.value}:{value}"

    async def exists(self, value: str, ioc_type: IOCType) -> bool:
        if self.backend == "sqlite":
            return await asyncio.to_thread(self._sqlite_exists, value, ioc_type)
        else:
            return await self._redis_exists(value, ioc_type)

    def _sqlite_exists(self, value: str, ioc_type: IOCType) -> bool:
        now = utcnow().isoformat()
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT 1 FROM ioc_cache WHERE value = ? AND ioc_type = ? AND expires > ?",
                (value, ioc_type.value, now),
            ).fetchone()
            return row is not None

    async def _redis_exists(self, value: str, ioc_type: IOCType) -> bool:
        key = self._cache_key(value, ioc_type)
        result = await self._redis.exists(key)
        return bool(result)

    async def add(self, value: str, ioc_type: IOCType) -> None:
        if self.backend == "sqlite":
            await asyncio.to_thread(self._sqlite_add, value, ioc_type)
        else:
            await self._redis_add(value, ioc_type)

    def _sqlite_add(self, value: str, ioc_type: IOCType) -> None:
        now = utcnow()
        expires = now + timedelta(days=self.ttl_days)
        with self._get_conn() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO ioc_cache (value, ioc_type, first_seen, expires)
                VALUES (?, ?, ?, ?)
                """,
                (value, ioc_type.value, now.isoformat(), expires.isoformat()),
            )

    async def _redis_add(self, value: str, ioc_type: IOCType) -> None:
        key = self._cache_key(value, ioc_type)
        ttl_seconds = self.ttl_days * 86400
        await self._redis.setex(key, ttl_seconds, "1")

    async def remove(self, value: str, ioc_type: IOCType) -> None:
        if self.backend == "sqlite":
            await asyncio.to_thread(self._sqlite_remove, value, ioc_type)
        else:
            await self._redis.delete(self._cache_key(value, ioc_type))

    def _sqlite_remove(self, value: str, ioc_type: IOCType) -> None:
        with self._get_conn() as conn:
            conn.execute(
                "DELETE FROM ioc_cache WHERE value = ? AND ioc_type = ?",
                (value, ioc_type.value),
            )

    async def stats(self) -> dict:
        if self.backend == "sqlite":
            return await asyncio.to_thread(self._sqlite_stats)
        else:
            return await self._redis_stats()

    def _sqlite_stats(self) -> dict:
        now = utcnow().isoformat()
        with self._get_conn() as conn:
            total = conn.execute(
                "SELECT COUNT(*) FROM ioc_cache WHERE expires > ?", (now,)
            ).fetchone()[0]
            by_type = conn.execute(
                "SELECT ioc_type, COUNT(*) FROM ioc_cache WHERE expires > ? GROUP BY ioc_type",
                (now,),
            ).fetchall()
        return {
            "total_entries": total,
            "backend": "sqlite",
            "ttl_days": self.ttl_days,
            "by_type": {row[0]: row[1] for row in by_type},
        }

    async def _redis_stats(self) -> dict:
        keys = await self._redis.keys("tip:ioc:*")
        return {"total_entries": len(keys), "backend": "redis", "ttl_days": self.ttl_days}

    async def purge_expired(self) -> int:
        if self.backend == "sqlite":
            return await asyncio.to_thread(self._sqlite_purge)
        else:
            return 0  # Redis handles TTL automatically

    def _sqlite_purge(self) -> int:
        now = utcnow().isoformat()
        with self._get_conn() as conn:
            cursor = conn.execute("DELETE FROM ioc_cache WHERE expires <= ?", (now,))
            return cursor.rowcount
