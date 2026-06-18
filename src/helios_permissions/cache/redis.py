"""RedisPermissionCache — production impl backed by Redis.

Connection: ``redis.asyncio.Redis`` (the standard asyncio client). Single
Redis instance per cluster (``PERMISSION_REDIS_URL`` shared by Helios and
every downstream service).

Key shape: ``helios:perms:{user_id}:{tenant_id}`` -> JSON array of perms.

Invalidation patterns:

  - ``invalidate(user_id)``            -> SCAN MATCH helios:perms:{user_id}:* DEL
  - ``invalidate(user_id, tenant_id)``  -> DEL helios:perms:{user_id}:{tenant_id}
  - ``invalidate_tenant(tenant_id)``    -> SCAN MATCH helios:perms:*:{tenant_id} DEL

SCAN is non-blocking (KEYS would block the Redis event loop on a large
keyspace — never use KEYS in production).

Error handling:

  - GET failures: log warn + return ``None``. Caller falls through to Helios.
  - SET / write_through failures: log warn + swallow. Cache is best-effort.
  - Invalidate failures: log error + raise. The caller (event consumer
    or Helios service) needs to know cache may be stale. The TTL is
    the bound — 60s of staleness is the worst case.

Why the error asymmetry:

  - Reads / writes that fail are degraded-but-correct paths (Helios is
    the source of truth).
  - Invalidation failures leave stale data with no automatic recovery
    except TTL expiry. Operators need visibility.
"""

from __future__ import annotations

import json
from typing import Any

from redis.asyncio import Redis

from ..logger import Logger, silent_logger
from ..role_permissions import Permission

KEY_PREFIX = "helios:perms:"

#: Default TTL: 60 seconds. Bounds staleness when invalidation fails.
DEFAULT_CACHE_TTL_SECONDS = 60

#: SCAN batch size — balances round-trip count vs cursor overhead.
_SCAN_BATCH = 100


class RedisPermissionCache:
    """Redis-backed permission cache.

    Connection: ``redis.asyncio.Redis`` async client. Single Redis
    instance per cluster (PERMISSION_REDIS_URL shared by Helios and every
    downstream service).
    """

    def __init__(
        self,
        redis: Redis,
        ttl_seconds: int = DEFAULT_CACHE_TTL_SECONDS,
        logger: Logger | None = None,
    ) -> None:
        self._redis = redis
        self._ttl_seconds = ttl_seconds
        self._logger = logger if logger is not None else silent_logger

    @staticmethod
    def _key(user_id: str, tenant_id: str) -> str:
        return f"{KEY_PREFIX}{user_id}:{tenant_id}"

    @staticmethod
    def _user_pattern(user_id: str) -> str:
        return f"{KEY_PREFIX}{user_id}:*"

    @staticmethod
    def _tenant_pattern(tenant_id: str) -> str:
        return f"{KEY_PREFIX}*:{tenant_id}"

    async def get(self, user_id: str, tenant_id: str) -> list[Permission] | None:
        try:
            raw = await self._redis.get(self._key(user_id, tenant_id))
        except Exception as err:  # noqa: BLE001 — log+swallow per spec
            self._logger.warn(
                {"err": str(err), "user_id": user_id, "tenant_id": tenant_id},
                "RedisPermissionCache.get failed, returning null (caller falls through to Helios)",
            )
            return None
        if raw is None:
            return None
        try:
            parsed: Any = json.loads(raw)
        except json.JSONDecodeError as err:
            self._logger.warn(
                {"err": str(err), "user_id": user_id, "tenant_id": tenant_id, "raw": str(raw)},
                "RedisPermissionCache.get: cached value is not valid JSON, treating as miss",
            )
            return None
        if not isinstance(parsed, list):
            self._logger.warn(
                {"user_id": user_id, "tenant_id": tenant_id, "raw": str(raw)},
                "RedisPermissionCache.get: cached value is not an array, treating as miss",
            )
            return None
        return list(parsed)

    async def set(self, user_id: str, tenant_id: str, perms: list[Permission]) -> None:
        try:
            # NX = only set if not exists. Prevents a slow in-flight read from
            # resurrecting a value that was invalidated after the read started.
            # The TTL is the safety net for missed invalidations.
            await self._redis.set(
                self._key(user_id, tenant_id),
                json.dumps(list(perms)),
                ex=self._ttl_seconds,
                nx=True,
            )
        except Exception as err:  # noqa: BLE001
            self._logger.warn(
                {"err": str(err), "user_id": user_id, "tenant_id": tenant_id},
                "RedisPermissionCache.set failed, continuing without cache",
            )

    async def write_through(
        self, user_id: str, tenant_id: str, perms: list[Permission]
    ) -> None:
        try:
            # No NX — write-through explicitly overwrites. Helios calls this
            # after it knows the new value is correct (e.g. after a role
            # change in user_projects). We want the next read to see the new
            # value immediately, not race with a stale cache entry.
            await self._redis.set(
                self._key(user_id, tenant_id),
                json.dumps(list(perms)),
                ex=self._ttl_seconds,
            )
        except Exception as err:  # noqa: BLE001
            self._logger.warn(
                {"err": str(err), "user_id": user_id, "tenant_id": tenant_id},
                "RedisPermissionCache.write_through failed, continuing without cache",
            )

    async def invalidate(self, user_id: str, tenant_id: str | None = None) -> None:
        try:
            if tenant_id is None:
                deleted = await self._scan_and_delete(self._user_pattern(user_id))
                self._logger.info(
                    {"user_id": user_id, "deleted": deleted},
                    "RedisPermissionCache.invalidate: dropped all entries for user",
                )
            else:
                deleted = await self._redis.delete(self._key(user_id, tenant_id))
                self._logger.info(
                    {"user_id": user_id, "tenant_id": tenant_id, "deleted": deleted},
                    "RedisPermissionCache.invalidate: deleted (user_id, tenant_id) entry",
                )
        except Exception as err:  # noqa: BLE001
            self._logger.error(
                {"err": str(err), "user_id": user_id, "tenant_id": tenant_id},
                "RedisPermissionCache.invalidate failed — cache may be stale for up to TTL seconds",
            )
            raise

    async def invalidate_tenant(self, tenant_id: str) -> None:
        try:
            deleted = await self._scan_and_delete(self._tenant_pattern(tenant_id))
            self._logger.info(
                {"tenant_id": tenant_id, "deleted": deleted},
                "RedisPermissionCache.invalidate_tenant: deleted all entries for tenant",
            )
        except Exception as err:  # noqa: BLE001
            self._logger.error(
                {"err": str(err), "tenant_id": tenant_id},
                "invalidate_tenant failed: cache may be stale for up to TTL seconds",
            )
            raise

    async def _scan_and_delete(self, pattern: str) -> int:
        """SCAN-based batched DEL. Non-blocking — unlike KEYS.

        Cursor-based iteration with batched DEL per page. Returns the
        total count of keys deleted.
        """
        cursor = 0
        total_deleted = 0
        while True:
            cursor, keys = await self._redis.scan(
                cursor=cursor, match=pattern, count=_SCAN_BATCH
            )
            if keys:
                total_deleted += await self._redis.delete(*keys)
            if cursor == 0:
                break
        return total_deleted
