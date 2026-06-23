"""RedisPermissionCache — production impl backed by Redis.

Connection: ``redis.asyncio.Redis`` (the standard asyncio client). Single
Redis instance per cluster (``PERMISSION_REDIS_URL`` shared by Helios and
every downstream service).

Key shape: ``helios:perms:{user_id}:{tenant_id}`` -> JSON array of perms.

TTL policy (no expiry by default):

  The cache is the primary read path for callerHasPermission. We aim
  for a 90-98% hit rate, which means entries must outlive the request
  burst. Every entry is invalidated explicitly at the mutation site —
  Helios calls write_through / invalidate after each role change,
  Hecate's event consumer drops the key on helios.* events, and the
  internal events handlers drop the tenant-level cache after each
  event. A TTL safety-net would only force needless re-population;
  remove it by default.

  Pass ``ttl_seconds=<positive int>`` to opt back into a TTL. Useful
  for staging environments with churn that blows up the keyspace.
  When set, every write below passes ``ex`` explicitly. When unset
  (the default), writes pass no ``ex`` and Redis keeps the key
  forever until explicit DEL.

  IMPORTANT: must match the Helios-side cache. If Helios writes with
  one TTL and the SDK reads with another, the SDK's EX wins on the
  next SDK-side ``set`` call and may drop entries before Helios has a
  chance to re-write them.

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
    or Helios service) needs to know cache may be stale. With no TTL,
    a failed invalidation is sticky until the next write_through for
    that user; that is the operator-visible signal.
"""

from __future__ import annotations

import json
from typing import Any

from redis.asyncio import Redis

from ..logger import Logger, silent_logger
from ..role_permissions import Permission

KEY_PREFIX = "helios:perms:"

#: Default TTL: none (PERMANENT). Entries are refreshed only by
#: explicit write_through / invalidate calls. Override per-instance
#: via the ``ttl_seconds`` constructor option.
#:
#: Historical note: v0.3.0 shipped with a 60s default TTL as a "safety
#: net" for missed invalidations. It was removed when the team moved
#: to a write-through model — the explicit invalidates on every
#: mutation make the TTL redundant, and a 90-98% cache-hit-rate
#: platform needs the entries to stick around.
DEFAULT_CACHE_TTL_SECONDS = 0

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
            # NX = only set if not exists. Prevents a slow in-flight read
            # from resurrecting a value that was invalidated after the
            # read started.
            #
            # TTL: only pass ex when ttl_seconds > 0. ttl_seconds === 0
            # (default) means "no expiry"; redis.asyncio omits ex and
            # Redis keeps the key until explicit DEL. We do NOT pass
            # KEEPTTL here — this is a fresh write, not a re-write.
            if self._ttl_seconds > 0:
                await self._redis.set(
                    self._key(user_id, tenant_id),
                    json.dumps(list(perms)),
                    ex=self._ttl_seconds,
                    nx=True,
                )
            else:
                await self._redis.set(
                    self._key(user_id, tenant_id),
                    json.dumps(list(perms)),
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
            #
            # TTL: same policy as set() — only pass ex when configured.
            # No KEEPTTL — this is an overwrite, not a refresh.
            if self._ttl_seconds > 0:
                await self._redis.set(
                    self._key(user_id, tenant_id),
                    json.dumps(list(perms)),
                    ex=self._ttl_seconds,
                )
            else:
                await self._redis.set(
                    self._key(user_id, tenant_id),
                    json.dumps(list(perms)),
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
                "RedisPermissionCache.invalidate failed — cache will stay "
                "stale until the next write_through for this user",
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
                "invalidate_tenant failed — affected entries will be "
                "re-written on the next role change for each user",
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
