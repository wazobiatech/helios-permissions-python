"""Redis cache tests using fakeredis.

Uses fakeredis so tests don't need a real Redis. The mock implements
the redis.asyncio surface we use (GET, SET with EX+NX, DEL, SCAN).
"""

import pytest
from fakeredis import aioredis as fakeredis_aio
from helios_permissions import RedisPermissionCache
from helios_permissions.logger import silent_logger


@pytest.fixture
async def redis():
    client = fakeredis_aio.FakeRedis()
    try:
        yield client
    finally:
        await client.flushall()
        await client.aclose()


@pytest.fixture
def cache(redis) -> RedisPermissionCache:
    return RedisPermissionCache(redis=redis, ttl_seconds=60, logger=silent_logger)


async def test_returns_none_on_miss(cache: RedisPermissionCache) -> None:
    assert await cache.get("user-1", "tenant-1") is None


async def test_returns_the_cached_value_on_hit(cache: RedisPermissionCache) -> None:
    await cache.set("user-1", "tenant-1", ["helios:members:view"])
    assert await cache.get("user-1", "tenant-1") == ["helios:members:view"]


async def test_uses_set_with_nx_does_not_overwrite_existing(
    cache: RedisPermissionCache,
) -> None:
    await cache.set("user-1", "tenant-1", ["helios:members:view"])
    await cache.set("user-1", "tenant-1", ["helios:members:invite"])
    assert await cache.get("user-1", "tenant-1") == ["helios:members:view"]


async def test_write_through_overwrites_unconditionally(
    cache: RedisPermissionCache,
) -> None:
    await cache.set("user-1", "tenant-1", ["helios:members:view"])
    await cache.write_through("user-1", "tenant-1", ["helios:members:invite"])
    assert await cache.get("user-1", "tenant-1") == ["helios:members:invite"]


async def test_invalidate_user_tenant_deletes_just_that_entry(
    cache: RedisPermissionCache,
) -> None:
    await cache.set("user-1", "tenant-1", ["helios:members:view"])
    await cache.set("user-1", "tenant-2", ["helios:members:invite"])
    await cache.invalidate("user-1", "tenant-1")
    assert await cache.get("user-1", "tenant-1") is None
    assert await cache.get("user-1", "tenant-2") == ["helios:members:invite"]


async def test_invalidate_user_drops_every_entry_for_user_scan_del(
    cache: RedisPermissionCache,
) -> None:
    await cache.set("user-1", "tenant-1", ["helios:members:view"])
    await cache.set("user-1", "tenant-2", ["helios:members:invite"])
    await cache.set("user-2", "tenant-1", ["helios:roles:assign"])
    await cache.invalidate("user-1")
    assert await cache.get("user-1", "tenant-1") is None
    assert await cache.get("user-1", "tenant-2") is None
    assert await cache.get("user-2", "tenant-1") == ["helios:roles:assign"]


async def test_invalidate_tenant_drops_every_entry_for_tenant(
    cache: RedisPermissionCache,
) -> None:
    await cache.set("user-1", "tenant-1", ["helios:members:view"])
    await cache.set("user-2", "tenant-1", ["helios:members:invite"])
    await cache.set("user-1", "tenant-2", ["helios:roles:assign"])
    await cache.invalidate_tenant("tenant-1")
    assert await cache.get("user-1", "tenant-1") is None
    assert await cache.get("user-2", "tenant-1") is None
    assert await cache.get("user-1", "tenant-2") == ["helios:roles:assign"]


async def test_serializes_perms_as_json_cross_language_compat(
    cache: RedisPermissionCache, redis
) -> None:
    import json

    perms = [
        "helios:members:view",
        "helios:tenant:transfer",
        "muse:posts:write",
    ]
    await cache.set("user-1", "tenant-1", perms)
    raw = await redis.get("helios:perms:user-1:tenant-1")
    assert raw is not None
    assert json.loads(raw) == perms


async def test_ttl_is_set_on_writes_bounded_staleness(
    cache: RedisPermissionCache, redis
) -> None:
    # The fixture's cache is built with ttl_seconds=60, so writes
    # SHOULD carry an EX. Pin that here — the no-expiry default is
    # exercised in TestNoTTL below with a separate, default-TTL
    # cache instance.
    await cache.set("user-1", "tenant-1", ["helios:members:view"])
    ttl = await redis.ttl("helios:perms:user-1:tenant-1")
    assert ttl is not None and ttl > 0
    assert ttl <= 60


class TestNoTTL:
    """v0.5.0 default: no expiry. Entries live until explicit DEL.

    The cache is the primary read path for callerHasPermission and we
    target a 90-98% hit rate — entries must outlive the request burst.
    Every entry is invalidated explicitly at the mutation site.
    """

    @pytest.fixture
    def no_ttl_cache(self, redis) -> RedisPermissionCache:
        return RedisPermissionCache(
            redis=redis, ttl_seconds=0, logger=silent_logger
        )

    async def test_default_constructor_has_no_ttl(
        self, no_ttl_cache: RedisPermissionCache, redis
    ) -> None:
        await no_ttl_cache.set("user-1", "tenant-1", ["helios:members:view"])
        # Redis returns -1 when a key exists with no expiry set.
        ttl = await redis.ttl("helios:perms:user-1:tenant-1")
        assert ttl == -1

    async def test_write_through_default_also_has_no_ttl(
        self, no_ttl_cache: RedisPermissionCache, redis
    ) -> None:
        await no_ttl_cache.write_through(
            "user-1", "tenant-1", ["helios:tenant:transfer"]
        )
        ttl = await redis.ttl("helios:perms:user-1:tenant-1")
        assert ttl == -1

    async def test_opt_in_ttl_via_constructor(
        self, redis
    ) -> None:
        # Positive ttl_seconds restores the EX arg on writes — useful
        # for staging with high churn where the keyspace would
        # otherwise grow unbounded.
        cache = RedisPermissionCache(
            redis=redis, ttl_seconds=120, logger=silent_logger
        )
        await cache.set("user-1", "tenant-1", ["helios:members:view"])
        ttl = await redis.ttl("helios:perms:user-1:tenant-1")
        assert ttl is not None and ttl > 0
        assert ttl <= 120


async def test_returns_none_does_not_raise_on_redis_get_error() -> None:
    """When Redis throws on GET, log+swallow and return None."""

    class _BrokenRedis:
        async def get(self, key: str):
            raise RuntimeError("redis down")

        async def set(self, *args, **kwargs):
            return None

        async def scan(self, *args, **kwargs):
            return (0, [])

        async def delete(self, *args, **kwargs):
            return 0

    broken = RedisPermissionCache(redis=_BrokenRedis(), ttl_seconds=60, logger=silent_logger)
    assert await broken.get("user-1", "tenant-1") is None


async def test_does_not_raise_on_redis_set_error() -> None:
    """When Redis throws on SET, log+swallow (best-effort)."""

    class _BrokenRedis:
        async def get(self, key: str):
            return None

        async def set(self, *args, **kwargs):
            raise RuntimeError("redis down")

        async def scan(self, *args, **kwargs):
            return (0, [])

        async def delete(self, *args, **kwargs):
            return 0

    broken = RedisPermissionCache(redis=_BrokenRedis(), ttl_seconds=60, logger=silent_logger)
    # Should not raise.
    await broken.set("user-1", "tenant-1", ["helios:members:view"])


async def test_raises_on_redis_del_error_invalidate_is_dangerous() -> None:
    """When Redis throws on DEL, the error MUST propagate.

    A failed invalidate means stale data may be served until TTL expires;
    operators need to know.
    """

    class _BrokenRedis:
        async def get(self, key: str):
            return None

        async def set(self, *args, **kwargs):
            return None

        async def scan(self, *args, **kwargs):
            return (0, [])

        async def delete(self, *args, **kwargs):
            raise RuntimeError("redis down")

    broken = RedisPermissionCache(redis=_BrokenRedis(), ttl_seconds=60, logger=silent_logger)
    with pytest.raises(RuntimeError, match="redis down"):
        await broken.invalidate("user-1", "tenant-1")
