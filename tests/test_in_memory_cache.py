"""In-memory cache contract tests.

These tests cover the cache contract; the Redis impl has the same
contract (verified via shared Protocol), so passing tests here means
the Redis impl should behave correctly too (modulo Redis-specific edge
cases verified separately).
"""

import pytest
from helios_permissions import InMemoryPermissionCache


class _Clock:
    def __init__(self, start_ms: float) -> None:
        self._ms = start_ms

    def __call__(self) -> float:
        return self._ms / 1000.0

    def advance(self, ms: float) -> None:
        self._ms += ms


@pytest.fixture
def clock() -> _Clock:
    return _Clock(start_ms=1_000_000)


@pytest.fixture
def cache(clock: _Clock) -> InMemoryPermissionCache:
    return InMemoryPermissionCache(ttl_ms=60_000, now=clock)


@pytest.fixture
def no_ttl_cache() -> InMemoryPermissionCache:
    """Default — no TTL. Entries live until explicit invalidation.

    Mirrors the v0.5.0 platform default: the cache is the primary
    read path for callerHasPermission; entries must outlive the
    request burst. Mutations invalidate explicitly.
    """
    return InMemoryPermissionCache()


class TestGetSet:
    async def test_returns_none_on_miss(self, cache: InMemoryPermissionCache) -> None:
        assert await cache.get("user-1", "tenant-1") is None

    async def test_returns_the_cached_value_on_hit(
        self, cache: InMemoryPermissionCache
    ) -> None:
        await cache.set("user-1", "tenant-1", ["helios:members:view"])
        assert await cache.get("user-1", "tenant-1") == ["helios:members:view"]

    async def test_negative_caching_empty_array_means_not_a_member(
        self, cache: InMemoryPermissionCache
    ) -> None:
        await cache.set("user-1", "tenant-1", [])
        result = await cache.get("user-1", "tenant-1")
        assert result is not None
        assert result == []


class TestNXSemanticsOnSet:
    async def test_does_not_overwrite_an_existing_live_entry(
        self, cache: InMemoryPermissionCache
    ) -> None:
        await cache.set("user-1", "tenant-1", ["helios:members:view"])
        await cache.set("user-1", "tenant-1", ["helios:members:invite"])
        assert await cache.get("user-1", "tenant-1") == ["helios:members:view"]

    async def test_writes_when_existing_entry_is_expired(
        self, cache: InMemoryPermissionCache, clock: _Clock
    ) -> None:
        await cache.set("user-1", "tenant-1", ["helios:members:view"])
        clock.advance(70_000)  # past TTL
        await cache.set("user-1", "tenant-1", ["helios:members:invite"])
        assert await cache.get("user-1", "tenant-1") == ["helios:members:invite"]


class TestWriteThrough:
    async def test_overwrites_unconditionally_no_nx(
        self, cache: InMemoryPermissionCache
    ) -> None:
        await cache.set("user-1", "tenant-1", ["helios:members:view"])
        await cache.write_through("user-1", "tenant-1", ["helios:members:invite"])
        assert await cache.get("user-1", "tenant-1") == ["helios:members:invite"]


class TestInvalidate:
    async def test_drops_specific_user_tenant_entry(
        self, cache: InMemoryPermissionCache
    ) -> None:
        await cache.set("user-1", "tenant-1", ["helios:members:view"])
        await cache.set("user-1", "tenant-2", ["helios:members:invite"])
        await cache.invalidate("user-1", "tenant-1")
        assert await cache.get("user-1", "tenant-1") is None
        assert await cache.get("user-1", "tenant-2") is not None

    async def test_drops_all_entries_for_user_when_tenant_omitted(
        self, cache: InMemoryPermissionCache
    ) -> None:
        await cache.set("user-1", "tenant-1", ["helios:members:view"])
        await cache.set("user-1", "tenant-2", ["helios:members:invite"])
        await cache.set("user-2", "tenant-1", ["helios:roles:assign"])
        await cache.invalidate("user-1")
        assert await cache.get("user-1", "tenant-1") is None
        assert await cache.get("user-1", "tenant-2") is None
        assert await cache.get("user-2", "tenant-1") is not None


class TestInvalidateTenant:
    async def test_drops_all_entries_for_a_tenant(
        self, cache: InMemoryPermissionCache
    ) -> None:
        await cache.set("user-1", "tenant-1", ["helios:members:view"])
        await cache.set("user-2", "tenant-1", ["helios:members:invite"])
        await cache.set("user-1", "tenant-2", ["helios:roles:assign"])
        await cache.invalidate_tenant("tenant-1")
        assert await cache.get("user-1", "tenant-1") is None
        assert await cache.get("user-2", "tenant-1") is None
        assert await cache.get("user-1", "tenant-2") is not None


class TestTTL:
    async def test_expires_entries_after_ttl(
        self, cache: InMemoryPermissionCache, clock: _Clock
    ) -> None:
        await cache.set("user-1", "tenant-1", ["helios:members:view"])
        assert await cache.get("user-1", "tenant-1") is not None
        clock.advance(60_001)
        assert await cache.get("user-1", "tenant-1") is None


class TestNoTTL:
    """v0.5.0 default: entries live until explicit invalidate.

    The cache is the primary read path for callerHasPermission and we
    target a 90-98% hit rate; entries must outlive the request burst.
    """

    async def test_entries_persist_indefinitely_without_ttl(
        self, no_ttl_cache: InMemoryPermissionCache
    ) -> None:
        await no_ttl_cache.set("user-1", "tenant-1", ["helios:members:view"])
        # Read it back many times — no expiry.
        for _ in range(10):
            assert await no_ttl_cache.get("user-1", "tenant-1") == [
                "helios:members:view"
            ]

    async def test_write_through_also_no_expiry(
        self, no_ttl_cache: InMemoryPermissionCache
    ) -> None:
        await no_ttl_cache.write_through(
            "user-1", "tenant-1", ["helios:tenant:transfer"]
        )
        assert await no_ttl_cache.get("user-1", "tenant-1") == [
            "helios:tenant:transfer"
        ]
