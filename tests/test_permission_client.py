"""PermissionClient — exercise the hot-path authz decision surface.

Uses InMemoryPermissionCache + a mocked HeliosClient (no real HTTP).
The mock has the same shape as the real HeliosClient so we can swap
it freely.
"""

import pytest
from helios_permissions import (
    HeliosUnreachableError,
    InMemoryPermissionCache,
    PermissionClient,
)
from helios_permissions.logger import silent_logger


class MockHeliosClient:
    """Mock with the same shape as HeliosClient.fetch_user_permissions."""

    def __init__(self) -> None:
        self.resolutions: dict[str, dict] = {}
        self.call_count = 0

    async def fetch_user_permissions(self, user_id: str, tenant_id: str) -> dict:
        self.call_count += 1
        key = f"{user_id}:{tenant_id}"
        r = self.resolutions.get(key)
        if r is None:
            return {"status": "not_a_member"}
        return r


class FailingHeliosClient:
    async def fetch_user_permissions(self, user_id: str, tenant_id: str) -> dict:
        raise HeliosUnreachableError("helios down", cause=None)


@pytest.fixture
def cache() -> InMemoryPermissionCache:
    return InMemoryPermissionCache(ttl_ms=60_000)


@pytest.fixture
def helios() -> MockHeliosClient:
    return MockHeliosClient()


@pytest.fixture
def client(helios: MockHeliosClient, cache: InMemoryPermissionCache) -> PermissionClient:
    return PermissionClient(
        helios=helios,  # type: ignore[arg-type]
        cache=cache,
        logger=silent_logger,
    )


# --- Happy path ------------------------------------------------------------


class TestCallerHasPermissionHappyPath:
    async def test_returns_true_when_role_grants_the_perm(
        self, client: PermissionClient, helios: MockHeliosClient
    ) -> None:
        helios.resolutions["user-1:tenant-1"] = {
            "status": "active",
            "role": "OWNER",
            "permissions": ["helios:tenant:transfer", "muse:posts:delete"],
        }
        granted = await client.caller_has_permission(
            "user-1", "tenant-1", "helios:tenant:transfer"
        )
        assert granted is True

    async def test_returns_false_when_role_lacks_the_perm(
        self, client: PermissionClient, helios: MockHeliosClient
    ) -> None:
        helios.resolutions["user-1:tenant-1"] = {
            "status": "active",
            "role": "VIEWER",
            "permissions": ["helios:members:view"],
        }
        granted = await client.caller_has_permission(
            "user-1", "tenant-1", "helios:tenant:transfer"
        )
        assert granted is False


# --- Cache behavior --------------------------------------------------------


class TestCallerHasPermissionCacheBehavior:
    async def test_hits_cache_on_second_call_no_second_helios_fetch(
        self, client: PermissionClient, helios: MockHeliosClient
    ) -> None:
        helios.resolutions["user-1:tenant-1"] = {
            "status": "active",
            "role": "OWNER",
            "permissions": ["helios:tenant:transfer"],
        }
        await client.caller_has_permission("user-1", "tenant-1", "helios:tenant:transfer")
        await client.caller_has_permission("user-1", "tenant-1", "helios:tenant:transfer")
        await client.caller_has_permission("user-1", "tenant-1", "helios:tenant:transfer")
        assert helios.call_count == 1

    async def test_returns_cached_value_with_different_perm_from_same_role(
        self, client: PermissionClient, helios: MockHeliosClient
    ) -> None:
        helios.resolutions["user-1:tenant-1"] = {
            "status": "active",
            "role": "OWNER",
            "permissions": ["helios:tenant:transfer", "muse:posts:delete"],
        }
        a = await client.caller_has_permission(
            "user-1", "tenant-1", "helios:tenant:transfer"
        )
        b = await client.caller_has_permission("user-1", "tenant-1", "muse:posts:delete")
        assert a is True
        assert b is True
        assert helios.call_count == 1

    async def test_not_a_member_returns_empty_perms_and_denies(
        self, client: PermissionClient
    ) -> None:
        granted = await client.caller_has_permission(
            "user-x", "tenant-y", "helios:members:view"
        )
        assert granted is False

    async def test_inactive_membership_returns_empty_perms_and_denies(
        self, client: PermissionClient, helios: MockHeliosClient
    ) -> None:
        helios.resolutions["user-1:tenant-1"] = {
            "status": "inactive",
            "role": "OWNER",
        }
        granted = await client.caller_has_permission(
            "user-1", "tenant-1", "helios:members:view"
        )
        assert granted is False


# --- Concurrent reads coalesce ---------------------------------------------


class TestConcurrentReadsCoalesce:
    async def test_makes_only_one_helios_call_for_n_concurrent_cold_cache_reads(
        self, helios: MockHeliosClient, cache: InMemoryPermissionCache
    ) -> None:
        helios.resolutions["user-1:tenant-1"] = {
            "status": "active",
            "role": "OWNER",
            "permissions": ["helios:tenant:transfer"],
        }
        client = PermissionClient(
            helios=helios,  # type: ignore[arg-type]
            cache=cache,
            logger=silent_logger,
        )

        import asyncio

        reads = [
            client.caller_has_permission("user-1", "tenant-1", "helios:tenant:transfer")
            for _ in range(20)
        ]
        results = await asyncio.gather(*reads)

        assert all(r is True for r in results)
        assert helios.call_count == 1


# --- Fail-closed on Helios error ------------------------------------------


class TestFailClosedOnHeliosError:
    async def test_returns_false_denies_when_helios_errors_and_no_cache_entry(
        self, cache: InMemoryPermissionCache
    ) -> None:
        client = PermissionClient(
            helios=FailingHeliosClient(),  # type: ignore[arg-type]
            cache=cache,
            logger=silent_logger,
            stale_on_error=True,
        )
        granted = await client.caller_has_permission(
            "user-1", "tenant-1", "helios:members:view"
        )
        assert granted is False

    async def test_raises_when_stale_on_error_is_false(
        self, cache: InMemoryPermissionCache
    ) -> None:
        client = PermissionClient(
            helios=FailingHeliosClient(),  # type: ignore[arg-type]
            cache=cache,
            logger=silent_logger,
            stale_on_error=False,
        )
        with pytest.raises(Exception, match="helios down"):
            await client.caller_has_permission(
                "user-1", "tenant-1", "helios:members:view"
            )


# --- Invalidate ------------------------------------------------------------


class TestInvalidate:
    async def test_drops_cache_entry_for_user_tenant(
        self, client: PermissionClient, helios: MockHeliosClient
    ) -> None:
        helios.resolutions["user-1:tenant-1"] = {
            "status": "active",
            "role": "OWNER",
            "permissions": ["helios:tenant:transfer"],
        }
        await client.caller_has_permission("user-1", "tenant-1", "helios:tenant:transfer")
        assert helios.call_count == 1
        await client.caller_has_permission("user-1", "tenant-1", "helios:tenant:transfer")
        assert helios.call_count == 1

        await client.invalidate("user-1", "tenant-1")

        await client.caller_has_permission("user-1", "tenant-1", "helios:tenant:transfer")
        assert helios.call_count == 2

    async def test_drops_all_entries_for_user_when_tenant_omitted(
        self, client: PermissionClient, helios: MockHeliosClient
    ) -> None:
        helios.resolutions["user-1:tenant-1"] = {
            "status": "active",
            "role": "OWNER",
            "permissions": ["helios:members:view"],
        }
        helios.resolutions["user-1:tenant-2"] = {
            "status": "active",
            "role": "ADMIN",
            "permissions": ["helios:members:invite"],
        }
        await client.caller_has_permission("user-1", "tenant-1", "helios:members:view")
        await client.caller_has_permission("user-1", "tenant-2", "helios:members:invite")
        assert helios.call_count == 2

        await client.invalidate("user-1")

        await client.caller_has_permission("user-1", "tenant-1", "helios:members:view")
        await client.caller_has_permission("user-1", "tenant-2", "helios:members:invite")
        assert helios.call_count == 4


# --- writeThrough ----------------------------------------------------------


class TestWriteThrough:
    async def test_overwrites_cached_value_used_by_helios_after_role_change(
        self, client: PermissionClient, helios: MockHeliosClient
    ) -> None:
        helios.resolutions["user-1:tenant-1"] = {
            "status": "active",
            "role": "VIEWER",
            "permissions": ["helios:members:view"],
        }
        await client.caller_has_permission("user-1", "tenant-1", "helios:tenant:transfer")
        assert helios.call_count == 1

        # Helios writes-through the new perm set (after promoting to OWNER).
        await client.write_through(
            "user-1", "tenant-1", ["helios:tenant:transfer"]
        )

        granted = await client.caller_has_permission(
            "user-1", "tenant-1", "helios:tenant:transfer"
        )
        assert granted is True
        assert helios.call_count == 1  # No additional Helios fetch.


# --- explain ---------------------------------------------------------------


class TestExplain:
    async def test_returns_granted_true_role_for_active_with_perm(
        self, client: PermissionClient, helios: MockHeliosClient
    ) -> None:
        helios.resolutions["user-1:tenant-1"] = {
            "status": "active",
            "role": "OWNER",
            "permissions": ["helios:tenant:transfer"],
        }
        result = await client.explain("user-1", "tenant-1", "helios:tenant:transfer")
        assert result.granted is True
        assert result.role == "OWNER"
        assert result.reason == "granted_by_role"

    async def test_returns_granted_false_role_reason_for_active_without_perm(
        self, client: PermissionClient, helios: MockHeliosClient
    ) -> None:
        helios.resolutions["user-1:tenant-1"] = {
            "status": "active",
            "role": "VIEWER",
            "permissions": ["helios:members:view"],
        }
        result = await client.explain("user-1", "tenant-1", "helios:tenant:transfer")
        assert result.granted is False
        assert result.role == "VIEWER"
        assert result.reason == "role_lacks_permission"

    async def test_returns_granted_false_null_not_a_member_for_non_members(
        self, client: PermissionClient
    ) -> None:
        result = await client.explain("user-x", "tenant-y", "helios:members:view")
        assert result.granted is False
        assert result.role is None
        assert result.reason == "not_a_member"

    async def test_returns_granted_false_role_inactive_for_inactive(
        self, client: PermissionClient, helios: MockHeliosClient
    ) -> None:
        helios.resolutions["user-1:tenant-1"] = {
            "status": "inactive",
            "role": "OWNER",
        }
        result = await client.explain("user-1", "tenant-1", "helios:tenant:transfer")
        assert result.granted is False
        assert result.role == "OWNER"
        assert result.reason == "membership_inactive"
