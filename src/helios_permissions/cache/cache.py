"""PermissionCache — the abstraction every cache impl satisfies.

``RedisPermissionCache`` is the production impl. ``InMemoryPermissionCache``
is the test impl. Helios and downstream services depend only on this
protocol; the impl is injected by the factory.
"""

from __future__ import annotations

from typing import Protocol

from ..role_permissions import Permission


class PermissionCache(Protocol):
    """Cache storing the resolved permission array for a (user_id, tenant_id) pair.

    Values are JSON-serializable so TS / Python / Go SDKs can read each
    other's cache entries (in practice each language runs its own Redis
    instance, but cross-language compat is the design goal).
    """

    async def get(self, user_id: str, tenant_id: str) -> list[Permission] | None:
        """Return the cached permission array, or ``None`` on cache miss.

        An empty list ``[]`` is a valid cached value meaning "user is not a
        member of this tenant" (negative cache). Callers must distinguish
        ``None`` (miss, fall through to Helios) from ``[]`` (hit, deny).

        Implementations MUST NOT raise on Redis errors. Log and return
        ``None`` — the caller's fall-through to Helios is the safety net.
        """
        ...

    async def set(self, user_id: str, tenant_id: str, perms: list[Permission]) -> None:
        """Store the permission array with the configured TTL.

        Uses ``SET NX`` to avoid resurrecting an entry that was just
        invalidated (the stale-populate race). TTL is the safety net for
        missed invalidations.

        Implementations MUST NOT raise on Redis errors. Log and swallow —
        the cache is best-effort.
        """
        ...

    async def write_through(
        self, user_id: str, tenant_id: str, perms: list[Permission]
    ) -> None:
        """Overwrite the cached value without the NX guard.

        Used by Helios for write-through after a perm change — Helios
        KNOWS the new value is correct and wants to force the update
        immediately, not wait for the race window to resolve.

        Same error semantics as ``set``: log + swallow on Redis failure.
        """
        ...

    async def invalidate(self, user_id: str, tenant_id: str | None = None) -> None:
        """Drop the cached entry.

        When ``tenant_id`` is omitted, drops all entries for this user
        across every tenant (used by ``member-removed``).

        This is the one cache operation that SHOULD raise on failure. A
        failed invalidate means stale data may be served until TTL
        expires; the caller (typically an event consumer) needs to know
        to retry or page operators.
        """
        ...

    async def invalidate_tenant(self, tenant_id: str) -> None:
        """Drop all cached entries for a tenant (every user).

        Used when a tenant is deleted — no ``helios.member.removed`` event
        fires per-user.

        Same raise-on-failure semantics as ``invalidate``.
        """
        ...
