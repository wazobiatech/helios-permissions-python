"""PermissionClient — the SDK's main surface.

Responsibilities:

  - ``caller_has_permission(user_id, tenant_id, perm)`` — the hot path
    every service calls on every authz decision. Redis-cached, with
    fail-closed behavior on Helios unavailability.

  - ``get_user_permissions(user_id, tenant_id)`` — full perm list (for
    UI display, not hot-path authz).

  - ``explain(user_id, tenant_id, perm)`` — diagnostic with role + reason
    for the explain endpoint and audit logs.

  - ``invalidate(user_id, tenant_id=None)`` — called by event consumers
    (and Helios's sync write-through path) to drop stale cache entries.

  - ``write_through(user_id, tenant_id, perms)`` — Helios-only path.
    After updating ``user_projects``, Helios writes the new perm array
    directly to the cache (no NX), so the next read sees fresh data
    with no race window.

Failure modes:

  - Cache miss + Helios OK: fetch + populate cache + return.
  - Cache miss + Helios error + ``stale_on_error=True`` → log + return
    ``False`` (fail-closed — deny rather than serve potentially-stale or
    unknown).
  - Cache miss + Helios error + ``stale_on_error=False`` → raise.
  - Cache hit: return cached value (no Helios call).

Concurrency:

  - In-process lock per ``(user_id, tenant_id)`` coalesces concurrent
    cold-cache reads. The first call fetches from Helios; concurrent
    calls await the same future.

Cache TTL:

  The default cache has NO TTL — entries live until explicit DEL via
  :meth:`invalidate` / :meth:`invalidate_tenant` (or via Helios's
  sync write-through on every role-changing mutation). The cache is
  the primary read path for ``callerHasPermission`` and we target a
  90-98% hit rate; entries must outlive the request burst. Pass
  ``cache_ttl_seconds=<positive int>`` to ``create_permission_client``
  to opt back into a TTL (useful for staging with high churn).
  Both Helios-side and SDK-side caches must use the same TTL policy.
"""

from __future__ import annotations

import asyncio
from typing import Literal

from .cache.cache import PermissionCache
from .helios.client import (
    HeliosClient,
    HeliosMembershipResolution,
    HeliosUnreachableError,
)
from .logger import Logger, silent_logger
from .role_permissions import (
    ROLES,
    PERM_SCOPE,
    ROLE_PERMISSIONS,
    SELF_PERMISSIONS,
    Permission,
    is_self_scope,
)


def _is_universal_perm(perm: Permission) -> bool:
    """``True`` if ``perm`` is universal-by-contract.

    A perm is universal-by-contract — granted to every authenticated
    caller without consulting Helios — if any of:

      1. The perm is ``self`` scope (universal by invariant 8 of the
         permission-contract — every authenticated user has these).
      2. The perm is in every role's role_permissions tuple (granted to
         OWNER + ADMIN + EDITOR + VIEWER; universal by contract design,
         regardless of scope).

    Why this exists: Helios stores per-(user, tenant) membership rows.
    Root-tenant users (Mercury's platform admins) and any other tenantless
    caller have no row to look up. Without this short-circuit, every
    ``caller_has_permission`` for a universal perm would resolve to
    ``not_a_member`` and 403 the caller. The contract invariant is that
    these perms do NOT depend on tenant membership — they are universal.

    The check trusts the contract: if a perm is in every role's perm
    array, the contract author intends every authenticated user to have
    it. Adding a perm to all four roles is a deliberate, reviewable
    contract decision — the SDK honors it without re-fetching.
    """
    if is_self_scope(perm):
        return True
    return all(perm in ROLE_PERMISSIONS[role] for role in ROLES)

Reason = Literal[
    "granted_by_role",
    "not_a_member",
    "membership_inactive",
    "role_lacks_permission",
    "cache_hit",
    "cache_miss_filled_by_helios",
    "helios_unreachable_fail_closed",
]


class PermissionExplanation:
    """Diagnostic return from :meth:`PermissionClient.explain`."""

    def __init__(
        self,
        granted: bool,
        role: str | None,
        reason: Reason,
    ) -> None:
        self.granted = granted
        self.role = role
        self.reason = reason

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, PermissionExplanation):
            return NotImplemented
        return (
            self.granted == other.granted
            and self.role == other.role
            and self.reason == other.reason
        )

    def __repr__(self) -> str:
        return (
            f"PermissionExplanation(granted={self.granted!r}, "
            f"role={self.role!r}, reason={self.reason!r})"
        )


class PermissionClient:
    """Cache-first authz decision surface."""

    def __init__(
        self,
        helios: HeliosClient,
        cache: PermissionCache,
        logger: Logger | None = None,
        stale_on_error: bool = True,
    ) -> None:
        self._helios = helios
        self._cache = cache
        self._logger = logger if logger is not None else silent_logger
        self._stale_on_error = stale_on_error
        # Per-key in-flight fetch future. Coalesces concurrent cold reads.
        self._in_flight: dict[str, asyncio.Future[list[Permission]]] = {}

    # -------------------------------------------------------------------------
    # Hot path
    # -------------------------------------------------------------------------

    async def caller_has_permission(
        self, user_id: str, tenant_id: str, required_perm: Permission
    ) -> bool:
        """``True`` if ``user_id`` is granted ``required_perm`` in ``tenant_id``.

        Universal perms (see :func:`_is_universal_perm`) — self-scope
        perms or perms granted to every role — short-circuit to ``True``
        without consulting cache or Helios. This is critical for
        root-tenant users (Mercury's platform admins) who have no Helios
        membership row: without the short-circuit, every
        ``caller_has_permission(root_user, root_tenant, perm)`` would
        resolve to ``not_a_member`` and deny every universal perm.

        Cache-first: a hit returns immediately. On miss, fetches from
        Helios and populates the cache. Concurrent misses for the same
        ``(user_id, tenant_id)`` are coalesced via in-process lock —
        only one Helios call is made per cold key.

        On Helios failure with no cache entry: fail-closed (deny) unless
        the client was constructed with ``stale_on_error=False``, in which
        case :class:`HeliosUnreachableError` propagates.
        """
        if _is_universal_perm(required_perm):
            return True
        perms = await self._resolve_perms(user_id, tenant_id)
        return required_perm in perms

    # -------------------------------------------------------------------------
    # Display / diagnostic
    # -------------------------------------------------------------------------

    async def get_user_permissions(
        self, user_id: str, tenant_id: str
    ) -> list[Permission]:
        """Return the full permission array for ``(user_id, tenant_id)``.

        Same cache-first behavior as :meth:`caller_has_permission`. An
        empty array means the user is not a member of the tenant (or
        the membership is inactive / past expiry).

        Self-scope perms (e.g. ``mercury:user:write:self``) are universal
        by contract — every authenticated user has them regardless of
        role or tenant membership. We always fold ``SELF_PERMISSIONS``
        into the result so callers see a complete view. Without this,
        root-tenant users (Mercury's platform admins, who have no
        Helios membership row) would show an empty perm array even
        though they can mutate their own profile.
        """
        role_perms = await self._resolve_perms(user_id, tenant_id)
        return list(SELF_PERMISSIONS) + role_perms

    async def explain(
        self, user_id: str, tenant_id: str, perm: Permission
    ) -> PermissionExplanation:
        """Diagnostic variant: returns the role, the granted flag, and a reason.

        Note: this method always hits Helios on cache miss (it returns
        the role, not just the perm array). It's intended for the
        explain endpoint and audit logging — not for hot-path authz.
        """
        # Universal perms are granted by contract — no Helios lookup needed.
        if _is_universal_perm(perm):
            return PermissionExplanation(
                granted=True, role=None, reason="granted_by_role"
            )
        try:
            resolution = await self._helios.fetch_user_permissions(user_id, tenant_id)
        except HeliosUnreachableError as err:
            self._logger.error(
                {
                    "err": str(err),
                    "user_id": user_id,
                    "tenant_id": tenant_id,
                    "perm": perm,
                },
                "PermissionClient.explain: Helios unreachable",
            )
            return PermissionExplanation(
                granted=False, role=None, reason="helios_unreachable_fail_closed"
            )

        if resolution["status"] == "not_a_member":
            return PermissionExplanation(
                granted=False, role=None, reason="not_a_member"
            )

        if resolution["status"] == "inactive":
            return PermissionExplanation(
                granted=False,
                role=self._parse_role(resolution["role"]),
                reason="membership_inactive",
            )

        # status == "active"
        role = self._parse_role(resolution["role"])
        granted = perm in resolution["permissions"]
        return PermissionExplanation(
            granted=granted,
            role=role,
            reason="granted_by_role" if granted else "role_lacks_permission",
        )

    # -------------------------------------------------------------------------
    # Cache management
    # -------------------------------------------------------------------------

    async def invalidate(self, user_id: str, tenant_id: str | None = None) -> None:
        """Drop the cache entry for ``(user_id, tenant_id)``.

        When ``tenant_id`` is omitted, drops all entries for this user
        across every tenant.

        Raises on cache failure (operators need to know — without a
        TTL safety net, a missed invalidate is sticky until the next
        write_through for this user).
        """
        await self._cache.invalidate(user_id, tenant_id)

    async def invalidate_tenant(self, tenant_id: str) -> None:
        """Drop all cache entries for a tenant (every user)."""
        await self._cache.invalidate_tenant(tenant_id)

    async def write_through(
        self, user_id: str, tenant_id: str, perms: list[Permission]
    ) -> None:
        """Helios-only path.

        After updating ``user_projects``, Helios calls this with the new
        resolved perm array so the next read sees fresh data without
        race window. Unlike :meth:`cache.set` (which uses NX), this
        overwrites unconditionally.
        """
        await self._cache.write_through(user_id, tenant_id, perms)

    # -------------------------------------------------------------------------
    # Internals
    # -------------------------------------------------------------------------

    async def _resolve_perms(self, user_id: str, tenant_id: str) -> list[Permission]:
        """Cache-first perm resolution.

        Handles the in-flight lock, the Helios call, the cache
        populate, and the fail-closed fallback.
        """
        # 1. Try cache.
        cached = await self._cache.get(user_id, tenant_id)
        if cached is not None:
            return cached

        # 2. Cache miss. Coalesce concurrent reads via in-process lock.
        lock_key = f"{user_id}:{tenant_id}"
        existing = self._in_flight.get(lock_key)
        if existing is not None:
            return await existing

        loop = asyncio.get_running_loop()
        future: asyncio.Future[list[Permission]] = loop.create_future()
        self._in_flight[lock_key] = future

        # The in-flight entry must be released BEFORE the future
        # resolves, so the next caller (after this one returns) sees a
        # clean lock. We pop it in the finally block of the fetcher
        # itself rather than via add_done_callback, because callbacks
        # don't fire synchronously — a sequential caller in the same
        # event-loop tick would otherwise see a stale in-flight entry.
        try:
            await self._fetch_and_populate(user_id, tenant_id, future)
        finally:
            self._in_flight.pop(lock_key, None)
        return await future

    async def _fetch_and_populate(
        self,
        user_id: str,
        tenant_id: str,
        future: asyncio.Future[list[Permission]],
    ) -> None:
        try:
            resolution = await self._helios.fetch_user_permissions(user_id, tenant_id)
        except HeliosUnreachableError as err:
            if not self._stale_on_error:
                future.set_exception(err)
                return
            self._logger.error(
                {"err": str(err), "user_id": user_id, "tenant_id": tenant_id},
                "PermissionClient: Helios unreachable, denying (fail-closed)",
            )
            # Fail-closed: return empty perms so all perm checks deny.
            future.set_result([])
            return

        perms = self._resolution_to_perms(resolution)

        # Populate cache (best-effort — set() swallows Redis errors).
        await self._cache.set(user_id, tenant_id, perms)

        future.set_result(perms)

    @staticmethod
    def _resolution_to_perms(
        resolution: HeliosMembershipResolution,
    ) -> list[Permission]:
        """Translate Helios's discriminated union into a flat ``Permission[]``.

        - ``not_a_member`` -> ``[]``
        - ``inactive`` -> ``[]`` (treat as no perms)
        - ``active`` -> ``resolution["permissions"]`` verbatim
        """
        if resolution["status"] == "active":
            return list(resolution["permissions"])
        return []

    @staticmethod
    def _parse_role(value: str) -> str | None:
        """Parse Helios's role string into the Role union.

        Defensive — if Helios returns an unknown role (shouldn't happen,
        but the schema allows strings), return ``None`` and the explain
        endpoint reports it.
        """
        return value if value in ROLES else None
