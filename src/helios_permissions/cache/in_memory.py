"""InMemoryPermissionCache — Map-backed impl for tests and single-instance dev.

Production uses ``RedisPermissionCache``; this impl exists so unit tests
don't need a Redis instance.

Same interface contract as the Redis impl:

  - ``get`` returns ``None`` on miss
  - ``set`` / ``write_through`` are best-effort (never raise)
  - ``invalidate`` / ``invalidate_tenant`` would raise on failure (no
    errors possible here, but kept consistent)
"""

from __future__ import annotations

import time
from collections.abc import Callable

from ..role_permissions import Permission


class InMemoryPermissionCache:
    """Map-backed cache with optional simulated TTL."""

    def __init__(
        self,
        ttl_ms: float | None = None,
        now: Callable[[], float] | None = None,
    ) -> None:
        self._store: dict[str, tuple[list[Permission], float]] = {}
        self._ttl_ms = ttl_ms if ttl_ms is not None else float("inf")
        self._now = now if now is not None else time.time

    @staticmethod
    def _key(user_id: str, tenant_id: str) -> str:
        return f"{user_id}:{tenant_id}"

    @staticmethod
    def _user_prefix(user_id: str) -> str:
        return f"{user_id}:"

    @staticmethod
    def _tenant_suffix(tenant_id: str) -> str:
        return f":{tenant_id}"

    def _is_expired(self, expires_at: float) -> bool:
        return expires_at <= self._now() * 1000.0

    def _expires_at_ms(self) -> float:
        return self._now() * 1000.0 + self._ttl_ms

    async def get(self, user_id: str, tenant_id: str) -> list[Permission] | None:
        k = self._key(user_id, tenant_id)
        entry = self._store.get(k)
        if entry is None:
            return None
        perms, expires_at = entry
        if self._is_expired(expires_at):
            self._store.pop(k, None)
            return None
        return list(perms)

    async def set(self, user_id: str, tenant_id: str, perms: list[Permission]) -> None:
        k = self._key(user_id, tenant_id)
        # NX semantics: don't overwrite an existing live entry.
        existing = self._store.get(k)
        if existing is not None and not self._is_expired(existing[1]):
            return
        self._store[k] = (list(perms), self._expires_at_ms())

    async def write_through(
        self, user_id: str, tenant_id: str, perms: list[Permission]
    ) -> None:
        k = self._key(user_id, tenant_id)
        self._store[k] = (list(perms), self._expires_at_ms())

    async def invalidate(self, user_id: str, tenant_id: str | None = None) -> None:
        if tenant_id is None:
            prefix = self._user_prefix(user_id)
            for k in list(self._store.keys()):
                if k.startswith(prefix):
                    self._store.pop(k, None)
        else:
            self._store.pop(self._key(user_id, tenant_id), None)

    async def invalidate_tenant(self, tenant_id: str) -> None:
        suffix = self._tenant_suffix(tenant_id)
        for k in list(self._store.keys()):
            if k.endswith(suffix):
                self._store.pop(k, None)

    def size(self) -> int:
        """Test helper — number of live entries."""
        return len(self._store)

    def clear(self) -> None:
        """Test helper — wipe between tests."""
        self._store.clear()
