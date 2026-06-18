"""Permission cache abstractions and implementations.

The cache stores the resolved permission array for a ``(user_id,
tenant_id)`` pair. Values are JSON-serializable so TS / Python / Go SDKs
can read each other's cache entries (in practice each language runs its
own Redis instance, but cross-language compat is the design goal).
"""

from .cache import PermissionCache
from .in_memory import InMemoryPermissionCache
from .redis import DEFAULT_CACHE_TTL_SECONDS, RedisPermissionCache

__all__ = [
    "DEFAULT_CACHE_TTL_SECONDS",
    "InMemoryPermissionCache",
    "PermissionCache",
    "RedisPermissionCache",
]
