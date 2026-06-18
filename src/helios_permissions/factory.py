"""``create_permission_client`` — convenience factory.

Composes:

  - :class:`RedisPermissionCache` (or :class:`InMemoryPermissionCache`
    for tests)
  - :class:`HeliosClient` (HMAC-signed GET)
  - :class:`PermissionClient` (the cache-first authz decision surface)

Caller injects the Redis connection (we don't own the connection
lifecycle) and the logger (stdlib ``logging.Logger`` satisfies the
protocol).
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from redis.asyncio import Redis

from .cache.in_memory import InMemoryPermissionCache
from .cache.redis import DEFAULT_CACHE_TTL_SECONDS, RedisPermissionCache
from .helios.client import HeliosClient
from .logger import Logger, silent_logger
from .permission_client import PermissionClient

#: Closer — async function that releases SDK-owned resources.
Closer = Callable[[], Awaitable[None]]

#: Returned cache is whichever impl was selected (Redis or in-memory).
CacheOrRedis = RedisPermissionCache | InMemoryPermissionCache | Redis


async def create_permission_client(
    *,
    helios_base_url: str,
    helios_hmac_secret: str,
    helios_project_token: str,
    redis_url: str | None = None,
    redis: Redis | None = None,
    helios_source_service: str = "helios-permissions-sdk",
    cache_ttl_seconds: int = DEFAULT_CACHE_TTL_SECONDS,
    logger: Logger | None = None,
    stale_on_error: bool = True,
    helios_fetch_timeout_ms: int = 2000,
    in_memory: bool = False,
) -> tuple[PermissionClient, CacheOrRedis, Closer]:
    """Construct the (client, cache, closer) trio.

    Pass ``in_memory=True`` for tests to swap the Redis cache for the
    in-memory impl (no Redis connection needed).

    Returns ``(client, cache, closer)``. ``closer`` is async callable
    that releases resources we own (the Redis client and the httpx
    client). For injected resources it's a no-op.
    """
    actual_logger = logger if logger is not None else silent_logger

    # Cache
    owns_redis = False
    cache: Any
    if in_memory:
        cache = InMemoryPermissionCache()
    else:
        if redis is None:
            if redis_url is None:
                raise ValueError(
                    "redis_url is required when redis is not injected and "
                    "in_memory is False"
                )
            redis = Redis.from_url(redis_url)
            owns_redis = True
        cache = RedisPermissionCache(
            redis=redis, ttl_seconds=cache_ttl_seconds, logger=actual_logger
        )

    # Helios client
    helios = HeliosClient(
        base_url=helios_base_url,
        hmac_secret=helios_hmac_secret,
        project_token=helios_project_token,
        source_service=helios_source_service,
        fetch_timeout_ms=helios_fetch_timeout_ms,
    )

    client = PermissionClient(
        helios=helios, cache=cache, logger=actual_logger, stale_on_error=stale_on_error
    )

    async def close() -> None:
        await helios.aclose()
        if owns_redis and redis is not None:
            await redis.aclose()

    return client, cache, close
