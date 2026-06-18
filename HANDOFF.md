# wazobiatech-helios-permissions — Handoff

> Python SDK for the Nexus permission contract. Redis-cached
> `caller_has_permission`, async client, fail-closed semantics.

## Status

| | |
|---|---|
| Version | 0.1.0 (initial release) |
| Branch | `feature/ZIN-4901d--helios-permissions-py` |
| Tests | 60 passing across 5 suites |
| Lint | `ruff check` clean |
| PyPI | not yet published (awaiting green CI) |

## What this SDK does

Single source of truth for cross-service authz: Helios's `user_projects`
table. Every service asks the SDK "can user U do perm P in tenant T?"
The SDK:

1. Checks Redis (one GET on the hot path).
2. On miss, fetches from Helios via HMAC-signed GET and populates the cache.
3. Translates Helios's discriminated union (active / inactive / not_a_member)
   into a flat `list[Permission]` (empty for non-members and inactive).
4. On Helios error with no cache entry: denies by default (`stale_on_error=True`).
5. Supports Helios's sync write-through path (after a role change in
   `user_projects`, Helios overwrites the cache directly with the new
   perm array — no race window).

## Files

```
src/
  helios_permissions/
    __init__.py                       # Public API barrel
    role_permissions.py                # Permission union + ROLE_PERMISSIONS map
    permission_client.py              # PermissionClient (hot-path authz)
    factory.py                        # create_permission_client() async factory
    logger.py                         # Logger protocol + silent/console defaults
    cache/
      __init__.py
      cache.py                        # PermissionCache Protocol
      in_memory.py                    # Map impl (tests)
      redis.py                        # Redis impl (production)
    helios/
      __init__.py
      client.py                       # HeliosClient (HMAC-signed GET)
tests/
  conftest.py                         # Adds src/ to sys.path
  test_role_permissions.py            # ROLE_PERMISSIONS matrix
  test_in_memory_cache.py             # Cache contract
  test_redis_cache.py                 # Redis impl via fakeredis
  test_helios_client.py               # HMAC signing + response handling
  test_permission_client.py           # Hot path, fail-closed, coalescing
```

## Decisions locked

- **Drop JWT `permissions[]` claim.** Every service uses the SDK for
  authz; the JWT is identity-only. (Follow-up: file in Mercury HANDOFF.)
- **Drop `@UserAuth(['perm:...'])` scope checks.** Service-layer
  `caller_has_permission` is the only gate. (Follow-up: per-service PRs.)
- **`PERMISSION_REDIS_URL` shared by all services + Helios.** Single
  Redis instance per cluster (v1); Sentinel/Cluster when scaling beyond
  one box.
- **Write-through from Helios.** Sync cache overwrite after role change
  — sub-millisecond staleness window. Event-driven invalidation as backup.
- **Fail-closed default.** Helios down + no cache → deny. Opt out via
  `stale_on_error=False`.
- **No wildcards in JWT.** Every perm enumerated.
- **No encryption.** JWT perms are plain JSON; SDK perms are plain JSON.

## Cache semantics

| Op | Behavior |
|---|---|
| `get(user_id, tenant_id)` | Redis GET. On miss → `None`. On error → log warn + `None` (fall-through). |
| `set(...)` | `SET ... NX EX 60`. Stale-populate race protection. On error → log warn + swallow. |
| `write_through(...)` | `SET ... EX 60` (no NX). Used by Helios after a role change. |
| `invalidate(user_id, tenant_id=None)` | `DEL` (specific) or `SCAN MATCH ... \| DEL` (all). On error → log error + raise. |
| `invalidate_tenant(tenant_id)` | `SCAN MATCH helios:perms:*:{tenant_id} \| DEL`. On error → raise. |

## Concurrent read coalescing

In-process lock keyed by `(user_id, tenant_id)`. The first concurrent
reader fetches from Helios; subsequent readers await the same future.
Verified in `test_permission_client.py` — 20 concurrent reads on cold
cache result in 1 Helios call.

### A subtle asyncio gotcha we hit and fixed

The first version of `_resolve_perms` cleaned up the in-flight entry
via `task.add_done_callback(lambda: in_flight.pop(...))`. **That
doesn't work** — `add_done_callback` doesn't fire synchronously when
the future resolves; it waits for the next event-loop tick. A
sequential caller in the same tick would see a stale in-flight entry
and short-circuit to the cached future, missing a legitimate refresh
after `invalidate`.

**Fix:** the in-flight entry is popped in a `try/finally` inside the
fetcher itself, so the lock is released BEFORE the future resolves.
The `add_done_callback` pattern (used in the TS SDK, where
microtask-ordering differs) is not portable to Python asyncio.

For multi-instance deployments, Helios is hit ~N times (once per
instance). Global coalescing via Redis lock is a v2 optimization.

## Environment variables

| Var | Required | Description |
|---|---|---|
| `HELIOS_BASE_URL` | yes | e.g. `https://helios.internal` |
| `HELIOS_HMAC_SECRET` | yes | Shared HMAC-SHA256 secret |
| `HELIOS_PROJECT_TOKEN` | yes | Project token for the platform tenant |
| `PERMISSION_REDIS_URL` | yes | Shared Redis URL across all services |

## Cross-SDK consistency

HMAC signing logic matches `wazobiatech/nexus-mcp-contract`:

```
payload = METHOD.upper() + fullPath + timestamp
digest  = HMAC-SHA256(secret_utf8, payload_utf8), lowercase hex
reject if |now - timestamp| > 300s
```

The TS SDK (`@wazobiatech/helios-permissions`) and this Python SDK
produce byte-identical signatures for the same inputs. Verified
independently in each SDK's test suite.

## Out of scope (deferred)

- **Permission contract repo** (`wazobiatech/permission-contract` —
  language-agnostic JSON files mirrored from this map). The contract
  ticket is ZIN-4901a. The SDK is structured so the JSON can replace the
  hardcoded tuples in `role_permissions.py` via codegen in v0.2.0.
- **Go / Laravel SDKs.** Mirror packages. Same API surface.
- **Multi-instance Redis lock.** Use Redis-based SET NX EX for global
  coalescing when scaling beyond ~5 instances.
- **Redis Sentinel / Cluster support.** v1 is single instance.
- **FastAPI / Starlette integration.** `create_permission_client()`
  works inside an existing FastAPI app (it's just an async factory);
  there's no separate `add_middleware` helper. Follow-up.

## Verification

```bash
poetry install
poetry run ruff check src tests   # clean
poetry run pytest                 # 60/60 pass
poetry run pytest -v              # verbose
```
