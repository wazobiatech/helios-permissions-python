# wazobiatech-helios-permissions — Handoff

> Python SDK for the Nexus permission contract. Redis-cached
> `caller_has_permission`, async client, fail-closed semantics.

## Status

| | |
|---|---|
| Version | **0.3.0** — codegen'd from `wazobiatech/permission-contract` |
| Branch | `feature/ZIN-4901d--helios-permissions-py` |
| Tests | 64 passing across 5 suites |
| Lint | `ruff check` clean |
| Contract version | `permission-contract@v1.0.0` |

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

## Authentication model (v0.2.0)

The Helios route is **HMAC-only**. Knowing `SIGNATURE_SHARED_SECRET` is
the entire auth surface — no `Authorization` header, no project token,
no user token, no `x-tenant-id` (the tenant is carried in the query
string, which the caller signs).

Why a static project token on an env var is wrong:
- A project token is **bound to one tenant** AND **expires**. Neither
  is compatible with a long-lived env var.
- The Helios `/internal/permissions/:userId?tenantId=...` route (ZIN-4901e
  in helios) is gated by `SIGNATURE_SHARED_SECRET` alone. The service
  calling the SDK proves it knows the secret by signing the request.

The previous v0.1.0 design used `x-project-token` against the legacy
`/internal/users/:userId/permissions` route (which is the Mercury target
and requires the full set of headers). That contract is now exclusive
to Mercury. The SDK uses the new HMAC-only route.

The `HeliosClient` constructor takes `signature_shared_secret` (the
canonical name, matches Hecate's `SIGNATURE_SHARED_SECRET` env var).
The v0.1.0 alias `hmac_secret` is still accepted for back-compat.

## Files

```
src/
  helios_permissions/
    __init__.py                       # Public API barrel
    role_permissions.py                # GENERATED — Permission Literal + ROLE_PERMISSIONS map (do not edit)
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
scripts/
  codegen-permissions.py              # Fetches contract, validates, runs codegen-py
  codegen-py.mjs                      # Vendored from permission-contract
tests/
  conftest.py                         # Adds src/ to sys.path
  test_role_permissions.py            # ROLE_PERMISSIONS matrix
  test_in_memory_cache.py             # Cache contract
  test_redis_cache.py                 # Redis impl via fakeredis
  test_helios_client.py               # HMAC signing + response handling
  test_permission_client.py           # Hot path, fail-closed, coalescing
```

## Permission contract source of truth (v0.3.0)

The `Permission = Literal[...]` type and `ROLE_PERMISSIONS` dict are
**codegen'd** from
[`wazobiatech/permission-contract`](https://github.com/wazobiatech/permission-contract)
(public mirror). To change the platform's role → permission matrix:

1. Open a PR against `permission-contract` — edit `permissions.json`,
   bump `version` (semver).
2. Tag a release (`v1.1.0`, etc.).
3. Open a PR against this SDK — bump `PERMISSION_CONTRACT_VERSION`
   in `bitbucket-pipelines.yml`.
4. CI runs `poetry run codegen`, then `ruff check`, `pytest`.

## Decisions locked

- **HMAC-only auth model (v0.2.0).** No project tokens, no service
  tokens, no Mercury-credentials exchange. The route is gated by
  `SIGNATURE_SHARED_SECRET` alone.
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
| `SIGNATURE_SHARED_SECRET` | yes | HMAC-SHA256 shared secret (canonical name) |
| `PERMISSION_REDIS_URL` | yes | Shared Redis URL across all services |

> **Removed in v0.2.0:** `HELIOS_PROJECT_TOKEN` is no longer needed.
> The new HMAC-only route is gated by `SIGNATURE_SHARED_SECRET` alone.
> Project tokens are tenant-bound AND expire, so they were never a
> good fit for an env var.
>
> **Deprecated alias:** `HELIOS_HMAC_SECRET` → use `SIGNATURE_SHARED_SECRET`.
> The old name is still accepted as a back-compat alias by both the
> `HeliosClient` constructor and the `create_permission_client` factory.

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

The HMAC-only route (`GET /internal/permissions/:userId?tenantId=...`)
is implemented in helios as ZIN-4901e (`ServicePermissionsController`
+ `hmacServicePermissionsMiddleware`).

## Out of scope (deferred)

- **Helios-side migration.** Helios still has its own copy of the
  permission map at `helios/src/permissions/role-permissions.ts`. A
  follow-up ticket will replace it with `import from
  wazobiatech_helios_permissions` (or a generated file). Not in
  ZIN-4901a scope.
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
# Codegen requires network — fetches the contract from GitHub.
PERMISSION_CONTRACT_VERSION=v1.0.0 poetry run codegen
poetry run ruff check src tests   # clean
poetry run pytest                 # 64/64 pass
poetry run pytest -v              # verbose
```
