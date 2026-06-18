# wazobiatech-helios-permissions

> Python SDK for the Nexus permission contract — Redis-cached
> `caller_has_permission` for cross-service authz.

## What it does

Every service in the platform needs to answer the same question: **"is this
user allowed to do X in tenant Y?"** The answer lives in Helios's
`user_projects` table (one row per user-per-tenant with a role). This SDK
is the client for that source of truth, with three properties that matter
in production:

1. **Cache-first** — Redis-cached (60s TTL), so the hot path is one Redis
   GET. Misses fetch from Helios and populate.
2. **Event-driven invalidation** — Helios writes to the cache synchronously
   after every role change (write-through). Kafka events invalidate
   downstream caches as a backup.
3. **Fail-closed** — if Helios is unreachable and no cache entry exists,
   the SDK denies by default. Operators page; users see 403 until Helios
   recovers. Better than serving potentially-stale perms during an outage.

## Install

```bash
pip install wazobiatech-helios-permissions
```

The only runtime dependencies are `httpx` (for the Helios client) and
`redis` (for the cache).

## Usage

### Hot-path authz decision

```python
from helios_permissions import create_permission_client

client, cache, close = await create_permission_client(
    helios_base_url="https://helios.internal",
    helios_hmac_secret="<shared-secret>",
    helios_project_token="<platform-tenant-token>",
    redis_url="redis://helios-permissions-redis:6379/0",
)

# In a resolver / handler:
granted = await client.caller_has_permission(
    user_id, tenant_id, "helios:members:update"
)
if not granted:
    raise PermissionError("forbidden")

# On shutdown:
await close()
```

### In-process testing (no Redis)

```python
client, cache, close = await create_permission_client(
    helios_base_url="https://helios.internal",
    helios_hmac_secret="<secret>",
    helios_project_token="<token>",
    in_memory=True,
)
```

### Pure role → perm map (used by Helios itself)

```python
from helios_permissions.role_permissions import (
    ROLE_PERMISSIONS, resolve_permissions, role_has_permission,
)

resolve_permissions("OWNER")  # every perm in every service
role_has_permission("VIEWER", "helios:tenant:transfer")  # False
```

## Permission vocabulary

Permissions follow `{service}:{resource}:{action}`. The closed union:

- `athens:project:view` / `update` / `delete`
- `athens:services:enable` / `disable`
- `athens:team:invite` / `remove`
- `mercury:users:read` / `write`
- `mercury:api_keys:manage`
- `mercury:connections:read`
- `muse:posts:read` / `write` / `delete`
- `muse:drafts:read` / `write`
- `helios:members:view` / `invite` / `remove`
- `helios:roles:assign` / `revoke`
- `helios:invitations:create` / `revoke`
- `helios:tenant:switch` / `transfer`

## Role → Permission map

| Role | What they get |
|---|---|
| `OWNER` | Everything in every service, including `helios:tenant:transfer` |
| `ADMIN` | Everything except destructive `*:delete` and `helios:tenant:transfer` |
| `EDITOR` | Read + write on content services; no team mgmt |
| `VIEWER` | Read-only across all services |

`helios:tenant:switch` is granted to every role (it's a navigation gesture).

## Environment variables

| Var | Required | Description |
|---|---|---|
| `HELIOS_BASE_URL` | yes | e.g. `https://helios.internal` |
| `HELIOS_HMAC_SECRET` | yes | HMAC-SHA256 secret shared with Helios |
| `HELIOS_PROJECT_TOKEN` | yes | Project token for the platform tenant |
| `PERMISSION_REDIS_URL` | yes | Shared Redis URL — Helios and all services use the same instance |

## Cache semantics

- **Key shape:** `helios:perms:{user_id}:{tenant_id}` → JSON list of perms
- **TTL:** 60 seconds (the safety net for missed invalidations)
- **Populate:** `SET ... NX EX 60` — never overwrites a concurrent populate (avoids stale-resurrection after invalidate race)
- **Write-through (Helios only):** `SET ... EX 60` (no NX) — Helios KNOWS the new value, overwrites unconditionally
- **Invalidate:** `SCAN MATCH ... | DEL` (non-blocking) for `invalidate(user_id)` / `invalidate_tenant`. Direct `DEL` for `invalidate(user_id, tenant_id)`.
- **Negative cache:** `[]` (empty list) means "user is not a member" — distinct from `None` (miss).
- **Failure modes:**
  - Redis GET fails → log + return `None` (caller falls through to Helios)
  - Redis SET fails → log + swallow (best-effort; cache miss next time)
  - Redis DEL fails → log + raise (operators need to know — TTL is the only safety net)

## Concurrent read coalescing

The SDK coalesces concurrent cold-cache reads via an in-process lock keyed
by `(user_id, tenant_id)`. The first concurrent reader fetches from
Helios; subsequent readers await the same future. No thundering herd.

For multi-instance deployments, each instance runs its own lock — Helios
is still hit ~N times (one per instance). For global coalescing, add a
Redis-lock layer (deferred for v1).

## HMAC contract

Matches `wazobiatech/nexus-mcp-contract`. Payload:

```
payload = METHOD.upper() + fullPath + timestamp
digest  = HMAC-SHA256(secret_utf8, payload_utf8), lowercase hex
reject if |now - timestamp| > 300s
```

Full path includes the query string. The signature is sent as
`x-signature` with `x-timestamp` (Unix seconds).

## Tests

```bash
poetry run pytest          # one run
poetry run pytest -v       # verbose
poetry run ruff check src tests
```

60 tests across 5 suites cover:

- Role × Permission map (every role, every perm)
- `InMemoryPermissionCache` (NX semantics, writeThrough, invalidate, TTL)
- `RedisPermissionCache` (via `fakeredis` — SET NX EX, SCAN, JSON, error handling)
- `HeliosClient` (HMAC signing, response handling, error paths)
- `PermissionClient` (cache-first, fail-closed, concurrent coalescing, writeThrough, explain)

## License

MIT — Wazobia Tech
