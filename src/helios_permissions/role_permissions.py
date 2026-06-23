"""helios-permissions — Role → Permission map and helpers.

Canonical source of truth for the platform. Generated from the
language-agnostic JSON contract at `wazobiatech/permission-contract`
v1.4.0 (generated 2026-06-23). Do NOT edit by hand — edit the
contract's `permissions.json` and re-run codegen.

The Helios service imports this module via the published package; Helios
does NOT redefine the map. TS / Python / Go / Laravel SDKs that read the
same JSON contract agree on what OWNER / ADMIN / EDITOR / VIEWER means.

Permission naming convention: `{service}:{resource}:{action}`.

  - service  — one of: athens, mercury, muse, helios
  - resource — domain noun (project, users, posts, members, ...)
  - action   — verb (view, write, delete, manage, ...)

v1.3.0 perm scopes — the resolver uses `PERM_SCOPE[perm]` to gate which
path (platform-user vs tenant-user) is valid for a given perm:

  - `self`              — universal, granted implicitly (no role needed).
  - `platform`          — granted via ROLE_PERMISSIONS (platform-user path);
                           cannot be bundled into a TenantRole.
  - `project`           — granted via TenantRole (tenant-user path);
                           cannot appear in ROLE_PERMISSIONS.
  - `platform/project`  — valid via either path (dual-scope).

ZIN-4714 — `helios:tenant:transfer` is OWNER-only by design. Ownership
transfer is the single entry point to the OWNER role (`assign_member`
and `create_invitation` refuse `role=OWNER`); it cannot be delegated
to ADMIN.
"""

# -----------------------------------------------------------------------------
# Permission vocabulary, partitioned by scope (v1.3.0+)
# -----------------------------------------------------------------------------

from typing import Final, Literal  # noqa: E402

SELF_PERMISSIONS: Final[tuple[str, ...]] = (
    "mercury:user:read:self",
    "mercury:user:write:self",
    "helios:tenant:switch:self",
)

PLATFORM_PERMISSIONS: Final[tuple[str, ...]] = (
    "athens:project:view",
    "athens:project:update",
    "athens:project:delete",
    "athens:services:enable",
    "athens:services:disable",
    "athens:team:invite",
    "athens:team:remove",
    "mercury:users:read",
    "mercury:users:write",
    "mercury:api_keys:manage",
    "muse:blog:create",
    "muse:blog:read",
    "muse:author:create",
    "muse:author:delete",
    "helios:tenant:transfer",
    "helios:members:view",
    "helios:members:invite",
    "helios:members:remove",
    "helios:roles:assign",
    "helios:roles:revoke",
    "helios:invitations:create",
    "helios:invitations:revoke",
    "helios:external:register",
    "helios:external:revoke",
    "helios:external:view",
)

PROJECT_PERMISSIONS: Final[tuple[str, ...]] = (
    "muse:posts:read",
    "muse:posts:write",
    "muse:posts:delete",
    "muse:drafts:read",
    "muse:drafts:write",
)

DUAL_PERMISSIONS: Final[tuple[str, ...]] = (
    "muse:author:read",
)

# The full set of valid permission strings in the system.
# Use Literal[...] at type-check time for closed-union typo detection.
SelfPermission = Literal[
    "mercury:user:read:self",
    "mercury:user:write:self",
    "helios:tenant:switch:self",
]
PlatformPermission = Literal[
    "athens:project:view",
    "athens:project:update",
    "athens:project:delete",
    "athens:services:enable",
    "athens:services:disable",
    "athens:team:invite",
    "athens:team:remove",
    "mercury:users:read",
    "mercury:users:write",
    "mercury:api_keys:manage",
    "muse:blog:create",
    "muse:blog:read",
    "muse:author:create",
    "muse:author:delete",
    "helios:tenant:transfer",
    "helios:members:view",
    "helios:members:invite",
    "helios:members:remove",
    "helios:roles:assign",
    "helios:roles:revoke",
    "helios:invitations:create",
    "helios:invitations:revoke",
    "helios:external:register",
    "helios:external:revoke",
    "helios:external:view",
]
ProjectPermission = Literal[
    "muse:posts:read",
    "muse:posts:write",
    "muse:posts:delete",
    "muse:drafts:read",
    "muse:drafts:write",
]
DualPermission = Literal["muse:author:read"]
Permission = Literal[SelfPermission | PlatformPermission | ProjectPermission | DualPermission]

# Mirrors the contract's `scope` enum. Four valid values.
PermScope = Literal["self", "platform", "project", "platform/project"]

# Perm → scope lookup, populated at module load. The two-track resolver in
# Helios checks `PERM_SCOPE[perm]` to decide which path (platform-user vs
# tenant-user) is valid for the perm.
PERM_SCOPE: Final[dict[str, PermScope]] = {
    "mercury:user:read:self": "self",
    "mercury:user:write:self": "self",
    "helios:tenant:switch:self": "self",
    "athens:project:view": "platform",
    "athens:project:update": "platform",
    "athens:project:delete": "platform",
    "athens:services:enable": "platform",
    "athens:services:disable": "platform",
    "athens:team:invite": "platform",
    "athens:team:remove": "platform",
    "mercury:users:read": "platform",
    "mercury:users:write": "platform",
    "mercury:api_keys:manage": "platform",
    "muse:blog:create": "platform",
    "muse:blog:read": "platform",
    "muse:author:create": "platform",
    "muse:author:delete": "platform",
    "helios:tenant:transfer": "platform",
    "helios:members:view": "platform",
    "helios:members:invite": "platform",
    "helios:members:remove": "platform",
    "helios:roles:assign": "platform",
    "helios:roles:revoke": "platform",
    "helios:invitations:create": "platform",
    "helios:invitations:revoke": "platform",
    "helios:external:register": "platform",
    "helios:external:revoke": "platform",
    "helios:external:view": "platform",
    "muse:posts:read": "project",
    "muse:posts:write": "project",
    "muse:posts:delete": "project",
    "muse:drafts:read": "project",
    "muse:drafts:write": "project",
    "muse:author:read": "platform/project",
}

# The closed set of roles. Mirrors `RoleType` in Helios's Prisma schema.
ROLES: Final[tuple[str, ...]] = ("OWNER", "ADMIN", "EDITOR", "VIEWER")
Role = Literal["OWNER", "ADMIN", "EDITOR", "VIEWER"]


# -----------------------------------------------------------------------------
# Role → Permission map
# -----------------------------------------------------------------------------

# ROLE_PERMISSIONS only contains `platform` and `platform/project` perms;
# `self` perms are universal (granted by the resolver's Step 1) and
# `project` perms are for tenant users via TenantRole.
ROLE_PERMISSIONS: Final[dict[str, tuple[str, ...]]] = {
    "OWNER": (
        "athens:project:view",
        "athens:project:update",
        "athens:project:delete",
        "athens:services:enable",
        "athens:services:disable",
        "athens:team:invite",
        "athens:team:remove",
        "mercury:users:read",
        "mercury:users:write",
        "mercury:api_keys:manage",
        "muse:blog:create",
        "muse:blog:read",
        "muse:author:create",
        "muse:author:read",
        "muse:author:delete",
        "helios:tenant:transfer",
        "helios:members:view",
        "helios:members:invite",
        "helios:members:remove",
        "helios:roles:assign",
        "helios:roles:revoke",
        "helios:invitations:create",
        "helios:invitations:revoke",
        "helios:external:register",
        "helios:external:revoke",
        "helios:external:view",
    ),
    "ADMIN": (
        "athens:project:view",
        "athens:project:update",
        "athens:services:enable",
        "athens:services:disable",
        "athens:team:invite",
        "athens:team:remove",
        "mercury:users:read",
        "mercury:users:write",
        "mercury:api_keys:manage",
        "muse:blog:create",
        "muse:blog:read",
        "muse:author:create",
        "muse:author:read",
        "helios:members:view",
        "helios:members:invite",
        "helios:members:remove",
        "helios:roles:assign",
        "helios:roles:revoke",
        "helios:invitations:create",
        "helios:invitations:revoke",
        "helios:external:view",
    ),
    "EDITOR": (
        "athens:project:view",
        "mercury:users:read",
        "muse:blog:create",
        "muse:blog:read",
        "muse:author:create",
        "muse:author:read",
    ),
    "VIEWER": (
        "athens:project:view",
        "mercury:users:read",
        "muse:blog:read",
        "muse:author:read",
    ),
}


def resolve_permissions(role: str) -> tuple[str, ...]:
    """Return the read-only permission tuple for a role.

    Spread it (`list(resolve_permissions(role))`) if you need a mutable
    copy.
    """
    return ROLE_PERMISSIONS[role]


def role_has_permission(role: str, perm: str) -> bool:
    """`True` if `role` is granted `perm`.

    Convenience wrapper around `ROLE_PERMISSIONS[role]`. Used by Helios's
    `PermissionResolverService` when resolving per-tenant membership rows.
    """
    return perm in ROLE_PERMISSIONS[role]


def is_self_scope(perm: str) -> bool:
    """`True` if `perm` has scope `self` (universal — granted without
    any role lookup). Used by the resolver's Step 1.
    """
    return PERM_SCOPE.get(perm) == "self"


def is_platform_grantable(perm: str) -> bool:
    """`True` if `perm` is grantable via the platform-user path (scope
    is `platform` or `platform/project`).
    """
    s = PERM_SCOPE.get(perm)
    return s == "platform" or s == "platform/project"


def is_tenant_grantable(perm: str) -> bool:
    """`True` if `perm` is grantable via the tenant-user path (scope is
    `project` or `platform/project`, OR scope is unknown — tenant-defined
    perms are always grantable via TenantRole).
    """
    if perm not in PERM_SCOPE:
        return True  # tenant-defined perm
    s = PERM_SCOPE[perm]
    return s == "project" or s == "platform/project"


def is_permission(value: object) -> bool:
    """Type guard — `True` if `value` is a known Permission string.

    Use at trust boundaries (HTTP request bodies, Kafka payloads) where
    the perm may be an arbitrary string and we want to reject unknowns
    rather than silently return `False`.
    """
    if not isinstance(value, str):
        return False
    return value in PERM_SCOPE


def is_role(value: object) -> bool:
    """Type guard — `True` if `value` is a known Role string."""
    return isinstance(value, str) and value in ROLES

