"""helios-permissions — Role → Permission map and helpers.

Canonical source of truth for the platform. Generated from the
language-agnostic JSON contract at `wazobiatech/permission-contract`
v1.0.0 (generated 2026-06-18). Do NOT edit by hand — edit the
contract's `permissions.json` and re-run codegen.

The Helios service imports this module via the published package; Helios
does NOT redefine the map. TS / Python / Go / Laravel SDKs that read the
same JSON contract agree on what OWNER / ADMIN / EDITOR / VIEWER means.

Permission naming convention: `{service}:{resource}:{action}`.

  - service  — one of: athens, mercury, muse, helios
  - resource — domain noun (project, users, posts, members, ...)
  - action   — verb (view, write, delete, manage, ...)

ZIN-4714 — `helios:tenant:transfer` is OWNER-only by design. Ownership
transfer is the single entry point to the OWNER role (`assign_member`
and `create_invitation` refuse `role=OWNER`); it cannot be delegated
to ADMIN.
"""

# -----------------------------------------------------------------------------
# Permission vocabulary
# -----------------------------------------------------------------------------

ATHENS_PERMISSIONS: tuple[str, ...] = (
    "athens:project:view",
    "athens:project:update",
    "athens:project:delete",
    "athens:services:enable",
    "athens:services:disable",
    "athens:team:invite",
    "athens:team:remove",
)

MERCURY_PERMISSIONS: tuple[str, ...] = (
    "mercury:users:read",
    "mercury:users:write",
    "mercury:api_keys:manage",
    "mercury:connections:read",
)

MUSE_PERMISSIONS: tuple[str, ...] = (
    "muse:posts:read",
    "muse:posts:write",
    "muse:posts:delete",
    "muse:drafts:read",
    "muse:drafts:write",
)

HELIOS_PERMISSIONS: tuple[str, ...] = (
    "helios:members:view",
    "helios:members:invite",
    "helios:members:remove",
    "helios:roles:assign",
    "helios:roles:revoke",
    "helios:invitations:create",
    "helios:invitations:revoke",
    "helios:tenant:switch",
    "helios:tenant:transfer",
)

# The full set of valid permission strings in the system.
# Use Literal[...] at type-check time for closed-union typo detection.
from typing import Final, Literal  # noqa: E402

Permission = Literal[
    # Athens
    "athens:project:view",
    "athens:project:update",
    "athens:project:delete",
    "athens:services:enable",
    "athens:services:disable",
    "athens:team:invite",
    "athens:team:remove",
    # Mercury
    "mercury:users:read",
    "mercury:users:write",
    "mercury:api_keys:manage",
    "mercury:connections:read",
    # Muse
    "muse:posts:read",
    "muse:posts:write",
    "muse:posts:delete",
    "muse:drafts:read",
    "muse:drafts:write",
    # Helios
    "helios:members:view",
    "helios:members:invite",
    "helios:members:remove",
    "helios:roles:assign",
    "helios:roles:revoke",
    "helios:invitations:create",
    "helios:invitations:revoke",
    "helios:tenant:switch",
    "helios:tenant:transfer",
]

# The closed set of roles. Mirrors `RoleType` in Helios's Prisma schema.
ROLES: Final[tuple[str, ...]] = ("OWNER", "ADMIN", "EDITOR", "VIEWER")
Role = Literal["OWNER", "ADMIN", "EDITOR", "VIEWER"]


# -----------------------------------------------------------------------------
# Role → Permission map
# -----------------------------------------------------------------------------

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
        "mercury:connections:read",
        "muse:posts:read",
        "muse:posts:write",
        "muse:posts:delete",
        "muse:drafts:read",
        "muse:drafts:write",
        "helios:members:view",
        "helios:members:invite",
        "helios:members:remove",
        "helios:roles:assign",
        "helios:roles:revoke",
        "helios:invitations:create",
        "helios:invitations:revoke",
        "helios:tenant:switch",
        "helios:tenant:transfer",
    ),
    "ADMIN": (
        "athens:project:view",
        "athens:project:update",
        "athens:services:enable",
        "athens:services:disable",
        "athens:team:invite",
        "mercury:users:read",
        "mercury:users:write",
        "mercury:api_keys:manage",
        "mercury:connections:read",
        "muse:posts:read",
        "muse:posts:write",
        "muse:drafts:read",
        "muse:drafts:write",
        "helios:members:view",
        "helios:members:invite",
        "helios:members:remove",
        "helios:roles:assign",
        "helios:roles:revoke",
        "helios:invitations:create",
        "helios:invitations:revoke",
        "helios:tenant:switch",
    ),
    "EDITOR": (
        "athens:project:view",
        "mercury:users:read",
        "mercury:connections:read",
        "muse:posts:read",
        "muse:posts:write",
        "muse:drafts:read",
        "muse:drafts:write",
        "helios:members:view",
        "helios:tenant:switch",
    ),
    "VIEWER": (
        "athens:project:view",
        "mercury:users:read",
        "mercury:connections:read",
        "muse:posts:read",
        "muse:drafts:read",
        "helios:members:view",
        "helios:tenant:switch",
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


def is_permission(value: object) -> bool:
    """Type guard — `True` if `value` is a known Permission string.

    Use at trust boundaries (HTTP request bodies, Kafka payloads) where
    the perm may be an arbitrary string and we want to reject unknowns
    rather than silently return `False`.
    """
    if not isinstance(value, str):
        return False
    return (
        value in ATHENS_PERMISSIONS or
        value in MERCURY_PERMISSIONS or
        value in MUSE_PERMISSIONS or
        value in HELIOS_PERMISSIONS
    )


def is_role(value: object) -> bool:
    """Type guard — `True` if `value` is a known Role string."""
    return isinstance(value, str) and value in ROLES

