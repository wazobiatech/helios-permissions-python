"""wazobiatech-helios-permissions — public API barrel.

Re-exports the canonical role → permission map (the platform source of
truth), the :class:`PermissionClient` (the authz decision surface), the
cache abstractions, and the Helios client.

Importers::

    # Hot-path authz decision in any service:
    from helios_permissions import PermissionClient
    granted = await perms.caller_has_permission(user_id, tenant_id, "helios:members:update")

    # Pure data — used by Helios itself to compute perms from roles:
    from helios_permissions import ROLE_PERMISSIONS, resolve_permissions
"""

from .cache import (
    DEFAULT_CACHE_TTL_SECONDS,
    InMemoryPermissionCache,
    PermissionCache,
    RedisPermissionCache,
)
from .factory import Closer, create_permission_client
from .helios import (
    HELIOS_HMAC_WINDOW_SECONDS,
    HeliosClient,
    HeliosMembershipResolution,
    HeliosUnreachableError,
)
from .logger import Logger, console_logger, silent_logger
from .permission_client import PermissionClient, PermissionExplanation
from .role_permissions import (
    DUAL_PERMISSIONS,
    PERM_SCOPE,
    PLATFORM_PERMISSIONS,
    PROJECT_PERMISSIONS,
    ROLE_PERMISSIONS,
    ROLES,
    SELF_PERMISSIONS,
    DualPermission,
    Permission,
    PermScope,
    PlatformPermission,
    ProjectPermission,
    Role,
    SelfPermission,
    is_permission,
    is_platform_grantable,
    is_role,
    is_self_scope,
    is_tenant_grantable,
    resolve_permissions,
    role_has_permission,
)

__version__ = "0.5.0"

__all__ = [
    # Version
    "__version__",
    # Role / permission map
    "ROLE_PERMISSIONS",
    "ROLES",
    "Permission",
    "Role",
    "resolve_permissions",
    "role_has_permission",
    "is_permission",
    "is_role",
    # v1.3.0 — 4-scope model
    "PERM_SCOPE",
    "PermScope",
    "SELF_PERMISSIONS",
    "PLATFORM_PERMISSIONS",
    "PROJECT_PERMISSIONS",
    "DUAL_PERMISSIONS",
    "SelfPermission",
    "PlatformPermission",
    "ProjectPermission",
    "DualPermission",
    "is_self_scope",
    "is_platform_grantable",
    "is_tenant_grantable",
    # Client
    "PermissionClient",
    "PermissionExplanation",
    "create_permission_client",
    "Closer",
    # Cache
    "PermissionCache",
    "InMemoryPermissionCache",
    "RedisPermissionCache",
    "DEFAULT_CACHE_TTL_SECONDS",
    # Helios
    "HeliosClient",
    "HeliosUnreachableError",
    "HeliosMembershipResolution",
    "HELIOS_HMAC_WINDOW_SECONDS",
    # Logger
    "Logger",
    "silent_logger",
    "console_logger",
]
