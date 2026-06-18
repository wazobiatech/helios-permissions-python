"""HeliosClient — HMAC-signed GET to Helios's permission endpoint.

Helios exposes::

    GET /internal/users/:userId/permissions?tenantId=<uuid>
    Headers: x-project-token, x-source-service, x-signature, x-timestamp
    Window: 300 seconds (per Helios CLAUDE.md — 300s HMAC for the user
             endpoints, vs 30s for the events endpoint)

Response shape (matches Helios's ``PermissionResolverService``)::

    {"status": "active", "role": "OWNER", "permissions": ["helios:...", ...]}
    {"status": "inactive", "role": "OWNER"}                          # expired
    {"status": "not_a_member"}

The SDK translates this into a ``list[Permission]`` (empty for
non-members or inactive memberships — the service-layer
``caller_has_permission`` then returns ``False`` for any perm against
an empty array).
"""

from .client import (
    HELIOS_HMAC_WINDOW_SECONDS,
    HeliosClient,
    HeliosMembershipResolution,
    HeliosUnreachableError,
)

__all__ = [
    "HELIOS_HMAC_WINDOW_SECONDS",
    "HeliosClient",
    "HeliosMembershipResolution",
    "HeliosUnreachableError",
]
