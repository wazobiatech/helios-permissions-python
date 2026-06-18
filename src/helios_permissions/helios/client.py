"""HeliosClient — async HMAC-signed GET to Helios's permission endpoint.

We implement the signing here directly (instead of pulling in
``wazobiatech-nexus-mcp``) to keep the SDK's dependency surface minimal.
The signing logic is a few lines of stdlib code; coupling to the HTTP
middleware library would be overkill for a single GET.

HMAC payload (per wazobiatech/nexus-mcp-contract)::

    payload = METHOD.upper() + fullPath + timestamp
    digest  = HMAC-SHA256(secret_utf8, payload_utf8), lowercase hex
    reject if |now - timestamp| > 300s
"""

from __future__ import annotations

import hashlib
import hmac
import time
import uuid
from collections.abc import Awaitable, Callable
from typing import Any
from urllib.parse import quote

import httpx

from ..role_permissions import Permission

#: HMAC validity window (seconds). Matches the contract: 300s for the
#: user endpoints (vs 30s for the events endpoint).
HELIOS_HMAC_WINDOW_SECONDS = 300


class HeliosUnreachableError(Exception):
    """Raised when the Helios request fails and the caller doesn't want stale-on-error."""

    def __init__(self, message: str, cause: Any = None) -> None:
        super().__init__(message)
        self.cause = cause
        self.name = "HeliosUnreachableError"


# Discriminated union: ``status`` is the discriminator.
HeliosMembershipResolution = (
    "HeliosMembershipResolution"  # forward-declared as a TypeAlias below
)


from typing import TypedDict  # noqa: E402


class HeliosActiveResolution(TypedDict):
    status: str  # "active"
    role: str
    permissions: list[Permission]


class HeliosInactiveResolution(TypedDict):
    status: str  # "inactive"
    role: str


class HeliosNotMemberResolution(TypedDict):
    status: str  # "not_a_member"


HeliosMembershipResolution = (
    HeliosActiveResolution | HeliosInactiveResolution | HeliosNotMemberResolution
)


# Default async fetch implementation. Overridable for tests.
_DefaultFetch = Callable[[str, dict[str, Any]], Awaitable[httpx.Response]]


class HeliosClient:
    """Async HMAC-signed client for Helios's permission endpoint."""

    def __init__(
        self,
        base_url: str,
        hmac_secret: str,
        project_token: str,
        *,
        source_service: str = "helios-permissions-sdk",
        fetch_timeout_ms: int = 2000,
        fetch_impl: _DefaultFetch | None = None,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        # Strip trailing slash to avoid double-slash in URL composition.
        self._base_url = base_url.rstrip("/")
        self._hmac_secret = hmac_secret
        self._project_token = project_token
        self._source_service = source_service
        self._fetch_timeout_ms = fetch_timeout_ms
        self._owns_client = client is None and fetch_impl is None
        self._client = client or httpx.AsyncClient(
            timeout=httpx.Timeout(fetch_timeout_ms / 1000.0)
        )
        self._fetch_impl = fetch_impl or self._default_fetch

    async def aclose(self) -> None:
        """Close the underlying httpx client if we created it."""
        if self._owns_client:
            await self._client.aclose()

    async def __aenter__(self) -> HeliosClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    async def _default_fetch(self, url: str, kwargs: dict[str, Any]) -> httpx.Response:
        return await self._client.get(url, **kwargs)

    def _sign(self, method: str, full_path: str, timestamp: str) -> str:
        """Compute the HMAC-SHA256 signature per the contract.

        Payload: ``METHOD.upper() + fullPath + timestamp`` (fullPath
        includes query string). Lowercase hex output.
        """
        payload = f"{method.upper()}{full_path}{timestamp}".encode()
        return hmac.new(
            self._hmac_secret.encode("utf-8"), payload, hashlib.sha256
        ).hexdigest()

    async def fetch_user_permissions(
        self, user_id: str, tenant_id: str
    ) -> HeliosMembershipResolution:
        """Fetch the resolved permission set for ``(user_id, tenant_id)``.

        Returns the discriminated union from Helios; the ``PermissionClient``
        translates ``not_a_member`` and ``inactive`` into empty arrays.

        Raises :class:`HeliosUnreachableError` on network failure, timeout,
        or non-2xx response (other than 404, which means ``not_a_member``).
        """
        path = (
            f"/internal/users/{quote(user_id, safe='')}/permissions"
            f"?tenantId={quote(tenant_id, safe='')}"
        )
        url = f"{self._base_url}{path}"
        timestamp = str(int(time.time()))

        signature = self._sign("GET", path, timestamp)

        headers = {
            "x-project-token": self._project_token,
            "x-source-service": self._source_service,
            "x-signature": signature,
            "x-timestamp": timestamp,
            "x-correlation-id": str(uuid.uuid4()),
            "accept": "application/json",
        }

        try:
            response = await self._fetch_impl(url, {"headers": headers})
        except Exception as err:  # noqa: BLE001
            raise HeliosUnreachableError(
                f"HeliosClient.fetch_user_permissions: network error for "
                f"({user_id}, {tenant_id})",
                cause=err,
            ) from err

        # Normalize response shape: tests inject a Response-like object.
        status_code = getattr(response, "status_code", None)
        if status_code is None:
            status_code = response.status  # type: ignore[union-attr]

        if status_code == 404:
            # 404 means the row doesn't exist — treat as not_a_member.
            return HeliosNotMemberResolution(status="not_a_member")

        if status_code < 200 or status_code >= 300:
            raise HeliosUnreachableError(
                f"HeliosClient.fetch_user_permissions: HTTP {status_code} for "
                f"({user_id}, {tenant_id})",
                cause=None,
            )

        # ``response.json()`` is the standard httpx shape. Allow test doubles
        # that expose ``.json()`` as an async or sync method.
        body_raw = response.json()
        if hasattr(body_raw, "__await__"):
            body = await body_raw  # type: ignore[func-returns-value]
        else:
            body = body_raw
        return body  # type: ignore[return-value]
