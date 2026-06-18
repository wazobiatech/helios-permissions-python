"""HeliosClient — exercise the HMAC signing + fetch path.

The signing logic is the cross-SDK contract (matches nexus-mcp's
HMAC-SHA256 payload = METHOD.upper() + path + timestamp). We test the
signature shape and the request headers — the actual HTTP behavior is
mocked via ``fetch_impl`` injection.
"""

import hashlib
import hmac
from typing import Any

import pytest
from helios_permissions import (
    HeliosClient,
    HeliosUnreachableError,
)

# --- Mock response ---------------------------------------------------------


class _MockResponse:
    """Minimal httpx.Response-shaped double for tests."""

    def __init__(self, status_code: int, body: Any = None) -> None:
        self.status_code = status_code
        self._body = body

    def json(self) -> Any:
        return self._body


def _make_client(
    response: _MockResponse,
    *,
    base_url: str = "https://helios.internal",
    secret: str = "secret",
    project_token: str = "pt",
) -> tuple[HeliosClient, dict[str, Any]]:
    captured: dict[str, Any] = {}

    async def mock_fetch(url: str, kwargs: dict[str, Any]) -> _MockResponse:
        captured["url"] = url
        captured["headers"] = kwargs["headers"]
        return response

    client = HeliosClient(
        base_url=base_url,
        hmac_secret=secret,
        project_token=project_token,
        fetch_impl=mock_fetch,
    )
    return client, captured


# --- HMAC signing ----------------------------------------------------------


async def test_signs_method_upper_path_timestamp_with_hmac_sha256_lowercase_hex() -> None:
    """Recompute the expected signature from the captured URL + timestamp."""
    secret = "super-secret-key"
    body = {
        "status": "active",
        "role": "OWNER",
        "permissions": ["helios:tenant:transfer"],
    }
    client, captured = _make_client(_MockResponse(200, body), secret=secret)

    await client.fetch_user_permissions("u-1", "t-1")

    timestamp = captured["headers"]["x-timestamp"]
    signature = captured["headers"]["x-signature"]
    signed_path = captured["url"].replace("https://helios.internal", "")

    expected = hmac.new(
        secret.encode("utf-8"),
        f"GET{signed_path}{timestamp}".encode(),
        hashlib.sha256,
    ).hexdigest()

    assert signature == expected
    # Lowercase hex, 64 chars (SHA-256).
    assert signature == expected.lower()
    assert len(signature) == 64


async def test_sets_required_headers() -> None:
    client, captured = _make_client(
        _MockResponse(200, {"status": "not_a_member"}),
    )

    await client.fetch_user_permissions("u-1", "t-1")

    headers = captured["headers"]
    assert headers["x-source-service"] == "helios-permissions-sdk"
    assert headers["x-project-token"] == "pt"
    assert headers["x-correlation-id"]


# --- Response handling -----------------------------------------------------


async def test_translates_404_to_not_a_member() -> None:
    client, _ = _make_client(_MockResponse(404))
    result = await client.fetch_user_permissions("u-1", "t-1")
    assert result == {"status": "not_a_member"}


async def test_passes_through_active_resolution() -> None:
    body = {
        "status": "active",
        "role": "OWNER",
        "permissions": ["helios:tenant:transfer"],
    }
    client, _ = _make_client(_MockResponse(200, body))
    result = await client.fetch_user_permissions("u-1", "t-1")
    assert result["status"] == "active"


async def test_passes_through_inactive_resolution() -> None:
    client, _ = _make_client(
        _MockResponse(200, {"status": "inactive", "role": "VIEWER"}),
    )
    result = await client.fetch_user_permissions("u-1", "t-1")
    assert result["status"] == "inactive"


async def test_raises_helios_unreachable_error_on_500() -> None:
    client, _ = _make_client(_MockResponse(500))
    with pytest.raises(HeliosUnreachableError):
        await client.fetch_user_permissions("u-1", "t-1")


async def test_raises_helios_unreachable_error_on_network_error() -> None:
    async def mock_fetch(url: str, kwargs: dict[str, Any]) -> _MockResponse:
        raise RuntimeError("network error")

    client = HeliosClient(
        base_url="https://helios.internal",
        hmac_secret="secret",
        project_token="pt",
        fetch_impl=mock_fetch,
    )
    with pytest.raises(HeliosUnreachableError):
        await client.fetch_user_permissions("u-1", "t-1")


async def test_encodes_user_id_and_tenant_id_in_the_path() -> None:
    client, captured = _make_client(
        _MockResponse(200, {"status": "not_a_member"}),
    )
    await client.fetch_user_permissions("user/with/slashes", "tenant with spaces")
    assert "user%2Fwith%2Fslashes" in captured["url"]
    assert "tenant%20with%20spaces" in captured["url"]
