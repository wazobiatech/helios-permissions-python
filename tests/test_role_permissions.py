"""Pure unit tests for the canonical role → permission map.

No mocks. These are the most important tests in the SDK — every other
service depends on this map being correct.
"""

from helios_permissions import (
    ROLE_PERMISSIONS,
    ROLES,
    is_permission,
    is_role,
    resolve_permissions,
    role_has_permission,
)


def test_owner_gets_every_permission_in_every_service():
    owner_perms = ROLE_PERMISSIONS["OWNER"]
    assert "athens:project:delete" in owner_perms
    assert "athens:services:enable" in owner_perms
    assert "mercury:users:write" in owner_perms
    assert "mercury:api_keys:manage" in owner_perms
    assert "muse:posts:delete" in owner_perms
    assert "helios:tenant:transfer" in owner_perms


def test_admin_gets_everything_except_destructive_deletes_and_ownership_transfer():
    admin_perms = ROLE_PERMISSIONS["ADMIN"]
    assert "athens:project:update" in admin_perms
    assert "athens:project:view" in admin_perms
    assert "athens:project:delete" not in admin_perms
    assert "muse:posts:write" in admin_perms
    assert "muse:posts:delete" not in admin_perms
    assert "helios:tenant:transfer" not in admin_perms
    # Switch is a navigation gesture, available to every role.
    assert "helios:tenant:switch" in admin_perms


def test_editor_gets_read_write_on_content_services_no_team_mgmt():
    editor_perms = ROLE_PERMISSIONS["EDITOR"]
    assert "muse:posts:read" in editor_perms
    assert "muse:posts:write" in editor_perms
    assert "muse:drafts:write" in editor_perms
    assert "muse:posts:delete" not in editor_perms
    assert "athens:project:update" not in editor_perms
    assert "helios:members:invite" not in editor_perms
    assert "helios:tenant:transfer" not in editor_perms


def test_viewer_gets_read_only_across_services():
    viewer_perms = ROLE_PERMISSIONS["VIEWER"]
    assert "athens:project:view" in viewer_perms
    assert "mercury:users:read" in viewer_perms
    assert "muse:posts:read" in viewer_perms
    assert "muse:posts:write" not in viewer_perms
    assert "muse:drafts:write" not in viewer_perms
    assert "mercury:users:write" not in viewer_perms
    assert "helios:members:invite" not in viewer_perms


def test_includes_every_role_in_the_record():
    assert ROLES == ("OWNER", "ADMIN", "EDITOR", "VIEWER")
    for role in ROLES:
        assert isinstance(ROLE_PERMISSIONS[role], tuple)


def test_perms_are_sorted_to_be_a_superset():
    """OWNER ⊇ ADMIN ⊇ EDITOR ⊇ VIEWER on common entries."""
    owner = set(ROLE_PERMISSIONS["OWNER"])
    admin = set(ROLE_PERMISSIONS["ADMIN"])
    editor = set(ROLE_PERMISSIONS["EDITOR"])
    viewer = set(ROLE_PERMISSIONS["VIEWER"])

    # Every editor perm is in admin (admin ⊇ editor).
    for p in editor:
        assert p in admin
    # Every viewer perm is in editor (editor ⊇ viewer).
    for p in viewer:
        assert p in editor
    # Every admin perm is in owner (owner ⊇ admin).
    for p in admin:
        assert p in owner


def test_resolve_permissions_returns_the_perms_for_a_role():
    assert "helios:tenant:transfer" in resolve_permissions("OWNER")
    assert "helios:tenant:transfer" not in resolve_permissions("VIEWER")


def test_role_has_permission_returns_true_when_granted():
    assert role_has_permission("OWNER", "helios:tenant:transfer") is True
    assert role_has_permission("ADMIN", "helios:members:invite") is True


def test_role_has_permission_returns_false_when_lacking():
    assert role_has_permission("VIEWER", "helios:tenant:transfer") is False
    assert role_has_permission("EDITOR", "muse:posts:delete") is False


def test_is_permission_accepts_valid_perm_strings():
    assert is_permission("helios:members:view") is True
    assert is_permission("athens:project:delete") is True


def test_is_permission_rejects_invalid_strings():
    assert is_permission("helios:made_up:perm") is False
    assert is_permission("") is False
    assert is_permission(None) is False
    assert is_permission(42) is False


def test_is_role_accepts_valid_role_strings():
    assert is_role("OWNER") is True
    assert is_role("VIEWER") is True


def test_is_role_rejects_invalid_strings():
    assert is_role("SUPERADMIN") is False
    assert is_role("") is False
    assert is_role(None) is False


def test_every_role_maps_to_a_non_empty_perm_array():
    for role in ROLES:
        assert len(ROLE_PERMISSIONS[role]) > 0
