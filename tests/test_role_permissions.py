"""Pure unit tests for the canonical role → permission map.

No mocks. These are the most important tests in the SDK — every other
service depends on this map being correct.

v1.3.0: perms are partitioned by `scope` (self / platform / project /
platform/project). SELF perms are universal (granted by the resolver's
Step 1, not in any role). PROJECT perms are tenant-user only (granted
via TenantRole, not in any role). Only PLATFORM and PLATFORM/PROJECT
perms appear in ROLE_PERMISSIONS.
"""

from helios_permissions import (
    DUAL_PERMISSIONS,
    PERM_SCOPE,
    PLATFORM_PERMISSIONS,
    PROJECT_PERMISSIONS,
    ROLE_PERMISSIONS,
    ROLES,
    SELF_PERMISSIONS,
    is_permission,
    is_platform_grantable,
    is_role,
    is_self_scope,
    is_tenant_grantable,
    resolve_permissions,
    role_has_permission,
)


def test_owner_gets_every_platform_and_dual_scope_perm():
    owner_perms = ROLE_PERMISSIONS["OWNER"]
    # Platform-scope perms
    assert "athens:project:delete" in owner_perms
    assert "athens:services:enable" in owner_perms
    assert "mercury:users:write" in owner_perms
    assert "mercury:api_keys:manage" in owner_perms
    assert "muse:author:delete" in owner_perms
    assert "helios:tenant:transfer" in owner_perms
    # Dual-scope perms (valid in platform-user path too)
    assert "muse:author:read" in owner_perms


def test_admin_gets_everything_except_destructive_deletes_and_ownership_transfer():
    admin_perms = ROLE_PERMISSIONS["ADMIN"]
    assert "athens:project:update" in admin_perms
    assert "athens:project:view" in admin_perms
    assert "athens:project:delete" not in admin_perms
    assert "muse:blog:create" in admin_perms
    assert "muse:author:create" in admin_perms
    assert "muse:author:delete" not in admin_perms
    assert "helios:tenant:transfer" not in admin_perms


def test_editor_gets_platform_user_read_write_on_content_services_no_team_mgmt():
    editor_perms = ROLE_PERMISSIONS["EDITOR"]
    assert "muse:blog:create" in editor_perms
    assert "muse:blog:read" in editor_perms
    assert "muse:author:create" in editor_perms
    assert "muse:author:delete" not in editor_perms
    assert "athens:project:update" not in editor_perms
    assert "helios:members:invite" not in editor_perms
    assert "helios:tenant:transfer" not in editor_perms


def test_viewer_gets_read_only_across_services():
    viewer_perms = ROLE_PERMISSIONS["VIEWER"]
    assert "athens:project:view" in viewer_perms
    assert "mercury:users:read" in viewer_perms
    assert "muse:blog:read" in viewer_perms
    assert "muse:author:read" in viewer_perms
    assert "muse:blog:create" not in viewer_perms
    assert "muse:author:create" not in viewer_perms
    assert "mercury:users:write" not in viewer_perms
    assert "helios:members:invite" not in viewer_perms


def test_role_perms_never_include_self_scope():
    """Self-scope perms are universal — granted by the resolver's Step 1."""
    for role in ROLES:
        for perm in ROLE_PERMISSIONS[role]:
            assert not is_self_scope(perm)


def test_role_perms_never_include_project_scope():
    """Project-scope perms are tenant-user only — granted via TenantRole."""
    for role in ROLES:
        for perm in ROLE_PERMISSIONS[role]:
            assert PERM_SCOPE[perm] != "project"


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

    for p in editor:
        assert p in admin
    for p in viewer:
        assert p in editor
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
    assert role_has_permission("EDITOR", "muse:author:delete") is False


def test_is_permission_accepts_valid_perm_strings():
    assert is_permission("helios:members:view") is True
    assert is_permission("athens:project:delete") is True
    # Self-scope
    assert is_permission("helios:tenant:switch:self") is True
    # Project-scope
    assert is_permission("muse:posts:read") is True


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


# =============================================================================
# v1.3.0 — 4-scope model
# =============================================================================


def test_perm_scope_contains_every_perm_in_the_contract_vocabulary():
    """Every perm in the contract has a scope entry in PERM_SCOPE."""
    # Self-scope
    assert PERM_SCOPE["helios:tenant:switch:self"] == "self"
    assert PERM_SCOPE["mercury:user:read:self"] == "self"
    assert PERM_SCOPE["mercury:user:write:self"] == "self"
    # Platform-scope
    assert PERM_SCOPE["athens:project:view"] == "platform"
    assert PERM_SCOPE["helios:tenant:transfer"] == "platform"
    # Project-scope
    assert PERM_SCOPE["muse:posts:read"] == "project"
    assert PERM_SCOPE["muse:drafts:write"] == "project"
    # Dual-scope
    assert PERM_SCOPE["muse:author:read"] == "platform/project"


def test_perm_scope_only_has_four_valid_values():
    valid = {"self", "platform", "project", "platform/project"}
    for scope in PERM_SCOPE.values():
        assert scope in valid


def test_self_permissions_only_contains_self_scope_perms():
    for p in SELF_PERMISSIONS:
        assert PERM_SCOPE[p] == "self"
    assert "helios:tenant:switch:self" in SELF_PERMISSIONS
    assert "mercury:user:read:self" in SELF_PERMISSIONS


def test_platform_permissions_only_contains_platform_scope_perms():
    for p in PLATFORM_PERMISSIONS:
        assert PERM_SCOPE[p] == "platform"


def test_project_permissions_only_contains_project_scope_perms():
    for p in PROJECT_PERMISSIONS:
        assert PERM_SCOPE[p] == "project"
    assert "muse:posts:read" in PROJECT_PERMISSIONS
    assert "muse:drafts:write" in PROJECT_PERMISSIONS


def test_dual_permissions_only_contains_platform_project_scope_perms():
    for p in DUAL_PERMISSIONS:
        assert PERM_SCOPE[p] == "platform/project"


def test_every_contract_perm_appears_in_exactly_one_tuple():
    """Union of the 4 tuples covers PERM_SCOPE without overlap."""
    all_from_tuples = (
        set(SELF_PERMISSIONS)
        | set(PLATFORM_PERMISSIONS)
        | set(PROJECT_PERMISSIONS)
        | set(DUAL_PERMISSIONS)
    )
    # Every key in PERM_SCOPE is in the tuple union.
    for name in PERM_SCOPE:
        assert name in all_from_tuples
    # The tuple union has no entries outside PERM_SCOPE.
    assert all_from_tuples == set(PERM_SCOPE.keys())


def test_is_self_scope_returns_true_for_self_perms():
    assert is_self_scope("helios:tenant:switch:self") is True
    assert is_self_scope("mercury:user:read:self") is True


def test_is_self_scope_returns_false_for_non_self_perms():
    assert is_self_scope("athens:project:view") is False
    assert is_self_scope("muse:posts:read") is False
    assert is_self_scope("muse:author:read") is False


def test_is_platform_grantable_returns_true_for_platform_perms():
    assert is_platform_grantable("athens:project:view") is True
    assert is_platform_grantable("helios:tenant:transfer") is True


def test_is_platform_grantable_returns_true_for_dual_perms():
    assert is_platform_grantable("muse:author:read") is True


def test_is_platform_grantable_returns_false_for_self_perms():
    assert is_platform_grantable("helios:tenant:switch:self") is False
    assert is_platform_grantable("mercury:user:read:self") is False


def test_is_platform_grantable_returns_false_for_project_perms():
    assert is_platform_grantable("muse:posts:read") is False
    assert is_platform_grantable("muse:drafts:write") is False


def test_is_tenant_grantable_returns_true_for_project_perms():
    assert is_tenant_grantable("muse:posts:read") is True
    assert is_tenant_grantable("muse:posts:delete") is True


def test_is_tenant_grantable_returns_true_for_dual_perms():
    assert is_tenant_grantable("muse:author:read") is True


def test_is_tenant_grantable_returns_false_for_self_perms():
    assert is_tenant_grantable("helios:tenant:switch:self") is False


def test_is_tenant_grantable_returns_false_for_platform_only_perms():
    assert is_tenant_grantable("athens:project:view") is False
    assert is_tenant_grantable("helios:tenant:transfer") is False


def test_is_tenant_grantable_returns_true_for_unknown_perms():
    """Tenant-defined perms (e.g., `inventory:items:read`) are not in the
    contract vocabulary. The resolver treats them as tenant-user-only.
    """
    assert is_tenant_grantable("inventory:items:read") is True
    assert is_tenant_grantable("custom_tenant_perm:foo:bar") is True
