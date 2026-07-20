#!/usr/bin/env python3
# =============================================================================
# wazobiatech-helios-permissions — codegen for role_permissions.py.
#
# Fetches the canonical permission contract from
#   github.com/wazobiatech/permission-contract (public mirror)
# and emits src/helios_permissions/role_permissions.py. The emitted file is
# the source of truth in the SDK — there is NO runtime JSON parsing.
#
# Why codegen, not runtime loading:
#   The SDK exposes a closed `Permission = Literal[...]` type for
#   type-checker typo detection. Codegen keeps that. Runtime loading
#   would make every perm a `str`, losing the closed union.
#
# Contract version is pinned by PERMISSION_CONTRACT_VERSION (env var)
# so SDK releases don't silently drift when the contract bumps.
#
# Usage:
#   PERMISSION_CONTRACT_VERSION=v1.7.0 python scripts/codegen-permissions.py
#   # default version: v1.7.0
#
# Network failure is fatal — there is no fallback to a checked-in
# permissions.json. The contract is the single source of truth; an
# offline build that uses a stale contract would defeat the purpose.
# =============================================================================

from __future__ import annotations

import json
import os
import subprocess
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GENERATED_FILE = ROOT / "src" / "helios_permissions" / "role_permissions.py"
CODEGEN_SCRIPT = ROOT / "scripts" / "codegen-py.mjs"
CONTRACT_VERSION = os.environ.get("PERMISSION_CONTRACT_VERSION", "v1.7.0")
CONTRACT_URL = (
    f"https://raw.githubusercontent.com/wazobiatech/permission-contract/"
    f"{CONTRACT_VERSION}/permissions.json"
)


def log(msg: str) -> None:
    print(f"[codegen] {msg}")


def fail(msg: str) -> None:
    print(f"[codegen] FATAL: {msg}", file=sys.stderr)
    sys.exit(1)


def fetch_contract_json() -> dict:
    """Fetch the contract JSON from the public GitHub mirror."""
    log(f"fetching {CONTRACT_URL}")
    try:
        with urllib.request.urlopen(CONTRACT_URL) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception as exc:
        fail(f"contract fetch failed: {exc}")


def validate_contract_in_memory(contract: dict) -> None:
    """Lightweight re-validation so a malformed contract can't silently
    produce broken code. Mirrors the script's invariants — keep in sync
    if validate.mjs in the contract repo gains new checks.
    """
    if "version" not in contract:
        fail("contract missing version")
    services = contract.get("services")
    roles = contract.get("roles")
    permissions = contract.get("permissions")
    role_permissions = contract.get("role_permissions")
    if not isinstance(services, list):
        fail("contract missing services[]")
    if not isinstance(roles, list):
        fail("contract missing roles[]")
    if not isinstance(permissions, dict):
        fail("contract missing permissions{}")
    if not isinstance(role_permissions, dict):
        fail("contract missing role_permissions{}")

    flat: dict[str, str] = {}  # name → scope
    valid_scopes = {"self", "platform", "project", "platform/project"}
    for service, perms in permissions.items():
        if not isinstance(perms, list):
            fail(f"permissions[{service}] is not an array")
        for p in perms:
            if isinstance(p, str):
                fail(
                    f"permissions[{service}] contains a bare string perm "
                    f'"{p}" — v1.4.0 requires {{name, scope}} objects'
                )
            if not isinstance(p, dict) or not isinstance(p.get("name"), str):
                fail(f"permissions[{service}] has a malformed perm: {p!r}")
            name = p["name"]
            scope = p.get("scope")
            if scope not in valid_scopes:
                fail(f'perm "{name}" has invalid scope "{scope}"')
            if scope == "self" and not name.endswith(":self"):
                fail(f'perm "{name}" has scope "self" but is missing the ":self" suffix')
            if name.endswith(":self") and scope != "self":
                fail(f'perm "{name}" ends with ":self" but scope is "{scope}" (must be "self")')
            flat[name] = scope

    for role, defn in role_permissions.items():
        perms = defn.get("permissions", [])
        for perm in perms:
            if perm not in flat:
                fail(f'role "{role}" references unknown perm "{perm}"')
            if flat[perm] == "self":
                fail(
                    f'role "{role}" contains self-scope perm "{perm}" '
                    "— self perms are universal and must not be in any role"
                )
            if flat[perm] == "project":
                fail(
                    f'role "{role}" contains project-scope perm "{perm}" '
                    "— project perms are tenant-user only and must not be in any role"
                )
        if role != "OWNER" and "helios:tenant:transfer" in perms:
            fail(f'role "{role}" has OWNER-only perm helios:tenant:transfer')

    # helios:tenant:switch:self must be present and have scope "self"
    SWITCH = "helios:tenant:switch:self"
    if SWITCH not in flat:
        fail(f'required perm "{SWITCH}" is missing from permissions[service]')
    elif flat[SWITCH] != "self":
        fail(
            f'perm "{SWITCH}" must have scope "self" (universal perm), '
            f'got "{flat[SWITCH]}"'
        )


def run_codegen_py(contract_path: Path) -> str:
    """Invoke the vendored codegen-py.mjs script and capture stdout."""
    result = subprocess.run(
        ["node", str(CODEGEN_SCRIPT), str(contract_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        fail(
            f"codegen-py.mjs exited {result.returncode}\n"
            f"stderr: {result.stderr}"
        )
    return result.stdout


def main() -> None:
    contract = fetch_contract_json()
    validate_contract_in_memory(contract)

    contracts_dir = ROOT / ".contracts"
    contracts_dir.mkdir(parents=True, exist_ok=True)
    contract_path = contracts_dir / f"permissions-{contract['version']}.json"
    contract_path.write_text(json.dumps(contract, indent=2) + "\n")
    log(f"cached contract at {contract_path}")

    generated = run_codegen_py(contract_path)
    GENERATED_FILE.parent.mkdir(parents=True, exist_ok=True)
    GENERATED_FILE.write_text(generated)

    # The vendored codegen-py.mjs emits the contract version as
    # `permission-contract\` v1.x.y (generated ...)`. The marker
    # substring we look for is `v1.x.y (generated` so we match the
    # header that the generator actually produces (backticks around
    # the repo name break a naive `permission-contract v1.x.y` check).
    sentinel = f"v{contract['version']} (generated"
    if sentinel not in generated:
        fail(
            f"generated source does not reference contract version "
            f"{contract['version']} (looking for substring {sentinel!r})"
        )
    log(f"wrote {GENERATED_FILE}")
    log(
        f"done — src/helios_permissions/role_permissions.py derived from "
        f"permission-contract {contract['version']}"
    )


if __name__ == "__main__":
    main()
