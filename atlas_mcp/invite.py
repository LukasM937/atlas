"""Generate a single-use invite link for onboarding a new tenant.

    python -m atlas_mcp.invite

Prints the link once (not stored anywhere in plaintext) and exits. Requires
ATLAS_ROOT and ATLAS_PUBLIC_URL to be set the same as the running server.
"""

from __future__ import annotations

import os

from .tenants import InviteRegistry

ATLAS_ROOT = os.environ.get("ATLAS_ROOT", "./data")
ATLAS_PUBLIC_URL = os.environ.get("ATLAS_PUBLIC_URL", "").rstrip("/")

if __name__ == "__main__":
    if not ATLAS_PUBLIC_URL:
        raise SystemExit("ATLAS_PUBLIC_URL must be set (same value the server uses).")
    registry = InviteRegistry(f"{ATLAS_ROOT}/invites.json")
    token = registry.create()
    print(f"{ATLAS_PUBLIC_URL}/invite/{token}")
    print("Single-use, expires in 7 days. Send it directly to the person — it grants access on redemption.")
