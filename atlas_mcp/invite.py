"""Generate a single-use invite link for onboarding a new tenant.

Docker Compose deployment (this project's default) — run it INSIDE the
already-running container, so it sees the exact same ATLAS_ROOT/
ATLAS_PUBLIC_URL the live server does:

    docker compose exec atlas python -m atlas_mcp.invite

Running it bare on the host instead only works if you export
ATLAS_ROOT/ATLAS_PUBLIC_URL yourself first — .env is read by `docker
compose` to interpolate docker-compose.yml, it is never auto-sourced into
any shell (container or host), regardless of the file's permissions.

Safe to run repeatedly and from a different process than the server:
InviteRegistry always reads/writes straight from $ATLAS_ROOT/invites.json
under a lock (no in-memory cache), so the running server picks up an
invite minted this way immediately, and redemption is still single-use
even though minting and redeeming happen in different processes.

Prints the link once (not stored anywhere in plaintext) and exits.
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
