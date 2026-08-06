"""Tenant registry + single-use invite links for multi-user Atlas.

One GitHub identity = one tenant = one AtlasStore rooted at
tenants/<slug>/. Registry membership is the only authorization check;
GitHub already proved identity (see github_oauth.py). Invites are
possession-based: an unguessable single-use token, not tied to a
username ahead of time.
"""

from __future__ import annotations

import json
import os
import secrets
import subprocess
import time
from pathlib import Path

from .store import AtlasStore, slugify

INVITE_TTL_SECONDS = 7 * 24 * 3600  # 1 week


def _atomic_write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data), encoding="utf-8")
    os.replace(tmp, path)


class TenantRegistry:
    def __init__(self, state_path: str | Path) -> None:
        self.state_path = Path(state_path)
        self._tenants: dict[str, dict] = {}
        if self.state_path.exists():
            self._tenants = json.loads(self.state_path.read_text(encoding="utf-8"))

    def is_allowed(self, username: str) -> bool:
        return username in self._tenants

    def add(self, username: str) -> None:
        if username in self._tenants:
            return
        self._tenants[username] = {"created": time.time()}
        _atomic_write_json(self.state_path, self._tenants)

    def list(self) -> list[str]:
        return list(self._tenants)


class InviteRegistry:
    def __init__(self, state_path: str | Path) -> None:
        self.state_path = Path(state_path)
        self._invites: dict[str, dict] = {}
        if self.state_path.exists():
            self._invites = json.loads(self.state_path.read_text(encoding="utf-8"))

    def _save(self) -> None:
        _atomic_write_json(self.state_path, self._invites)

    def create(self, ttl_seconds: int = INVITE_TTL_SECONDS) -> str:
        token = secrets.token_urlsafe(32)
        self._invites[token] = {"created": time.time(), "expires_at": time.time() + ttl_seconds}
        self._save()
        return token

    def is_valid(self, token: str) -> bool:
        invite = self._invites.get(token)
        return invite is not None and invite["expires_at"] > time.time()

    def redeem(self, token: str) -> bool:
        """Atomic check-and-consume: valid+unexpired -> delete, return True."""
        if not self.is_valid(token):
            self._invites.pop(token, None)
            self._save()
            return False
        del self._invites[token]
        self._save()
        return True


_store_cache: dict[str, AtlasStore] = {}


def get_store_for(username: str, atlas_root: str | Path, **store_kwargs) -> AtlasStore:
    root = Path(atlas_root) / "tenants" / slugify(username)
    cache_key = str(root)
    if cache_key not in _store_cache:
        if store_kwargs.get("git") and not (root / ".git").exists():
            root.mkdir(parents=True, exist_ok=True)
            try:
                subprocess.run(["git", "init"], cwd=root, check=True, capture_output=True, timeout=15)
            except Exception:
                pass  # same swallow-and-continue policy as AtlasStore._commit
        _store_cache[cache_key] = AtlasStore(root, **store_kwargs)
    return _store_cache[cache_key]
