"""Tenant registry + single-use invite links for multi-user Atlas.

One GitHub identity = one tenant = one AtlasStore rooted at
tenants/<slug>/. Registry membership is the only authorization check;
GitHub already proved identity (see github_oauth.py). Invites are
possession-based: an unguessable single-use token, not tied to a
username ahead of time.
"""

from __future__ import annotations

import fcntl
import json
import os
import secrets
import subprocess
import time
from pathlib import Path
from typing import Callable, TypeVar

from .store import AtlasStore, slugify

INVITE_TTL_SECONDS = 7 * 24 * 3600  # 1 week

T = TypeVar("T")


def _atomic_write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data), encoding="utf-8")
    os.replace(tmp, path)


def _locked_json_update(path: Path, mutate: Callable[[dict], T]) -> T:
    """Read-modify-write path's JSON under an exclusive lock.

    Invites are minted by a short-lived CLI process (`python -m
    atlas_mcp.invite`) while the long-lived server process is the one that
    redeems them — an in-memory cache in either process would miss the
    other's writes. Always hitting disk, under a lock, is what makes
    "single-use" actually hold across processes, not just within one.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_suffix(path.suffix + ".lock")
    with open(lock_path, "w") as lf:
        fcntl.flock(lf, fcntl.LOCK_EX)
        try:
            data = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
            result = mutate(data)
            _atomic_write_json(path, data)
            return result
        finally:
            fcntl.flock(lf, fcntl.LOCK_UN)


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
    """No in-memory cache, deliberately — see _locked_json_update's docstring.
    Every call hits $state_path fresh, so the CLI (mints) and the server
    (redeems) always agree on the current set, even though they're separate
    processes and neither restarts to pick up the other's writes."""

    def __init__(self, state_path: str | Path) -> None:
        self.state_path = Path(state_path)

    def create(self, ttl_seconds: int = INVITE_TTL_SECONDS) -> str:
        token = secrets.token_urlsafe(32)

        def mutate(invites: dict) -> None:
            invites[token] = {"created": time.time(), "expires_at": time.time() + ttl_seconds}

        _locked_json_update(self.state_path, mutate)
        return token

    def is_valid(self, token: str) -> bool:
        invites = json.loads(self.state_path.read_text(encoding="utf-8")) if self.state_path.exists() else {}
        invite = invites.get(token)
        return invite is not None and invite["expires_at"] > time.time()

    def redeem(self, token: str) -> bool:
        """Atomic check-and-consume, cross-process: valid+unexpired -> delete,
        return True; a second caller (concurrent or later) sees it gone."""

        def mutate(invites: dict) -> bool:
            invite = invites.get(token)
            valid = invite is not None and invite["expires_at"] > time.time()
            invites.pop(token, None)
            return valid

        return _locked_json_update(self.state_path, mutate)


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
