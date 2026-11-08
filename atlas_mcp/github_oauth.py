"""GitHub-backed OAuth authorization server for the MCP endpoint.

The MCP client (Claude, ChatGPT) does a normal OAuth 2.1 + PKCE + dynamic
client registration flow against us — we are the authorization server from
their point of view (mcp.server.auth builds the actual HTTP endpoints and
verifies PKCE; this module is only the storage/business-logic layer it
calls into). Internally, our /authorize step redirects to GitHub's real
login, and only usernames present in the TenantRegistry are accepted —
GitHub proves identity here, not authorization scope. Membership is
managed via the registry (bootstrapped from ATLAS_GITHUB_ALLOWED_USER,
extended by invite-link redemption); each accepted username gets its own
isolated AtlasStore (see tenants.py).

State (registered clients, issued codes/tokens) persists to a JSON file next
to the note store, so a container restart doesn't force every client to
re-register. Pending GitHub-side state (the bridge between our /authorize
call and GitHub's callback) is in-memory only — if the server restarts
mid-login, the user just retries.
"""

from __future__ import annotations

import json
import os
import secrets
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import httpx
from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    AuthorizeError,
    OAuthAuthorizationServerProvider,
    RefreshToken,
    RegistrationError,
    TokenError,
    construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

from .tenants import TenantRegistry

GITHUB_AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
GITHUB_USER_URL = "https://api.github.com/user"

ACCESS_TOKEN_TTL = 3600  # 1 hour
REFRESH_TOKEN_TTL = 30 * 24 * 3600  # 30 days: bounds the exposure of any leaked refresh token
AUTH_CODE_TTL = 300  # 5 minutes, single-use
PENDING_TTL = 600  # 10 minutes to complete the GitHub redirect
CONSENT_TTL = 300  # 5 minutes to click "Authorize" after GitHub login

# Dynamic client registration is anonymous, and every _save() rewrites the whole
# state file, so registry size and per-client payload are bounded (CWE-770).
MAX_CLIENTS = int(os.environ.get("ATLAS_MAX_OAUTH_CLIENTS", 256))
MAX_CLIENT_METADATA_BYTES = int(os.environ.get("ATLAS_MAX_CLIENT_METADATA_BYTES", 8192))
# /authorize is anonymous too and its _pending dict lives in RAM. Real values are
# tiny (S256 challenge = 43 chars, RFC 8707 resource <= 512), so cap them.
PENDING_FIELD_MAX_CHARS = 2048
PENDING_MAX_ENTRIES = 1024


async def verify_github_code(
    code: str, client_id: str, client_secret: str, callback_url: str
) -> tuple[str, int]:
    """Exchange a GitHub OAuth code for the logged-in user's username and
    immutable numeric GitHub id. Usernames are mutable and recyclable; only
    the id identifies the account that originally earned tenant membership."""
    async with httpx.AsyncClient() as http:
        token_resp = await http.post(
            GITHUB_TOKEN_URL,
            headers={"Accept": "application/json"},
            data={
                "client_id": client_id,
                "client_secret": client_secret,
                "code": code,
                "redirect_uri": callback_url,
            },
        )
        token_resp.raise_for_status()
        gh_token = token_resp.json().get("access_token")
        if not gh_token:
            raise AuthorizeError(error="access_denied", error_description="GitHub login failed.")

        user_resp = await http.get(GITHUB_USER_URL, headers={"Authorization": f"Bearer {gh_token}"})
        user_resp.raise_for_status()
        user = user_resp.json()
        username = user.get("login")
        github_id = user.get("id")
    if not username or not isinstance(github_id, int) or isinstance(github_id, bool):
        raise AuthorizeError(error="access_denied", error_description="GitHub login failed.")
    return username, github_id


class GitHubOAuthProvider(OAuthAuthorizationServerProvider[AuthorizationCode, RefreshToken, AccessToken]):
    def __init__(
        self,
        state_path: str | Path,
        client_id: str,
        client_secret: str,
        registry: TenantRegistry,
        callback_url: str,
    ) -> None:
        self.state_path = Path(state_path)
        self.client_id = client_id
        self.client_secret = client_secret
        self.registry = registry
        self.callback_url = callback_url
        self._clients: dict[str, OAuthClientInformationFull] = {}
        self._auth_codes: dict[str, AuthorizationCode] = {}
        self._access_tokens: dict[str, AccessToken] = {}
        self._refresh_tokens: dict[str, RefreshToken] = {}
        # Grant families: one grant id per authorization links every access/refresh
        # token it mints (rotation successors included), so revoking any one
        # token revokes the whole grant, and replaying a rotated-away refresh
        # token revokes its family (RFC 7009 s2.1, RFC 9700 s4.14).
        self._grant_of: dict[str, str] = {}  # token string -> grant id
        self._grant_members: dict[str, set[str]] = {}  # grant id -> token strings
        self._rotated: dict[str, str] = {}  # rotated-away refresh token -> grant id
        self._pending: dict[str, dict[str, Any]] = {}  # transient, not persisted
        self._load()

    # --- persistence --------------------------------------------------------

    def _load(self) -> None:
        if not self.state_path.exists():
            return
        data = json.loads(self.state_path.read_text(encoding="utf-8"))
        self._clients = {k: OAuthClientInformationFull.model_validate(v) for k, v in data.get("clients", {}).items()}
        self._auth_codes = {k: AuthorizationCode.model_validate(v) for k, v in data.get("auth_codes", {}).items()}
        self._access_tokens = {
            k: AccessToken.model_validate(v) for k, v in data.get("access_tokens", {}).items()
        }
        self._refresh_tokens = {
            k: RefreshToken.model_validate(v) for k, v in data.get("refresh_tokens", {}).items()
        }
        self._grant_of = dict(data.get("grant_of", {}))
        self._grant_members = {k: set(v) for k, v in data.get("grant_members", {}).items()}
        self._rotated = dict(data.get("rotated", {}))
        self._prune()

    def _save(self) -> None:
        self._prune()
        data = {
            "clients": {k: json.loads(v.model_dump_json()) for k, v in self._clients.items()},
            "auth_codes": {k: json.loads(v.model_dump_json()) for k, v in self._auth_codes.items()},
            "access_tokens": {k: json.loads(v.model_dump_json()) for k, v in self._access_tokens.items()},
            "refresh_tokens": {k: json.loads(v.model_dump_json()) for k, v in self._refresh_tokens.items()},
            "grant_of": self._grant_of,
            "grant_members": {k: sorted(v) for k, v in self._grant_members.items()},
            "rotated": self._rotated,
        }
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.state_path.with_suffix(".tmp")
        # This file holds every client secret and live token in cleartext:
        # create it owner-only whatever the ambient umask (Docker runs as root
        # with umask 022, which would leave it world-readable on the bind mount).
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.fchmod(fd, 0o600)  # also tightens a stale tmp file
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(json.dumps(data))
        os.replace(tmp, self.state_path)

    def _prune(self) -> None:
        now = time.time()
        self._auth_codes = {k: v for k, v in self._auth_codes.items() if v.expires_at > now}
        self._access_tokens = {
            k: v for k, v in self._access_tokens.items() if v.expires_at is None or v.expires_at > now
        }
        self._pending = {k: v for k, v in self._pending.items() if v["expires_at"] > now}
        # Entries minted before refresh tokens carried a deadline have none and
        # are honored until first use; every token minted now expires.
        self._refresh_tokens = {
            k: v for k, v in self._refresh_tokens.items() if v.expires_at is None or v.expires_at > now
        }
        live = set(self._access_tokens) | set(self._refresh_tokens)
        self._grant_of = {k: g for k, g in self._grant_of.items() if k in live}
        self._grant_members = {
            g: {t for t in m if t in live} for g, m in self._grant_members.items()
        }
        self._grant_members = {g: m for g, m in self._grant_members.items() if m}
        # Tombstones outlive their token (that is the point) but only as long
        # as a stolen copy could still be a refresh token.
        self._rotated = {k: g for k, g in self._rotated.items() if g in self._grant_members}

    def _link_grant(self, grant: str, *tokens: str) -> None:
        members = self._grant_members.setdefault(grant, set())
        for t in tokens:
            self._grant_of[t] = grant
            members.add(t)

    def _revoke_grant(self, grant: str) -> None:
        for t in self._grant_members.pop(grant, set()):
            self._access_tokens.pop(t, None)
            self._refresh_tokens.pop(t, None)
            self._grant_of.pop(t, None)
        for t in [k for k, g in self._rotated.items() if g == grant]:
            self._rotated.pop(t)

    # --- OAuthAuthorizationServerProvider ------------------------------------

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        return self._clients.get(client_id)

    def _evict_idle_client(self) -> bool:
        """Make room by dropping the oldest client that holds no tokens, so
        anonymous registration spam cannot lock real clients out."""
        in_use = {t.client_id for t in self._access_tokens.values()} | {
            t.client_id for t in self._refresh_tokens.values()
        }
        idle = [c for c in self._clients.values() if c.client_id not in in_use]
        if not idle:
            return False
        oldest = min(idle, key=lambda c: c.client_id_issued_at or 0)
        del self._clients[oldest.client_id]
        return True

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        if len(client_info.model_dump_json()) > MAX_CLIENT_METADATA_BYTES:
            raise RegistrationError(
                error="invalid_client_metadata",
                error_description=f"Client metadata exceeds {MAX_CLIENT_METADATA_BYTES} bytes.",
            )
        if len(self._clients) >= MAX_CLIENTS and not self._evict_idle_client():
            raise RegistrationError(
                error="invalid_client_metadata",
                error_description="Client registry is full; contact the operator.",
            )
        self._clients[client_info.client_id] = client_info
        self._save()

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        for name, value in (
            ("state", params.state),
            ("resource", params.resource),
            ("code_challenge", params.code_challenge),
        ):
            if value is not None and len(value) > PENDING_FIELD_MAX_CHARS:
                raise AuthorizeError(
                    error="invalid_request",
                    error_description=f"'{name}' exceeds {PENDING_FIELD_MAX_CHARS} characters.",
                )
        self._prune()  # authorize() never saves, so nothing else would
        if len(self._pending) >= PENDING_MAX_ENTRIES:
            raise AuthorizeError(
                error="temporarily_unavailable",
                error_description="Too many pending logins; retry in a moment.",
            )
        github_state = secrets.token_urlsafe(32)
        self._pending[github_state] = {
            "client_id": client.client_id,
            "client_name": (client.client_name or client.client_id)[:200],
            "state": params.state,
            "scopes": params.scopes or [],
            "code_challenge": params.code_challenge,
            "redirect_uri": str(params.redirect_uri),
            "redirect_uri_provided_explicitly": params.redirect_uri_provided_explicitly,
            "resource": params.resource,
            "expires_at": time.time() + PENDING_TTL,
        }
        query = urlencode(
            {
                "client_id": self.client_id,
                "redirect_uri": self.callback_url,
                "scope": "read:user",
                "state": github_state,
                "allow_signup": "false",
            }
        )
        return f"{GITHUB_AUTHORIZE_URL}?{query}"

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        code = self._auth_codes.get(authorization_code)
        if code is None or code.client_id != client.client_id or code.expires_at < time.time():
            return None
        return code

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        self._auth_codes.pop(authorization_code.code, None)
        access_token = secrets.token_urlsafe(32)
        refresh_token = secrets.token_urlsafe(32)
        expires_at = int(time.time()) + ACCESS_TOKEN_TTL
        self._access_tokens[access_token] = AccessToken(
            token=access_token,
            client_id=client.client_id,
            scopes=authorization_code.scopes,
            expires_at=expires_at,
            resource=authorization_code.resource,
            subject=authorization_code.subject,
        )
        self._refresh_tokens[refresh_token] = RefreshToken(
            token=refresh_token,
            client_id=client.client_id,
            scopes=authorization_code.scopes,
            expires_at=int(time.time()) + REFRESH_TOKEN_TTL,
            subject=authorization_code.subject,
        )
        self._link_grant(secrets.token_urlsafe(16), access_token, refresh_token)
        self._save()
        return OAuthToken(
            access_token=access_token,
            token_type="bearer",
            expires_in=ACCESS_TOKEN_TTL,
            refresh_token=refresh_token,
            scope=" ".join(authorization_code.scopes),
        )

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> RefreshToken | None:
        token = self._refresh_tokens.get(refresh_token)
        if token is None:
            # Replay of an already-rotated refresh token is a theft signal:
            # revoke the whole grant it belonged to.
            grant = self._rotated.get(refresh_token)
            if grant is not None:
                self._revoke_grant(grant)
                self._save()
            return None
        if token.client_id != client.client_id:
            return None
        if token.expires_at is not None and token.expires_at < time.time():
            self._refresh_tokens.pop(refresh_token, None)
            return None
        return token

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        # Tenancy is re-derived at renewal: a subject removed from the registry
        # must not keep rotating tokens.
        if not refresh_token.subject or not self.registry.has(refresh_token.subject):
            self._revoke_grant(self._grant_of.get(refresh_token.token, ""))
            self._refresh_tokens.pop(refresh_token.token, None)
            self._save()
            raise TokenError(error="invalid_grant", error_description="Tenant is no longer authorized.")
        self._refresh_tokens.pop(refresh_token.token, None)
        grant = self._grant_of.get(refresh_token.token)
        if grant is not None:
            self._rotated[refresh_token.token] = grant  # tombstone for replay detection
        access_token = secrets.token_urlsafe(32)
        new_refresh = secrets.token_urlsafe(32)
        expires_at = int(time.time()) + ACCESS_TOKEN_TTL
        use_scopes = scopes or refresh_token.scopes
        self._access_tokens[access_token] = AccessToken(
            token=access_token,
            client_id=client.client_id,
            scopes=use_scopes,
            expires_at=expires_at,
            subject=refresh_token.subject,
        )
        self._refresh_tokens[new_refresh] = RefreshToken(
            token=new_refresh,
            client_id=client.client_id,
            scopes=use_scopes,
            expires_at=int(time.time()) + REFRESH_TOKEN_TTL,
            subject=refresh_token.subject,
        )
        if grant is not None:
            self._link_grant(grant, access_token, new_refresh)
        self._save()
        return OAuthToken(
            access_token=access_token,
            token_type="bearer",
            expires_in=ACCESS_TOKEN_TTL,
            refresh_token=new_refresh,
            scope=" ".join(use_scopes),
        )

    async def load_access_token(self, token: str) -> AccessToken | None:
        at = self._access_tokens.get(token)
        if at is None:
            return None
        if at.expires_at is not None and at.expires_at < time.time():
            self._access_tokens.pop(token, None)
            return None
        # Deauthorization takes effect immediately: a removed tenant's live
        # access tokens stop working on the next request, not after their TTL.
        if not at.subject or not self.registry.has(at.subject):
            return None
        return at

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        grant = self._grant_of.get(token.token)
        if grant is not None:
            self._revoke_grant(grant)  # access + refresh + all successors
        else:  # persisted before grant tracking existed
            self._access_tokens.pop(token.token, None)
            self._refresh_tokens.pop(token.token, None)
        self._save()

    # --- GitHub delegation, called from the callback route in app.py --------

    async def stage_github_login(self, code: str, github_state: str) -> dict[str, Any]:
        """Exchange the GitHub code, check identity and tenancy, then hold the
        grant until the user explicitly approves the requesting client.

        GitHub proves *who* is logging in, not that they intended to authorize
        *this* client: an attacker-registered client (registration is open)
        could otherwise send a victim straight through a silent re-login and
        receive a code for the victim's tenant. The consent nonce is rendered
        only to the browser that completed the GitHub login."""
        pending = self._pending.pop(github_state, None)
        if pending is None or pending["expires_at"] < time.time():
            raise AuthorizeError(error="access_denied", error_description="Login expired or invalid, try again.")

        username, github_id = await verify_github_code(
            code, self.client_id, self.client_secret, self.callback_url
        )
        if not self.registry.is_allowed(username, github_id):
            raise AuthorizeError(
                error="access_denied",
                error_description="This GitHub account is not authorized for this Atlas.",
            )
        pending["subject"] = username
        pending["consent_nonce"] = secrets.token_urlsafe(32)
        pending["expires_at"] = time.time() + CONSENT_TTL
        self._pending[github_state] = pending
        return pending

    async def complete_login_consent(self, github_state: str, nonce: str) -> str:
        """Mint our authorization code and return the redirect back to the MCP
        client, only after the user approved that client."""
        pending = self._pending.pop(github_state, None)
        if pending is None or pending["expires_at"] < time.time() or "consent_nonce" not in pending:
            raise AuthorizeError(error="access_denied", error_description="Login expired or invalid, try again.")
        if not secrets.compare_digest(pending["consent_nonce"], nonce or ""):
            raise AuthorizeError(error="access_denied", error_description="Invalid consent confirmation.")

        our_code = secrets.token_urlsafe(32)
        self._auth_codes[our_code] = AuthorizationCode(
            code=our_code,
            scopes=pending["scopes"],
            expires_at=time.time() + AUTH_CODE_TTL,
            client_id=pending["client_id"],
            code_challenge=pending["code_challenge"],
            redirect_uri=pending["redirect_uri"],
            redirect_uri_provided_explicitly=pending["redirect_uri_provided_explicitly"],
            resource=pending["resource"],
            subject=pending["subject"],
        )
        self._save()
        return construct_redirect_uri(pending["redirect_uri"], code=our_code, state=pending["state"])
