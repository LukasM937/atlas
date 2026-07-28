"""GitHub-backed OAuth authorization server for the MCP endpoint.

The MCP client (Claude, ChatGPT) does a normal OAuth 2.1 + PKCE + dynamic
client registration flow against us — we are the authorization server from
their point of view (mcp.server.auth builds the actual HTTP endpoints and
verifies PKCE; this module is only the storage/business-logic layer it
calls into). Internally, our /authorize step redirects to GitHub's real
login, and only a single allow-listed GitHub username is accepted — GitHub
proves identity here, not authorization scope; there is exactly one
authorized user for this personal server.

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
    construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

GITHUB_AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
GITHUB_USER_URL = "https://api.github.com/user"

ACCESS_TOKEN_TTL = 3600  # 1 hour
AUTH_CODE_TTL = 300  # 5 minutes, single-use
PENDING_TTL = 600  # 10 minutes to complete the GitHub redirect


class GitHubOAuthProvider(OAuthAuthorizationServerProvider[AuthorizationCode, RefreshToken, AccessToken]):
    def __init__(
        self,
        state_path: str | Path,
        client_id: str,
        client_secret: str,
        allowed_user: str,
        callback_url: str,
    ) -> None:
        self.state_path = Path(state_path)
        self.client_id = client_id
        self.client_secret = client_secret
        self.allowed_user = allowed_user
        self.callback_url = callback_url
        self._clients: dict[str, OAuthClientInformationFull] = {}
        self._auth_codes: dict[str, AuthorizationCode] = {}
        self._access_tokens: dict[str, AccessToken] = {}
        self._refresh_tokens: dict[str, RefreshToken] = {}
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
        self._prune()

    def _save(self) -> None:
        self._prune()
        data = {
            "clients": {k: json.loads(v.model_dump_json()) for k, v in self._clients.items()},
            "auth_codes": {k: json.loads(v.model_dump_json()) for k, v in self._auth_codes.items()},
            "access_tokens": {k: json.loads(v.model_dump_json()) for k, v in self._access_tokens.items()},
            "refresh_tokens": {k: json.loads(v.model_dump_json()) for k, v in self._refresh_tokens.items()},
        }
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.state_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data), encoding="utf-8")
        os.replace(tmp, self.state_path)

    def _prune(self) -> None:
        now = time.time()
        self._auth_codes = {k: v for k, v in self._auth_codes.items() if v.expires_at > now}
        self._access_tokens = {
            k: v for k, v in self._access_tokens.items() if v.expires_at is None or v.expires_at > now
        }
        self._pending = {k: v for k, v in self._pending.items() if v["expires_at"] > now}

    # --- OAuthAuthorizationServerProvider ------------------------------------

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        return self._clients.get(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        self._clients[client_info.client_id] = client_info
        self._save()

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        github_state = secrets.token_urlsafe(32)
        self._pending[github_state] = {
            "client_id": client.client_id,
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
            subject=authorization_code.subject,
        )
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
        if token is None or token.client_id != client.client_id:
            return None
        return token

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        self._refresh_tokens.pop(refresh_token.token, None)
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
            subject=refresh_token.subject,
        )
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
        return at

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        self._access_tokens.pop(token.token, None)
        self._refresh_tokens.pop(token.token, None)
        self._save()

    # --- GitHub delegation, called from the callback route in app.py --------

    async def complete_github_login(self, code: str, github_state: str) -> str:
        """Exchange the GitHub code, check identity, mint our own auth code,
        and return the redirect URL back to the original MCP client."""
        pending = self._pending.pop(github_state, None)
        if pending is None or pending["expires_at"] < time.time():
            raise AuthorizeError(error="access_denied", error_description="Login expired or invalid, try again.")

        async with httpx.AsyncClient() as http:
            token_resp = await http.post(
                GITHUB_TOKEN_URL,
                headers={"Accept": "application/json"},
                data={
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "code": code,
                    "redirect_uri": self.callback_url,
                },
            )
            token_resp.raise_for_status()
            gh_token = token_resp.json().get("access_token")
            if not gh_token:
                raise AuthorizeError(error="access_denied", error_description="GitHub login failed.")

            user_resp = await http.get(GITHUB_USER_URL, headers={"Authorization": f"Bearer {gh_token}"})
            user_resp.raise_for_status()
            username = user_resp.json().get("login")

        if username != self.allowed_user:
            raise AuthorizeError(
                error="access_denied",
                error_description=f"GitHub user '{username}' is not authorized for this Atlas.",
            )

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
            subject=username,
        )
        self._save()
        return construct_redirect_uri(pending["redirect_uri"], code=our_code, state=pending["state"])
