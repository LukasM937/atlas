"""ASGI entrypoint.

Routes
  /mcp                       streamable HTTP MCP endpoint, OAuth-protected
                              (when ATLAS_PUBLIC_URL/ATLAS_GITHUB_* are set)
  /mcp/{ATLAS_TOKEN}/        streamable HTTP MCP endpoint, path-secret scheme
                              (fallback when OAuth env vars are unset)
  /oauth/github/callback     GitHub login redirect target, only when OAuth is on.
                              Shared by both MCP/REST client login and invite
                              redemption -- GitHub OAuth Apps only support one
                              registered callback URL; a second one gets
                              rejected by GitHub itself before we see the
                              request. Which flow a given callback belongs to
                              is carried in `state` (see invite_start).
  /invite/{token}            Redeem a single-use invite link, only when OAuth is on
  /api/...                   REST facade                   -> ChatGPT Actions, curl, RAG
  /openapi.json              schema for the REST facade
  /healthz                   liveness

Only one of the two /mcp modes is ever live: FastMCP builds its own
AuthenticationMiddleware bound to the single oauth_provider, and there's
only one of those per instance, so there is no way to run the same
instance with OAuth on one path and the old path-secret on another. Set
the OAuth env vars to switch over; unset them to revert instantly (a
redeploy, nothing else) — see docs/ADR-001-auth.md.
"""

from __future__ import annotations

import asyncio
import html
import os
import secrets
import time
from collections import defaultdict, deque
from pathlib import Path
from urllib.parse import urlencode, urlparse

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from starlette.routing import Mount, Route
from starlette.types import ASGIApp, Receive, Scope, Send

from mcp.server.auth.middleware.auth_context import AuthContextMiddleware
from mcp.server.auth.middleware.bearer_auth import BearerAuthBackend
from mcp.server.auth.provider import AuthorizeError, ProviderTokenVerifier
from pydantic import ValidationError

from .github_oauth import GITHUB_AUTHORIZE_URL, verify_github_code
from .server import (
    ATLAS_GIT,
    ATLAS_MAX_SENSITIVITY,
    ATLAS_PUBLIC_URL,
    ATLAS_ROOT,
    GITHUB_CLIENT_ID,
    GITHUB_CLIENT_SECRET,
    OAUTH_ENABLED,
    audit,
    invite_registry,
    mcp,
    oauth_provider,
    store,
    tenant_registry,
)
from .server import MAX_FIELD_CHARS, AppendInput, UpsertInput, apply_append, apply_upsert
from .store import AtlasDenied, AtlasError, AtlasStore, slugify
from .tenants import get_store_for

TOKEN = os.environ.get("ATLAS_TOKEN") or secrets.token_urlsafe(24)

# 1 MB matches the Apache vhost's LimitRequestBody; kept here too so the app
# is safe standalone (docker compose exposes it with no Apache in front).
MAX_BODY_BYTES = int(os.environ.get("ATLAS_MAX_BODY_BYTES", 1_048_576))
# per-IP request budget; ponytail: in-process dict, fine for one instance —
# move to a shared store if this ever runs behind multiple workers.
RATE_LIMIT = int(os.environ.get("ATLAS_RATE_LIMIT_PER_MIN", 120))
_hits: dict[str, deque[float]] = defaultdict(deque)


class BodySizeLimitMiddleware:
    """Reject oversized request bodies with 413.

    Meters the actual ASGI body stream, not just Content-Length: chunked
    (Transfer-Encoding) requests carry no length header and would otherwise be
    buffered without bound by the single-process service. Apache's
    LimitRequestBody does not apply to reverse-proxied bodies, so this is the
    only real cap. The header check stays as a cheap early reject.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        too_large = JSONResponse({"error": "request body too large"}, status_code=413)
        length = dict(scope.get("headers") or []).get(b"content-length")
        if length is not None:
            try:
                if int(length) > MAX_BODY_BYTES:
                    return await too_large(scope, receive, send)
            except ValueError:
                return await JSONResponse({"error": "bad Content-Length"}, status_code=400)(
                    scope, receive, send)

        # Read the whole (bounded) body up front, then replay it.
        chunks: list[bytes] = []
        size = 0
        trailing: dict | None = None
        while True:
            message = await receive()
            if message["type"] != "http.request":
                trailing = message  # e.g. http.disconnect
                break
            chunk = message.get("body", b"")
            size += len(chunk)
            if size > MAX_BODY_BYTES:
                return await too_large(scope, receive, send)
            chunks.append(chunk)
            if not message.get("more_body", False):
                break

        replay: list[dict] = [{"type": "http.request", "body": b"".join(chunks), "more_body": False}]
        if trailing is not None:
            replay.append(trailing)

        async def receive_replay() -> dict:
            return replay.pop(0) if replay else await receive()

        await self.app(scope, receive_replay, send)


class RateLimitMiddleware:
    """Simple per-IP sliding window; fail2ban handles sustained abuse, this
    catches a single client hammering the API within its ban threshold.

    The key is scope["client"], which uvicorn rewrites from X-Forwarded-For
    only when the direct peer is in FORWARDED_ALLOW_IPS. Behind Docker NAT that
    peer is the bridge gateway (see docker-compose.yml); if it is not listed
    every client shares one bucket and one noisy client can 429 everybody."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        client = scope.get("client")
        ip = client[0] if client else "unknown"
        now = time.monotonic()
        if len(_hits) > 10_000:  # bound memory: drop idle keys
            for k in [k for k, w in _hits.items() if not w or now - w[-1] > 60]:
                del _hits[k]
        window = _hits[ip]
        while window and now - window[0] > 60:
            window.popleft()
        if len(window) >= RATE_LIMIT:
            response = JSONResponse({"error": "rate limit exceeded"}, status_code=429)
            await response(scope, receive, send)
            return
        window.append(now)
        await self.app(scope, receive, send)


async def _resolve_store(request: Request) -> AtlasStore:
    """Authenticate a REST request and return the caller's store.

    In OAuth mode, GitHub login is the only accepted credential — the
    static ATLAS_TOKEN's REST role was deprecated (see docs/ADR-002
    "Unifying REST") and is now retired now that GitHub login is confirmed
    working end to end for both MCP and REST. ATLAS_TOKEN still exists as
    an env var (docker-compose.yml requires it) and still works as the
    sole credential in genuine single-tenant fallback mode (OAuth entirely
    disabled) — that's a different, still-supported deployment mode, not
    the deprecated path this removed.
    """
    header = request.headers.get("authorization", "")
    token = header[7:].strip() if header[:7].lower() == "bearer " else ""
    if not token:
        raise PermissionError("Missing or wrong Bearer token.")

    if OAUTH_ENABLED and oauth_provider is not None:
        access = await oauth_provider.load_access_token(token)
        if access is not None and access.subject:
            return get_store_for(
                access.subject, ATLAS_ROOT, git=ATLAS_GIT, max_sensitivity=ATLAS_MAX_SENSITIVITY
            )
        raise PermissionError("Missing or wrong Bearer token.")

    # Genuine single-tenant fallback mode: OAuth isn't configured at all.
    if secrets.compare_digest(token, TOKEN):
        return store

    raise PermissionError("Missing or wrong Bearer token.")


async def healthz(request: Request) -> PlainTextResponse:
    return PlainTextResponse("ok")


def _validated(model, data):
    """Validate REST input with the same pydantic models the MCP tools use, so
    both facades enforce identical types, vocabularies and size caps."""
    try:
        return model.model_validate(data)
    except ValidationError as e:
        raise AtlasError(
            "Invalid request: "
            + "; ".join(f"{'.'.join(map(str, err['loc']))}: {err['msg']}" for err in e.errors())
        ) from None


async def _json_object(request: Request) -> dict:
    try:
        body = await request.json()
    except ValueError:
        raise AtlasError("Request body must be valid JSON.") from None
    if not isinstance(body, dict):
        raise AtlasError("Request body must be a JSON object.")
    return body


# Store calls are blocking (file I/O, YAML, regex, git); run them in worker
# threads so one slow request cannot freeze the event loop for everyone.


async def api_list(request: Request) -> JSONResponse:
    s = await _resolve_store(request)
    q = request.query_params
    ps = await asyncio.to_thread(
        s.filter, q.get("status"), q.get("priority"), q.get("category"), q.get("tag")
    )
    return JSONResponse([{"id": p.id, **p.meta} for p in ps])


async def api_get(request: Request) -> JSONResponse:
    s = await _resolve_store(request)
    p = await asyncio.to_thread(s.load, request.path_params["project_id"])
    return JSONResponse({"id": p.id, "meta": p.meta, "body": p.body})


async def api_search(request: Request) -> JSONResponse:
    s = await _resolve_store(request)
    try:
        limit = min(max(int(request.query_params.get("limit", 8)), 1), 50)
    except ValueError:
        raise AtlasError("'limit' must be an integer between 1 and 50.") from None
    hits = await asyncio.to_thread(s.search, request.query_params.get("q", ""), limit)
    return JSONResponse(
        [{"id": p.id, "name": p.name, "score": score, "snippet": snip} for p, snip, score in hits]
    )


async def api_append(request: Request) -> JSONResponse:
    s = await _resolve_store(request)
    body = await _json_object(request)
    params = _validated(AppendInput, {
        "id": request.path_params["project_id"],
        "kind": body.get("kind", "note"),
        "text": body.get("text"),
        "author": body.get("author", "api"),
    })
    p = await asyncio.to_thread(apply_append, s, params)
    return JSONResponse({"ok": True, "id": p.id})


async def api_delete(request: Request) -> JSONResponse:
    s = await _resolve_store(request)
    pid = await asyncio.to_thread(s.delete, request.path_params["project_id"])
    return JSONResponse({"ok": True, "id": pid})


async def api_upsert(request: Request) -> JSONResponse:
    s = await _resolve_store(request)
    body = await _json_object(request)
    summary = body.pop("summary", "")
    if not isinstance(summary, str) or len(summary) > MAX_FIELD_CHARS:
        raise AtlasError(f"'summary' must be a string of at most {MAX_FIELD_CHARS} characters.")
    params = _validated(UpsertInput, body)
    p, _ = await asyncio.to_thread(apply_upsert, s, params, summary)
    return JSONResponse({"ok": True, "id": p.id, "meta": p.meta})


async def openapi(request: Request) -> JSONResponse:
    base = str(request.base_url).rstrip("/")
    return JSONResponse(
        {
            "openapi": "3.1.0",
            "info": {"title": "Project Atlas", "version": "1.0.0"},
            "servers": [{"url": base}],
            "components": {
                "securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}}
            },
            "security": [{"bearer": []}],
            "paths": {
                "/api/projects": {
                    "get": {
                        "operationId": "listProjects",
                        "parameters": [
                            {"name": n, "in": "query", "schema": {"type": "string"}}
                            for n in ("status", "priority", "category", "tag")
                        ],
                        "responses": {"200": {"description": "project list"}},
                    },
                    "post": {
                        "operationId": "upsertProject",
                        "responses": {"200": {"description": "written"}},
                    },
                },
                "/api/projects/{project_id}": {
                    "get": {
                        "operationId": "getProject",
                        "parameters": [
                            {"name": "project_id", "in": "path", "required": True,
                             "schema": {"type": "string"}}
                        ],
                        "responses": {"200": {"description": "one project"}},
                    }
                },
                "/api/projects/{project_id}/entries": {
                    "post": {
                        "operationId": "appendEntry",
                        "parameters": [
                            {"name": "project_id", "in": "path", "required": True,
                             "schema": {"type": "string"}}
                        ],
                        "responses": {"200": {"description": "appended"}},
                    }
                },
                "/api/search": {
                    "get": {
                        "operationId": "searchProjects",
                        "parameters": [
                            {"name": "q", "in": "query", "required": True,
                             "schema": {"type": "string"}}
                        ],
                        "responses": {"200": {"description": "hits"}},
                    }
                },
            },
        }
    )


async def on_error(request: Request, exc: Exception) -> JSONResponse:
    # Only these are guaranteed to carry a safe, actionable message (see
    # AtlasError/PermissionError callsites). Anything else is unclassified --
    # it might be a FileNotFoundError or similar carrying a filesystem path,
    # so it gets a generic body instead of str(exc). Never leak stack traces
    # or paths to the client (CLAUDE.md invariant #6).
    if isinstance(exc, AtlasDenied):
        status = 403
    elif isinstance(exc, AtlasError):
        status = 400
    elif isinstance(exc, PermissionError):
        status = 401
    elif type(exc) is KeyError:
        status = 400
    else:
        return JSONResponse({"error": "internal error"}, status_code=500)
    return JSONResponse({"error": str(exc) or type(exc).__name__}, status_code=status)


# The one and only callback URL registered on the GitHub OAuth App (see
# README's setup steps). Classic GitHub OAuth Apps support exactly one --
# a redirect_uri that doesn't match it exactly gets rejected by GitHub
# itself ("the redirect_uri is not associated with this application")
# before any of our code runs. Invite redemption reuses this same URL
# rather than registering a second one; which flow a callback belongs to
# is carried in `state` instead (see invite_start / github_oauth_callback).
GITHUB_CALLBACK_URL = f"{ATLAS_PUBLIC_URL}/oauth/github/callback"
INVITE_STATE_PREFIX = "invite:"


async def invite_start(request: Request):
    """Entry point for a shared invite link: validate (without consuming)
    then hand off to GitHub login. The invite token rides in `state`,
    prefixed so the shared callback can tell this apart from a normal MCP/
    REST client login (github_state values there are bare
    secrets.token_urlsafe(32) -- never contain ':', so no collision risk)."""
    assert invite_registry is not None  # route only mounted when OAUTH_ENABLED
    token = request.path_params["token"]
    if not invite_registry.is_valid(token):
        return PlainTextResponse("This invite link is no longer valid.", status_code=404)
    query = urlencode(
        {
            "client_id": GITHUB_CLIENT_ID,
            "redirect_uri": GITHUB_CALLBACK_URL,
            "scope": "read:user",
            "state": INVITE_STATE_PREFIX + token,
            "allow_signup": "false",
        }
    )
    return RedirectResponse(f"{GITHUB_AUTHORIZE_URL}?{query}", status_code=302)


async def _complete_invite(code: str, token: str) -> PlainTextResponse:
    """Redeems the invite (single-use) and registers the GitHub login as a
    new tenant."""
    assert invite_registry is not None and tenant_registry is not None
    try:
        username, github_id = await verify_github_code(
            code, GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, GITHUB_CALLBACK_URL
        )
    except AuthorizeError as e:
        return PlainTextResponse(f"Login failed: {e.error_description or e.error}", status_code=403)
    if not tenant_registry.has(username):
        # A new tenancy must never provision onto a leftover directory: the slug
        # comes from a recyclable GitHub username, so data from a former tenant
        # at the same slug would be silently handed to the new holder. Checked
        # before the invite is consumed so the operator can fix it and retry.
        dest = Path(ATLAS_ROOT) / "tenants" / slugify(username)
        if dest.exists() and any(dest.iterdir()):
            return PlainTextResponse(
                "This username matches a leftover tenant directory that still holds "
                "data from a previous tenant. Ask the operator to archive or remove "
                "it before onboarding this username.",
                status_code=409,
            )
    if not invite_registry.redeem(token):
        return PlainTextResponse("This invite link is no longer valid.", status_code=404)
    tenant_registry.add(username, github_id)
    audit("invite_redeem", username, "tenant-added")
    get_store_for(username, ATLAS_ROOT, git=ATLAS_GIT, max_sensitivity=ATLAS_MAX_SENSITIVITY)
    mcp_url = f"{ATLAS_PUBLIC_URL}/mcp"
    return PlainTextResponse(
        f"Welcome, {username}. Your Atlas is ready.\n\n"
        f"Add this as a custom connector in Claude or ChatGPT:\n{mcp_url}\n\n"
        "It will ask you to log in with GitHub again — that's expected."
    )


async def github_oauth_callback(request: Request):
    """GitHub redirects here after the user approves/denies login -- the
    single callback URL registered on the OAuth App, shared by the MCP/REST
    client login flow and invite redemption (see GITHUB_CALLBACK_URL).
    Routes on the `state` prefix to whichever flow it belongs to."""
    code = request.query_params.get("code")
    state = request.query_params.get("state")
    if not code or not state:
        return PlainTextResponse("Missing code or state.", status_code=400)
    if state.startswith(INVITE_STATE_PREFIX):
        return await _complete_invite(code, state[len(INVITE_STATE_PREFIX):])
    assert oauth_provider is not None  # route only mounted when OAUTH_ENABLED
    try:
        pending = await oauth_provider.stage_github_login(code, state)
    except AuthorizeError as e:
        return PlainTextResponse(f"Login failed: {e.error_description or e.error}", status_code=403)
    # The one user-facing authorization decision the AS owes the user: show WHICH
    # client is asking before any code is minted. client_name is whatever the
    # registrant typed, so the redirect host (where the code will actually be
    # sent) is shown too. The nonce is rendered only to this browser, so whoever
    # started /authorize can never approve on the user's behalf.
    redirect_host = urlparse(pending["redirect_uri"]).netloc
    return HTMLResponse(
        '<!doctype html><html lang="en"><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1"><title>Authorize</title>'
        "<body><p>An application named <strong>"
        f"{html.escape(pending['client_name'])}</strong> wants access to the Atlas of "
        f"<strong>{html.escape(pending['subject'])}</strong>.</p>"
        f"<p>It will receive its access at <strong>{html.escape(redirect_host)}</strong>. "
        "Only continue if you just started connecting this application yourself.</p>"
        '<form method="post" action="/oauth/consent">'
        f'<input type="hidden" name="state" value="{html.escape(state)}">'
        f'<input type="hidden" name="nonce" value="{html.escape(pending["consent_nonce"])}">'
        '<button type="submit">Authorize</button></form></body></html>',
        headers={"Content-Security-Policy": "frame-ancestors 'none'", "X-Frame-Options": "DENY",
                 "Cache-Control": "no-store"},
    )


async def oauth_login_consent(request: Request):
    """Second half of the client-login flow: mint the authorization code only
    after the user approved the requesting client on the consent page."""
    assert oauth_provider is not None  # route only mounted when OAUTH_ENABLED
    form = await request.form()
    try:
        redirect_url = await oauth_provider.complete_login_consent(
            str(form.get("state", "")), str(form.get("nonce", ""))
        )
    except AuthorizeError as e:
        return PlainTextResponse(f"Login failed: {e.error_description or e.error}", status_code=403)
    return RedirectResponse(redirect_url, status_code=302)


routes = [
    Route("/healthz", healthz),
    Route("/openapi.json", openapi),
    Route("/api/projects", api_list, methods=["GET"]),
    Route("/api/projects", api_upsert, methods=["POST"]),
    Route("/api/search", api_search, methods=["GET"]),
    Route("/api/projects/{project_id}", api_get, methods=["GET"]),
    Route("/api/projects/{project_id}", api_delete, methods=["DELETE"]),
    Route("/api/projects/{project_id}/entries", api_append, methods=["POST"]),
]

if OAUTH_ENABLED:
    # Flattened, not mounted: a Mount("/mcp", app=...) requires a literal "/"
    # after the prefix to match at all (Starlette's Mount compiles
    # "<path>/{path:path}") -- a bare POST /mcp with no trailing slash
    # doesn't match, and redirecting to add one doesn't help either, since
    # (confirmed in practice) at least one real MCP client doesn't follow
    # redirects on POST: the whole OAuth handshake can succeed and the
    # actual tool call still fails right after. FastMCP already built each
    # of its routes (the MCP endpoint itself via streamable_http_path,
    # authorize/token/register/revoke, both metadata documents) as literal
    # absolute-feeling paths matching issuer_url/resource_server_url in
    # server.py -- extending our own routes with them directly, instead of
    # wrapping the whole app in an extra prefix, makes those paths and the
    # advertised URLs actually agree with each other.
    routes.extend(mcp.streamable_http_app().routes)
    routes.append(Route("/oauth/github/callback", github_oauth_callback))
    routes.append(Route("/oauth/consent", oauth_login_consent, methods=["POST"]))
    routes.append(Route("/invite/{token}", invite_start))
else:
    routes.append(Mount(f"/mcp/{TOKEN}", app=mcp.streamable_http_app()))

_middleware = [
    Middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"],
               allow_headers=["*"], expose_headers=["mcp-session-id"]),
    Middleware(RateLimitMiddleware),
    Middleware(BodySizeLimitMiddleware),
]
if OAUTH_ENABLED:
    # FastMCP normally adds these itself inside the Starlette app it builds
    # for streamable_http_app() -- lost when that app's routes were flattened
    # into this one instead of mounted (see routes= above), since middleware
    # is application-level, not carried along with individual routes. Without
    # this, RequireAuthMiddleware (attached per-route, still present) always
    # sees scope["user"] unset and 401s every request regardless of a valid
    # token -- confirmed in practice: /token kept succeeding while every
    # following /mcp call still 401'd.
    _middleware += [
        Middleware(AuthenticationMiddleware, backend=BearerAuthBackend(ProviderTokenVerifier(oauth_provider))),
        Middleware(AuthContextMiddleware),
    ]

app = Starlette(
    routes=routes,
    lifespan=lambda a: mcp.session_manager.run(),
    exception_handlers={Exception: on_error, AtlasError: on_error, PermissionError: on_error},
    middleware=_middleware,
)

if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PORT", 8787))
    if OAUTH_ENABLED:
        print(f"MCP endpoint:  http://127.0.0.1:{port}/mcp  (OAuth, GitHub login required)")
    else:
        print(f"MCP endpoint:  http://127.0.0.1:{port}/mcp/{TOKEN}/")
    uvicorn.run(app, host="0.0.0.0", port=port)
