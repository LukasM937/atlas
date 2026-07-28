"""ASGI entrypoint.

Routes
  /mcp                       streamable HTTP MCP endpoint, OAuth-protected
                              (when ATLAS_PUBLIC_URL/ATLAS_GITHUB_* are set)
  /mcp/{ATLAS_TOKEN}/        streamable HTTP MCP endpoint, path-secret scheme
                              (fallback when OAuth env vars are unset)
  /oauth/github/callback     GitHub login redirect target, only when OAuth is on
  /api/...                   REST facade                   -> ChatGPT Actions, curl, RAG
  /openapi.json              schema for the REST facade
  /healthz                   liveness

Only one of the two /mcp mounts is ever live: FastMCP's own auth middleware
applies to the whole app instance uniformly, so there is no way to run the
same instance with OAuth on one path and the old path-secret on another.
Set the OAuth env vars to switch over; unset them to revert instantly (a
redeploy, nothing else) — see docs/ADR-001-auth.md.
"""

from __future__ import annotations

import os
import secrets
import time
from collections import defaultdict, deque

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, RedirectResponse
from starlette.routing import Mount, Route
from starlette.types import ASGIApp, Receive, Scope, Send

from mcp.server.auth.provider import AuthorizeError

from .server import ATLAS_PUBLIC_URL, OAUTH_ENABLED, mcp, oauth_provider, store
from .store import AtlasError, Project, make_entry, new_project_body, slugify, utcnow

TOKEN = os.environ.get("ATLAS_TOKEN") or secrets.token_urlsafe(24)

# 1 MB matches the Apache vhost's LimitRequestBody; kept here too so the app
# is safe standalone (docker compose exposes it with no Apache in front).
MAX_BODY_BYTES = int(os.environ.get("ATLAS_MAX_BODY_BYTES", 1_048_576))
# per-IP request budget; ponytail: in-process dict, fine for one instance —
# move to a shared store if this ever runs behind multiple workers.
RATE_LIMIT = int(os.environ.get("ATLAS_RATE_LIMIT_PER_MIN", 120))
_hits: dict[str, deque[float]] = defaultdict(deque)


class BodySizeLimitMiddleware:
    """Reject oversized request bodies with 413, checked via Content-Length.
    # ponytail: trusts the header rather than metering the stream byte-by-byte;
    # a client that lies about Content-Length and streams past it anyway gets
    # caught by Apache's LimitRequestBody in front. Add stream metering here
    # too if this app is ever run with no reverse proxy in front of it.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        headers = dict(scope.get("headers") or [])
        length = headers.get(b"content-length")
        if length is not None and int(length) > MAX_BODY_BYTES:
            response = JSONResponse({"error": "request body too large"}, status_code=413)
            await response(scope, receive, send)
            return
        await self.app(scope, receive, send)


class RateLimitMiddleware:
    """Simple per-IP sliding window; fail2ban handles sustained abuse, this
    catches a single client hammering the API within its ban threshold."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        client = scope.get("client")
        ip = client[0] if client else "unknown"
        now = time.monotonic()
        window = _hits[ip]
        while window and now - window[0] > 60:
            window.popleft()
        if len(window) >= RATE_LIMIT:
            response = JSONResponse({"error": "rate limit exceeded"}, status_code=429)
            await response(scope, receive, send)
            return
        window.append(now)
        await self.app(scope, receive, send)


def _auth(request: Request) -> None:
    header = request.headers.get("authorization", "")
    if header != f"Bearer {TOKEN}":
        raise PermissionError("Missing or wrong Bearer token.")


async def healthz(request: Request) -> PlainTextResponse:
    return PlainTextResponse("ok")


async def api_list(request: Request) -> JSONResponse:
    _auth(request)
    q = request.query_params
    ps = store.filter(q.get("status"), q.get("priority"), q.get("category"), q.get("tag"))
    return JSONResponse([{"id": p.id, **p.meta} for p in ps])


async def api_get(request: Request) -> JSONResponse:
    _auth(request)
    p = store.load(request.path_params["project_id"])
    return JSONResponse({"id": p.id, "meta": p.meta, "body": p.body})


async def api_search(request: Request) -> JSONResponse:
    _auth(request)
    hits = store.search(request.query_params.get("q", ""), int(request.query_params.get("limit", 8)))
    return JSONResponse(
        [{"id": p.id, "name": p.name, "score": s, "snippet": snip} for p, snip, s in hits]
    )


async def api_append(request: Request) -> JSONResponse:
    _auth(request)
    body = await request.json()
    p = store.load(request.path_params["project_id"])
    if "## Log" not in p.body:
        p.body = p.body.rstrip() + "\n\n## Log\n"
    p.body = p.body.rstrip() + "\n" + make_entry(
        body.get("kind", "note"), body["text"], body.get("author", "api")
    )
    store.save(p)
    return JSONResponse({"ok": True, "id": p.id})


# Same fields the MCP UpsertInput model accepts — keeps the REST facade from
# writing arbitrary caller-supplied keys into stored frontmatter unchecked.
ALLOWED_META_FIELDS = (
    "name", "status", "priority", "category", "completion", "tags", "links", "sensitivity",
)


async def api_upsert(request: Request) -> JSONResponse:
    _auth(request)
    body = await request.json()
    pid = slugify(body["id"])
    if store.exists(pid):
        p = store.load(pid)
        p.meta.update({k: v for k, v in body.items() if k in ALLOWED_META_FIELDS})
    else:
        p = Project(
            id=pid,
            meta={
                "name": body.get("name", pid),
                "category": body.get("category", "unsorted"),
                "status": body.get("status", "concept"),
                "priority": body.get("priority", "C"),
                "completion": body.get("completion", 0),
                "created": utcnow(),
                "tags": body.get("tags", []),
                "links": body.get("links", []),
                "sensitivity": body.get("sensitivity", "internal"),
            },
            body=new_project_body(body.get("summary", "")),
        )
    if body.get("section") and body.get("content"):
        p.set_section(body["section"], body["content"])
    store.save(p)
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
    # AtlasError/PermissionError callsites). Anything else is unclassified —
    # it might be a FileNotFoundError or similar carrying a filesystem path,
    # so it gets a generic body instead of str(exc). Never leak stack traces
    # or paths to the client (CLAUDE.md invariant #6).
    known = {AtlasError: 400, PermissionError: 401, KeyError: 400}
    status = known.get(type(exc))
    if status is None:
        return JSONResponse({"error": "internal error"}, status_code=500)
    return JSONResponse({"error": str(exc) or type(exc).__name__}, status_code=status)


async def github_oauth_callback(request: Request):
    """GitHub redirects here after the user approves/denies login. Exchanges
    the GitHub code, checks identity against the allow-listed user, and
    redirects back to the MCP client's own redirect_uri with our code."""
    code = request.query_params.get("code")
    github_state = request.query_params.get("state")
    if not code or not github_state:
        return PlainTextResponse("Missing code or state.", status_code=400)
    assert oauth_provider is not None  # route only mounted when OAUTH_ENABLED
    try:
        redirect_url = await oauth_provider.complete_github_login(code, github_state)
    except AuthorizeError as e:
        return PlainTextResponse(f"Login failed: {e.error_description or e.error}", status_code=403)
    return RedirectResponse(redirect_url, status_code=302)


# Only one of these two /mcp mounts is ever added — see module docstring.
mcp_mount = Mount("/mcp", app=mcp.streamable_http_app()) if OAUTH_ENABLED else Mount(
    f"/mcp/{TOKEN}", app=mcp.streamable_http_app()
)

routes = [
    Route("/healthz", healthz),
    Route("/openapi.json", openapi),
    Route("/api/projects", api_list, methods=["GET"]),
    Route("/api/projects", api_upsert, methods=["POST"]),
    Route("/api/search", api_search, methods=["GET"]),
    Route("/api/projects/{project_id}", api_get, methods=["GET"]),
    Route("/api/projects/{project_id}/entries", api_append, methods=["POST"]),
    mcp_mount,
]
if OAUTH_ENABLED:
    routes.append(Route("/oauth/github/callback", github_oauth_callback))

    # FastMCP auto-generates an RFC 9728 "protected resource metadata" route
    # too, but its path is computed FROM the resource URL (already includes
    # "/mcp") and then gets mounted again under our own Mount("/mcp", ...),
    # landing at /mcp/.well-known/oauth-protected-resource/mcp -- not the
    # root-relative path (/.well-known/oauth-protected-resource/mcp) a
    # spec-following client actually requests. Re-registered here at the
    # correct top-level path with the same content, bypassing the buried,
    # unreachable copy FastMCP built internally.
    from urllib.parse import urlparse

    from mcp.server.auth.handlers.metadata import ProtectedResourceMetadataHandler
    from mcp.server.auth.routes import build_resource_metadata_url
    from mcp.shared.auth import ProtectedResourceMetadata

    _resource_url = f"{ATLAS_PUBLIC_URL}/mcp"
    _prm_handler = ProtectedResourceMetadataHandler(
        ProtectedResourceMetadata(
            resource=_resource_url,
            authorization_servers=[_resource_url],
            scopes_supported=["mcp"],
        )
    )
    _prm_path = urlparse(str(build_resource_metadata_url(_resource_url))).path
    routes.append(Route(_prm_path, endpoint=_prm_handler.handle, methods=["GET", "OPTIONS"]))

app = Starlette(
    routes=routes,
    lifespan=lambda a: mcp.session_manager.run(),
    exception_handlers={Exception: on_error, AtlasError: on_error, PermissionError: on_error},
    middleware=[
        Middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"],
                   allow_headers=["*"], expose_headers=["mcp-session-id"]),
        Middleware(RateLimitMiddleware),
        Middleware(BodySizeLimitMiddleware),
    ],
)

if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PORT", 8787))
    if OAUTH_ENABLED:
        print(f"MCP endpoint:  http://127.0.0.1:{port}/mcp  (OAuth, GitHub login required)")
    else:
        print(f"MCP endpoint:  http://127.0.0.1:{port}/mcp/{TOKEN}/")
    uvicorn.run(app, host="0.0.0.0", port=port)
