"""ASGI entrypoint.

Routes
  /mcp/{ATLAS_TOKEN}/     streamable HTTP MCP endpoint  -> Claude custom connector
  /api/...                REST facade                   -> ChatGPT Actions, curl, RAG
  /openapi.json           schema for the REST facade
  /healthz                liveness

Auth for the first test is a single shared secret: an unguessable path segment
for MCP (Claude's connector UI has no field for a static bearer token) and a
Bearer header for REST. See README for the OAuth upgrade path.
"""

from __future__ import annotations

import os
import secrets

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.routing import Mount, Route

from .server import mcp, store
from .store import AtlasError, Project, make_entry, new_project_body, slugify, utcnow

TOKEN = os.environ.get("ATLAS_TOKEN") or secrets.token_urlsafe(24)


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


async def api_upsert(request: Request) -> JSONResponse:
    _auth(request)
    body = await request.json()
    pid = slugify(body["id"])
    if store.exists(pid):
        p = store.load(pid)
        p.meta.update({k: v for k, v in body.items() if k not in ("id", "section", "content")})
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
    status = {AtlasError: 400, PermissionError: 401, KeyError: 400}.get(type(exc), 500)
    return JSONResponse({"error": str(exc) or type(exc).__name__}, status_code=status)


routes = [
    Route("/healthz", healthz),
    Route("/openapi.json", openapi),
    Route("/api/projects", api_list, methods=["GET"]),
    Route("/api/projects", api_upsert, methods=["POST"]),
    Route("/api/search", api_search, methods=["GET"]),
    Route("/api/projects/{project_id}", api_get, methods=["GET"]),
    Route("/api/projects/{project_id}/entries", api_append, methods=["POST"]),
    Mount(f"/mcp/{TOKEN}", app=mcp.streamable_http_app()),
]

app = Starlette(
    routes=routes,
    lifespan=lambda a: mcp.session_manager.run(),
    exception_handlers={Exception: on_error, AtlasError: on_error, PermissionError: on_error},
    middleware=[
        Middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"],
                   allow_headers=["*"], expose_headers=["mcp-session-id"])
    ],
)

if __name__ == "__main__":
    import uvicorn

    print(f"MCP endpoint:  http://127.0.0.1:8787/mcp/{TOKEN}/")
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8787)))
