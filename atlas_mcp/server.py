"""Project Atlas — a shared note/knowledge layer for every LLM you use.

Exposes the same store twice:
  * MCP (streamable HTTP)  -> Claude custom connector, Claude Code, local agents
  * REST + OpenAPI         -> ChatGPT Actions, curl, scripts, RAG ingestion

Nothing here is Claude-specific: the store is plain markdown on your disk.
"""

from __future__ import annotations

import json
import os
from typing import Annotated, Any, Literal, Optional

from pathlib import Path

from urllib.parse import urlparse

from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions, RevocationOptions
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import BaseModel, ConfigDict, Field

from .github_oauth import GitHubOAuthProvider
from .store import (
    ENTRY_KINDS,
    PRIORITY,
    SECTIONS,
    SENSITIVITY,
    STATUS,
    AtlasError,
    AtlasStore,
    Project,
    make_entry,
    new_project_body,
    slugify,
    utcnow,
)

ATLAS_ROOT = os.environ.get("ATLAS_ROOT", "./data")
ATLAS_GIT = os.environ.get("ATLAS_GIT", "0") == "1"
# Clearance of THIS process. The internet-facing unit runs at "internal";
# anything classified higher is invisible to it, not merely hidden.
ATLAS_MAX_SENSITIVITY = os.environ.get("ATLAS_MAX_SENSITIVITY", "internal")
store = AtlasStore(ATLAS_ROOT, git=ATLAS_GIT, max_sensitivity=ATLAS_MAX_SENSITIVITY)

# --- OAuth (Phase 4) -------------------------------------------------------
# Entirely optional: unset any of these and the server falls back to the
# original /mcp/<token>/ path-secret scheme with no auth wired into FastMCP
# itself. Set all four to switch this instance over to GitHub-backed OAuth —
# see docs/ADR-001-auth.md for why GitHub and why this shape.
ATLAS_PUBLIC_URL = os.environ.get("ATLAS_PUBLIC_URL", "").rstrip("/")
GITHUB_CLIENT_ID = os.environ.get("ATLAS_GITHUB_CLIENT_ID", "")
GITHUB_CLIENT_SECRET = os.environ.get("ATLAS_GITHUB_CLIENT_SECRET", "")
GITHUB_ALLOWED_USER = os.environ.get("ATLAS_GITHUB_ALLOWED_USER", "")

OAUTH_ENABLED = bool(ATLAS_PUBLIC_URL and GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET and GITHUB_ALLOWED_USER)

oauth_provider: GitHubOAuthProvider | None = None
if OAUTH_ENABLED:
    oauth_provider = GitHubOAuthProvider(
        state_path=Path(ATLAS_ROOT) / "oauth_state.json",
        client_id=GITHUB_CLIENT_ID,
        client_secret=GITHUB_CLIENT_SECRET,
        allowed_user=GITHUB_ALLOWED_USER,
        callback_url=f"{ATLAS_PUBLIC_URL}/oauth/github/callback",
    )

_audit_path = os.environ.get("ATLAS_AUDIT_LOG", "")


def audit(tool: str, target: str = "", outcome: str = "ok") -> None:
    """Append one metadata-only audit line. Never records note content."""
    if not _audit_path:
        return
    from datetime import datetime, timezone

    line = json.dumps(
        {
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "tool": tool,
            "target": target,
            "outcome": outcome,
        }
    )
    try:
        with open(_audit_path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except OSError:
        pass

INSTRUCTIONS = f"""
Project Atlas is Lukas' single source of truth for projects, research and ideas,
shared across all LLM assistants.

Rules for every assistant using this connector:
1. Before advising on an ongoing project, call atlas_search or atlas_get_project.
   Do not rely on your own memory of it.
2. Never invent completed work or assume implementation without evidence in the
   store. If the store is silent, say so.
3. Do not overwrite a section that contains substance without being asked.
   Prefer atlas_append_entry (append-only log) over atlas_upsert_project.
4. Record decisions as they happen: kind='decision' with the reason, not just
   the outcome.
5. Statuses: {', '.join(STATUS)}. Priorities: {', '.join(PRIORITY)} (S = critical).
6. Everything you read here leaves the owner's server and is processed by a
   third-party model provider. Never write identifiers into the Atlas —
   no addresses, account numbers, phone numbers, e-mail addresses, dates of
   birth, health details, credentials, or personal data about third parties.
   Reference the location of such material instead of copying it. Writes are
   scanned and rejected if they contain identifiers.
7. Classification is per project: {', '.join(SENSITIVITY)}. This instance serves
   up to '{ATLAS_MAX_SENSITIVITY}'; higher records are not readable here at all.

Sections available per project: {', '.join(SECTIONS)} plus an append-only Log.
""".strip()

# FastMCP auto-enables DNS-rebinding protection restricted to localhost
# whenever its own (unrelated to us) `host` constructor arg defaults to
# "127.0.0.1" -- which it always does here, since we don't set it. Left
# implicit, every real request's Host: atlas.muehrke.de gets rejected with
# 421 "Invalid Host header", regardless of auth -- confirmed in practice.
# Configure it explicitly instead, for the actual public hostname.
_public_host = urlparse(ATLAS_PUBLIC_URL).hostname if ATLAS_PUBLIC_URL else None
transport_security = (
    TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=[_public_host, f"{_public_host}:*"],
        allowed_origins=[ATLAS_PUBLIC_URL],
    )
    if _public_host
    else None
)

mcp = FastMCP(
    "atlas_mcp",
    instructions=INSTRUCTIONS,
    stateless_http=True,
    json_response=True,
    # Not "127.0.0.1" (FastMCP's own default): app.py always runs this under
    # uvicorn/Apache, never FastMCP's own standalone dev server, so this
    # value itself is inert -- it only matters because FastMCP auto-enables
    # its localhost-only transport_security default when host is a
    # loopback value, which would otherwise override our own explicit
    # config below (or silently leave old path-secret mode with no domain
    # to configure it for at all).
    host="0.0.0.0",
    # OAuth mode: a literal absolute path, flattened directly into app.py's
    # routes (no Mount wrapper) -- see the comment there for why. Old
    # path-secret mode: "/" as before, used inside a Mount(f"/mcp/{TOKEN}").
    streamable_http_path="/mcp" if OAUTH_ENABLED else "/",
    transport_security=transport_security,
    auth_server_provider=oauth_provider,
    auth=AuthSettings(
        # Root-level: /authorize, /token, /register, /revoke, and the AS
        # metadata document all end up as literal top-level paths once
        # app.py flattens this app's routes instead of mounting it under a
        # prefix (see app.py) -- issuer_url must match where they actually
        # end up, not include /mcp.
        issuer_url=ATLAS_PUBLIC_URL,
        # The resource itself is still genuinely at /mcp -- this drives the
        # RFC 9728 protected-resource metadata path and content, independent
        # of where the AS's own operational endpoints live.
        resource_server_url=f"{ATLAS_PUBLIC_URL}/mcp",
        client_registration_options=ClientRegistrationOptions(
            enabled=True, valid_scopes=["mcp"], default_scopes=["mcp"]
        ),
        revocation_options=RevocationOptions(enabled=True),
    )
    if OAUTH_ENABLED
    else None,
)

# --------------------------------------------------------------------------
# tools
# --------------------------------------------------------------------------


class ListInput(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    status: Optional[Literal[tuple(STATUS)]] = Field(  # type: ignore[valid-type]
        default=None, description="Filter by status, e.g. 'active'."
    )
    priority: Optional[Literal["S", "A", "B", "C", "D"]] = Field(
        default=None, description="Filter by strategic priority. S is critical."
    )
    category: Optional[str] = Field(default=None, description="e.g. 'ml', 'hardware', 'writing'.")
    tag: Optional[str] = Field(default=None, description="Single tag that must be present.")
    limit: int = Field(default=30, ge=1, le=200)
    offset: int = Field(default=0, ge=0)


@mcp.tool(
    name="atlas_list_projects",
    annotations={"title": "List Atlas projects", "readOnlyHint": True, "openWorldHint": False},
)
def atlas_list_projects(params: ListInput) -> str:
    """List projects in the Atlas, newest-relevant first, with optional filters.

    Returns a compact markdown list (id, name, status, priority, completion).
    Call atlas_get_project for the full record of any id.
    """
    hits = store.filter(params.status, params.priority, params.category, params.tag)
    page = hits[params.offset : params.offset + params.limit]
    if not page:
        return "No projects match. Try atlas_list_projects with no filters."
    head = f"{len(hits)} project(s) matched, showing {params.offset + 1}–{params.offset + len(page)}:\n"
    return head + "\n".join(p.summary_line() for p in page)


class GetInput(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    id: str = Field(..., description="Project id/slug, e.g. 'my-project'.", min_length=1)
    sections: Optional[list[str]] = Field(
        default=None,
        description=f"Only return these sections. One of: {SECTIONS + ['Log']}. Omit for all.",
    )
    log_limit: int = Field(default=15, ge=0, le=200, description="Most recent log entries to include.")


@mcp.tool(
    name="atlas_get_project",
    annotations={"title": "Read a project", "readOnlyHint": True, "openWorldHint": False},
)
def atlas_get_project(params: GetInput) -> str:
    """Read one project: metadata, requested sections and the most recent log entries."""
    p = store.load(params.id)
    audit("atlas_get_project", p.id)
    out = [f"# {p.name} (`{p.id}`)", "```yaml\n" + _yaml(p.meta) + "\n```"]
    wanted = params.sections or SECTIONS
    for s in wanted:
        text = p.section(s)
        if text and text != "_tbd_":
            out.append(f"## {s}\n{text}")
    log = p.section("Log")
    if params.log_limit and log:
        lines = [l for l in log.splitlines() if l.strip().startswith("- ")]
        out.append("## Log (most recent)\n" + "\n".join(lines[-params.log_limit :]))
    return "\n\n".join(out)


class SearchInput(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    query: str = Field(..., description="Free-text terms, e.g. 'mamba encoder walk-forward'.", min_length=1)
    limit: int = Field(default=8, ge=1, le=50)


@mcp.tool(
    name="atlas_search",
    annotations={"title": "Search the Atlas", "readOnlyHint": True, "openWorldHint": False},
)
def atlas_search(params: SearchInput) -> str:
    """Full-text search across all projects. Use this first when the user
    references a project by an informal name."""
    hits = store.search(params.query, params.limit)
    if not hits:
        return f"Nothing found for '{params.query}'. Try atlas_list_projects to see what exists."
    return "\n\n".join(
        f"**{p.name}** (`{p.id}`, {p.meta.get('status','?')}) — score {score}\n> {snip}"
        for p, snip, score in hits
    )


class UpsertInput(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    id: str = Field(..., description="Slug id. Created if it does not exist.", min_length=1)
    name: Optional[str] = Field(default=None, description="Human-readable project name.")
    status: Optional[Literal[tuple(STATUS)]] = None  # type: ignore[valid-type]
    priority: Optional[Literal["S", "A", "B", "C", "D"]] = None
    category: Optional[str] = None
    completion: Optional[int] = Field(default=None, ge=0, le=100, description="Percent done.")
    tags: Optional[list[str]] = Field(default=None, max_length=20)
    links: Optional[list[str]] = Field(default=None, max_length=20, description="URLs or repo paths.")
    sensitivity: Optional[Literal["public", "internal", "confidential", "secret"]] = Field(
        default=None,
        description="Classification. Default 'internal'. Records above this "
        "instance's clearance cannot be written or read here.",
    )
    section: Optional[str] = Field(
        default=None, description=f"Section to rewrite. One of: {SECTIONS}."
    )
    content: Optional[str] = Field(default=None, description="New markdown for that section.")


@mcp.tool(
    name="atlas_upsert_project",
    annotations={
        "title": "Create or update a project",
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": True,
    },
)
def atlas_upsert_project(params: UpsertInput) -> str:
    """Create a project or update its metadata and at most one section.

    Rewriting a section replaces it. For incremental facts, decisions or
    progress use atlas_append_entry instead — it never destroys history.
    """
    pid = slugify(params.id)
    created = not store.exists(pid)
    if created:
        p = Project(
            id=pid,
            meta={
                "name": params.name or params.id,
                "category": params.category or "unsorted",
                "status": params.status or "concept",
                "priority": params.priority or "C",
                "completion": params.completion or 0,
                "created": utcnow(),
                "tags": params.tags or [],
                "links": params.links or [],
                "sensitivity": params.sensitivity or "internal",
            },
            body=new_project_body(),
        )
    else:
        p = store.load(pid)
        for key in ("name", "status", "priority", "category", "completion", "tags",
                    "links", "sensitivity"):
            val = getattr(params, key)
            if val is not None:
                p.meta[key] = val

    if params.section:
        if params.section not in SECTIONS:
            raise AtlasError(f"Unknown section '{params.section}'. Allowed: {SECTIONS}.")
        if not params.content:
            raise AtlasError("Pass 'content' together with 'section'.")
        p.set_section(params.section, params.content)

    store.save(p, f"atlas: {'create' if created else 'update'} {pid}")
    audit("atlas_upsert_project", pid, "created" if created else "updated")
    return f"{'Created' if created else 'Updated'} `{pid}`.\n" + p.summary_line()


class AppendInput(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    id: str = Field(..., description="Project id/slug.", min_length=1)
    kind: Literal["decision", "note", "log", "question", "result", "idea"] = Field(
        ..., description="decision = a choice + its reason; result = measured outcome."
    )
    text: str = Field(..., description="One or two sentences. Include the 'why' for decisions.", min_length=1)
    author: str = Field(default="claude", description="Which assistant or person is writing.")


@mcp.tool(
    name="atlas_append_entry",
    annotations={
        "title": "Append to a project log",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
    },
)
def atlas_append_entry(params: AppendInput) -> str:
    """Append a dated, attributed entry to a project's append-only log.

    This is the safe default write: it can never lose existing content and is
    how continuity between different assistants is maintained.
    """
    p = store.load(params.id)
    entry = make_entry(params.kind, params.text, params.author)
    if "## Log" not in p.body:
        p.body = p.body.rstrip() + "\n\n## Log\n"
    p.body = p.body.rstrip() + "\n" + entry
    store.save(p, f"atlas: {params.kind} on {p.id}")
    audit("atlas_append_entry", p.id, params.kind)
    return f"Appended {params.kind} to `{p.id}`."


@mcp.tool(
    name="atlas_overview",
    annotations={"title": "Atlas overview", "readOnlyHint": True, "openWorldHint": False},
)
def atlas_overview() -> str:
    """Portfolio-level snapshot: counts per status/priority and the projects
    that have gone longest without an update. Good opening move for a review."""
    ps = store.all()
    if not ps:
        return "Atlas is empty. Create the first project with atlas_upsert_project."
    by_status: dict[str, int] = {}
    by_prio: dict[str, int] = {}
    for p in ps:
        by_status[p.meta.get("status", "?")] = by_status.get(p.meta.get("status", "?"), 0) + 1
        by_prio[p.meta.get("priority", "?")] = by_prio.get(p.meta.get("priority", "?"), 0) + 1
    stale = sorted(ps, key=lambda p: p.meta.get("updated", ""))[:5]
    return (
        f"{len(ps)} projects.\n"
        f"By status: {json.dumps(by_status)}\n"
        f"By priority: {json.dumps(by_prio)}\n\n"
        "Least recently touched:\n" + "\n".join(p.summary_line() for p in stale)
    )


# --------------------------------------------------------------------------
# resources + prompt
# --------------------------------------------------------------------------


@mcp.resource("atlas://instructions", mime_type="text/markdown")
def res_instructions() -> str:
    """The shared contract every assistant should follow when using the Atlas."""
    return INSTRUCTIONS


@mcp.resource("atlas://index", mime_type="text/markdown")
def res_index() -> str:
    """Index of all projects."""
    return "\n".join(p.summary_line() for p in store.filter())


@mcp.resource("atlas://project/{project_id}", mime_type="text/markdown")
def res_project(project_id: str) -> str:
    """Raw markdown of a single project file."""
    return store.load(project_id).to_markdown()


@mcp.prompt(name="atlas_review")
def prompt_review(scope: str = "active") -> str:
    """Quarterly-review prompt over the Atlas."""
    return (
        f"Use the Atlas tools to review all '{scope}' projects. For each: what "
        "moved since the last log entry, what is blocked, and what is the single "
        "highest-leverage next step. Then name one project that should be "
        "archived and justify it. Append your conclusions as 'note' entries."
    )


def _yaml(meta: dict[str, Any]) -> str:
    import yaml as _y

    return _y.safe_dump(meta, sort_keys=False, allow_unicode=True).strip()
