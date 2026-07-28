# Code review before exposure — TODO.md Phase 1.1

Read `store.py`, `server.py`, `app.py` looking for anything that could
disclose a record above clearance, or write unfiltered input to disk. Listed
first, fixed after, per TODO.md's instruction.

## Findings

1. **Unhandled exceptions leak their message verbatim (fixed).**
   `app.py`'s `on_error` mapped only `AtlasError`/`PermissionError`/`KeyError`
   to safe status codes; anything else fell through to
   `JSONResponse({"error": str(exc) or type(exc).__name__}, status_code=500)`.
   An unexpected exception (e.g. a `FileNotFoundError`, an `OSError` from a
   full disk) can carry a filesystem path in its message, which would then go
   straight to the client — CLAUDE.md invariant #6 forbids this. Fixed:
   unclassified exceptions now return a generic `{"error": "internal error"}`.

2. **No body-size or rate limit inside the app itself (fixed).**
   Only control was `LimitRequestBody 1048576` in the Apache vhost — real,
   but not active for `docker compose up` (app exposed directly) or if Apache
   is ever bypassed. Added an ASGI-level body-size cap and a per-IP sliding
   window rate limit in `app.py`, so the app is safe standalone; Apache's
   limit stays as the outer layer (defense in depth, not either/or).

3. **Path traversal — no proof, just an argument (fixed).**
   `_path()` slugifies every id before touching the filesystem; `slugify`
   collapses any run of non `[a-z0-9]` characters (including `/` and `.`) to
   a single `-`, so `../../etc/passwd`-shaped ids cannot produce a path
   segment outside `projects/`. Added `tests/test_store.py::test_no_traversal`
   proving it for `../../etc/passwd`, `..%2f..%2fx` (literal, not
   URL-decoded — passed through as a string same as any other id), `a/b`,
   and the empty string.

4. **Resource template clearance — no separate test needed.**
   `atlas://project/{id}` (`res_project`) is `store.load(project_id).to_markdown()`
   with no logic of its own, so it already inherits the same `AtlasDenied`
   gate exercised by `tests/test_store.py::security()` (item 2: "classified
   records are invisible to the low-clearance instance"). Adding a second,
   MCP-protocol-level test for the same code path would just be ceremony —
   noted here instead of duplicated.

5. **REST facade accepts arbitrary metadata keys (fixed).**
   The MCP write path (`UpsertInput`) is a Pydantic model with
   `extra="forbid"` and a `Literal["public","internal","confidential","secret"]`
   constraint on `sensitivity`. The REST facade's `api_upsert` instead did
   `p.meta.update({k: v for k, v in body.items() if k not in (...)})` — any
   JSON key the caller sent landed in the stored frontmatter unchecked. Not a
   disclosure bug (an invalid `sensitivity` value only ever fails closed, per
   `sensitivity_rank`'s fail-closed default), but it breaks parity between
   the two client surfaces and is unvalidated input at a trust boundary.
   Fixed: REST now allowlists the same fields the MCP tool accepts.

6. **CORS is wide open (`allow_origins=["*"]`) — flagged, not changed.**
   Not currently exploitable: none of today's clients (Claude's connector,
   ChatGPT Actions, curl/RAG scripts) are same-origin browser fetches, and
   auth is a Bearer header, not a cookie, so there's no ambient credential
   for a third-party page to ride on. Becomes a real risk once the
   "client-side app for individual note-taking" mentioned in this session
   exists and holds a token in browser JS reachable from any origin —
   tighten `allow_origins` to that app's actual origin when it's built, not
   before (there's nothing correct to allowlist yet).

7. **Already handled by the code as delivered, not something I added:**
   PII tripwire on every write (`scan_pii`), clearance gate covering
   read/list/search/resource/write (`_visible`), fail-closed on unknown
   `sensitivity` labels, metadata-only audit log, atomic writes under an
   `flock`. All covered by `tests/test_store.py::security()`.

## Separate from the Phase 1 checklist: test fixtures contained real content

`tests/test_store.py`, `tests/test_e2e.py`, and one example string each in
`store.py`/`server.py` reused `candlebot` — a real, active project id from
the actual Atlas — as a test fixture, and `test_e2e.py`'s fixture body was a
near-verbatim copy of that project's real Summary section. CLAUDE.md
invariant #3 is explicit: "No test fixture may contain real note content."
Replaced with fictional `demo-widget`/`demo-gadget` fixtures and generic
example strings; behavior of the tests is unchanged, only the content.
