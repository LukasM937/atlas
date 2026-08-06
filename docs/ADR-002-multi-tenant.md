# ADR-002: Multi-tenant Atlas — registry + invite links (MCP first)

## Status

Accepted, implemented for both MCP and REST (REST landed 2026-08-06,
triggered exactly as anticipated below — the iOS app's Setup screen
gaining "Log in with GitHub"). See "Unifying REST onto OAuth" for what
that changed and why it was safe to build once that trigger fired.

## Context

The original plan for onboarding a second person (a family member) was a
fully separate instance: its own domain (`atlas2.muehrke.de`), its own
Docker container, its own GitHub OAuth App. That's a legitimate design,
but with no deadline forcing it, running N instances for N people doesn't
scale past "a couple of family members" and throws away the actual
opportunity: a proper single-server multi-tenant design, reasoned through
once, that also covers larger cases (a small team, a family, in principle
a company) without re-deriving the architecture each time someone new
needs access.

Two things, checked directly rather than assumed, made this tractable to
build now instead of deferring it further:

1. **No one but the admin ever registers anything on GitHub.** GitHub
   OAuth Apps are a one-time, admin-side registration (already done for
   ADR-001). Every additional person only needs a GitHub account and to
   click "Log in with GitHub" — same as before, just against a broader
   allow-list.
2. **MCP tool functions can read per-request identity.** Confirmed by
   reading the SDK source directly: `AuthContextMiddleware` (already
   wired into `app.py` from ADR-001, for an unrelated reason) sets a
   `contextvars.ContextVar` holding the authenticated identity for the
   duration of each request, exposed via
   `mcp.server.auth.middleware.auth_context.get_access_token()`. Safe
   per-request even though the server is one process — each request gets
   its own context, not a shared mutable global.

## Decision

**Identity-based tenancy, not path-based.** Considered
`atlas.muehrke.de/u/<name>/mcp` first; rejected once actually designing it
for real. With identity-based resolution, "your data" is always exactly
"the store belonging to whoever GitHub says you are" — there's no separate
"is this identity allowed to see this path" check to get wrong. Removes an
entire class of possible tenant-confusion bugs versus a scheme where
identity and requested-path are two things that have to be checked against
each other.

**Registry membership is the authorization check.** `TenantRegistry`
(`$ATLAS_ROOT/tenants.json`) replaces the single `ATLAS_GITHUB_ALLOWED_USER`
string comparison from ADR-001 with `username in registry`. On first boot
with an empty registry, `ATLAS_GITHUB_ALLOWED_USER` is auto-registered as
tenant #1 — an existing `.env` needs zero changes to keep working exactly
as before.

**Invite links are the onboarding path**, not a second admin-managed
allow-list to edit by hand. `InviteRegistry` (`$ATLAS_ROOT/invites.json`)
issues an unguessable, single-use, time-limited token
(`python -m atlas_mcp.invite`). Visiting `/invite/<token>` kicks off a
GitHub login; on success the token is atomically consumed (can never be
redeemed twice, even under a race) and the resulting username is added to
the tenant registry. Possession of the link is the access control —
invites are deliberately *not* pre-bound to a specific GitHub username,
matching "here's a link, whoever gets there first with it is in."

**Each tenant gets its own `AtlasStore`**, rooted at
`tenants/<slugify(username)>/`, reusing `AtlasStore` completely unchanged
— it already accepted an arbitrary `root`; nothing about the store itself
needed to know about tenancy. `get_current_store()` in `server.py` resolves
which one to use per request: `get_access_token().subject` in OAuth mode,
the single legacy global `store` in old path-secret fallback mode (that
mode stays genuinely single-tenant — it's an emergency fallback, not
somewhere to add multi-tenant complexity).

`$ATLAS_ROOT/oauth_state.json` (registered MCP clients, issued OAuth
tokens) stays exactly where it was — that's Claude's/ChatGPT's own client
registration state, not tenant data. One `GitHubOAuthProvider` continues
to serve every tenant; only the allow-check and the resulting
`AccessToken.subject` differ per login.

### Tenant directory naming

`slugify(github_username)`, no separate opaque tenant ID. Considered
decoupling the directory name from the username (survives a GitHub
username rename without touching the filesystem), but for the actual
scale here the added indirection isn't worth it. If a username is ever
renamed, that's a manual one-time directory rename + registry edit — a
known, bounded cost, not a silently-waiting design gap.

### Git per tenant

Each tenant's `AtlasStore` commits inside its own root, so each tenant
directory needs its own `.git` — a fresh `git init` on first provisioning
for anyone but the original owner (whose existing `.git` is *moved*
alongside `projects/` during migration, not recreated — see
`deploy/migrate_to_tenants.py`). The Dockerfile's
`git config --system --add safe.directory /data` (added in ADR-001 to fix
"dubious ownership" on the bind-mounted volume) only exempted that one
exact path. Changed to `safe.directory '*'` — a real documented wildcard
value, not a glob — since enumerating tenant paths at image-build time
doesn't work once tenants are added at runtime. This check is a
Docker-bind-mount ownership artifact, not a real multi-user OS boundary
inside the container, so widening it doesn't weaken anything that was
actually protecting tenant data from each other.

## Unifying REST onto OAuth (built 2026-08-06)

Originally deferred: nothing needed REST to be multi-tenant while the
invited family member was MCP-only and the iOS app didn't exist yet.
Built once its actual trigger fired — the iOS app's Setup screen gaining
"Log in with GitHub" — exactly as this ADR anticipated, not on a
schedule.

What changed, in `app.py`:

- `_auth()` (sync, pass/fail, always the single global `store`) was
  replaced by `async def _resolve_store(request) -> AtlasStore`. Accepts
  either credential, an OR:
  - A valid OAuth access token — resolved via `oauth_provider
    .load_access_token()` (the exact check `ProviderTokenVerifier` already
    did for MCP) to `AccessToken.subject`, then to that identity's tenant
    store via `get_store_for()` — the same resolution `get_current_store()`
    uses for MCP tool calls.
  - The static `ATLAS_TOKEN` — at this point kept as a deprecated fallback,
    not retired yet (superseded below). In OAuth mode it resolved to the
    *owner's* own tenant (`GITHUB_ALLOWED_USER`) rather than the old single
    global `store`, which the tenant migration left empty. Without that
    remapping, every existing static-token caller (curl, scripts, and the
    iOS app's pre-OAuth token path) would have silently started seeing
    nothing after the migration — this is what actually surfaced the gap:
    the iOS app authenticated fine post-migration but the projects list
    came back empty, tracing straight back to `_auth()` still reading the
    pre-migration root `store`.
  - Timing-safe comparison (`secrets.compare_digest`) kept for the static
    token check; OAuth tokens are opaque random strings looked up by exact
    match in the provider's own token table, same as MCP.
- All six REST handlers (`api_list`, `api_get`, `api_search`, `api_append`,
  `api_delete`, `api_upsert`) now call `await _resolve_store(request)` and
  operate on the returned per-request store instead of the module-level
  `store` global.

The client side (Atlas Notes, the iOS app) added full OAuth 2.1 + PKCE +
`ASWebAuthenticationSession` "Log in with GitHub" as the primary Setup
option, with the static token initially kept as an "Advanced, deprecated"
fallback in the Setup screen.

### Static REST token retired (also 2026-08-06, once GitHub login was confirmed working)

Deprecating something that still works quietly becomes permanent if
nothing ever forces the question. Here the trigger was concrete and fast:
GitHub login was verified working end to end (real device, real server)
within the same day, at which point there was no remaining reason to keep
a second, weaker credential alive. `_resolve_store()` now branches once on
`OAUTH_ENABLED`, not per-request per-credential:

- **OAuth mode**: only a valid OAuth access token is accepted. The static
  `ATLAS_TOKEN` branch is gone from this path entirely — a request bearing
  it gets the same 401 as any other invalid token, not a resolved store.
- **Fallback mode** (`OAUTH_ENABLED` false — OAuth not configured at all,
  a genuinely different deployment shape): unchanged, static `ATLAS_TOKEN`
  is still the sole credential, still resolves to the single global
  `store`. This was never the deprecated path and isn't affected.

`ATLAS_TOKEN` the *environment variable* is untouched — `docker-compose.yml`
still requires it unconditionally, and it's still what fallback mode runs
on. What changed is narrower: once OAuth is live, that value simply stops
being an accepted REST credential.

Regression coverage, one file per mode (each decides `OAUTH_ENABLED` from
env vars at import time, so they can't share a process):
`tests/test_rest_auth.py` — an OAuth token resolves to its own subject's
tenant and never anyone else's, and the static token is now explicitly
rejected in OAuth mode. `tests/test_rest_auth_fallback.py` — the static
token still authenticates, unaffected, with OAuth unconfigured.

## Consequences

- Sysadmin-with-root-access honesty from the original multi-user
  discussion is unchanged by this design: per-tenant directories are a
  logical isolation boundary enforced by the application, not an OS-level
  permission boundary. Whoever can read the disk (the admin, root) can
  still read every tenant's files directly. `SECURITY.md` says this
  plainly rather than implying stronger isolation than actually exists.
- `tests/test_tenants.py` adds a cross-tenant isolation test as a
  regression guard: writing through one tenant's store must never be
  visible through another's `all()`/`search()`/`load()`. This is the test
  that would catch a real leak if this logic is ever touched again.
- The live server's existing 43 projects need one manual migration step
  (`deploy/migrate_to_tenants.py`) before this ships to production — not
  automatic, since it touches real private data and moves its git
  history; see the script's own docstring for the exact procedure.
