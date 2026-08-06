# ADR-002: Multi-tenant Atlas — registry + invite links (MCP first)

## Status

Accepted, implemented for MCP. REST intentionally left single-tenant — see
"Unifying REST onto OAuth" below.

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

## Unifying REST onto OAuth (roadmap, not built)

`/api/*` still authenticates with the single static `ATLAS_TOKEN` and
still serves the one legacy global `store` — deliberately, not by
oversight. Nothing today needs REST to be multi-tenant: the invited
family member is a Claude/ChatGPT (MCP) user, and the iOS app that would
be the actual REST client doesn't exist yet (it currently talks to the
owner's own instance with the static token — see the client app's own
`CLAUDE.md`). Building REST multi-tenancy now would roughly double the
size and risk of this change for no user waiting on it.

What changes when this is picked up:

- `_auth()` in `app.py` needs to accept a valid OAuth access token in
  addition to the static bearer token — resolved via
  `oauth_provider.load_access_token()`, the same `ProviderTokenVerifier`
  already used for MCP. `AccessToken.subject` gives the same per-request
  identity `get_current_store()` already uses for MCP.
- REST handlers (`api_list`, `api_get`, etc.) switch from the module-level
  `store` to the same `get_current_store()`-style resolution MCP tools
  use — mechanical once `_auth()` can hand back an identity instead of
  just pass/fail.
- The static `ATLAS_TOKEN` is **not retired** when this happens. It stays
  as the owner's own credential (useful for curl/scripts/local tooling
  that doesn't want to do an OAuth dance) — the change is additive, an
  OR, not a replacement.

What triggers doing it: the iOS app's Setup screen gaining "Log in with
GitHub" as a connection option, which is the concrete moment REST actually
needs more than one identity. Not a date — a feature.

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
