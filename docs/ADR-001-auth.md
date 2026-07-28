# ADR-001: MCP authentication — GitHub-backed OAuth proxy

## Status

Accepted, implemented. Rollout in progress (old path-secret scheme kept
live in parallel until the new one is confirmed working end to end).

## Context

The original `/mcp/<ATLAS_TOKEN>/` path-secret scheme was documented from
the start as a stopgap (README.md, SECURITY.md T3) — Claude's connector
dialog has no field for a static bearer token, so the secret went in the
URL path instead. That was known to be weak, but was assumed to at least
*work* for basic connectivity, with the real OAuth upgrade deferred to
"later."

That assumption turned out to be wrong. In practice, both Claude and
ChatGPT's connector setup actively attempt OAuth discovery and dynamic
client registration (DCR) against the server before completing setup —
they don't gracefully fall back to treating the URL as a no-auth or
secret-bearing connection when no OAuth metadata is found. Claude's actual
error: *"Registrierung beim Anmeldedienst von Atlas fehlgeschlagen... du
kannst... eine OAuth Client ID hinzufügen"* ("registration with Atlas's
login service failed... you can add an OAuth Client ID"). This makes Phase 4
a connectivity blocker, not an optional hardening step.

## Decision

Implement option 2 from README's original upgrade path: front the MCP
endpoint with an OAuth proxy against GitHub, rather than (a) a from-scratch
full authorization server with our own user/password handling, or (b) a
self-hosted IdP (Authentik/Keycloak) that would be one more service to run
and maintain on an already multi-service host.

GitHub is used purely as an **identity check**, not for any authorization
scope — this is a single-owner personal server, so "authorized" means
exactly one thing: the caller successfully logged into the one allow-listed
GitHub account (`ATLAS_GITHUB_ALLOWED_USER`). Anyone else who completes
GitHub's login screen is rejected at the callback step before any MCP token
is ever issued.

### Why not the standalone `fastmcp` package's `OAuthProxy`

That's the more turnkey option and was the original placeholder in
README's upgrade-path text. Went with a from-scratch provider instead,
using primitives already in the `mcp` SDK we're pinned to
(`mcp.server.auth.provider.OAuthAuthorizationServerProvider`,
`mcp.server.auth.routes.create_auth_routes`) rather than adding a second,
differently-named "FastMCP" package alongside `mcp.server.fastmcp.FastMCP` —
avoids a dependency that would be confusing to reason about later (two
same-named-but-different implementations in one codebase) for a proxy that
turned out to be a few hundred lines of storage/business logic once the
SDK's own route-building machinery is doing the HTTP/PKCE/DCR mechanics.

### Shape of the implementation

- `atlas_mcp/github_oauth.py`: `GitHubOAuthProvider`, implementing the
  `OAuthAuthorizationServerProvider` protocol. State (registered DCR
  clients, issued codes/tokens) persists as JSON next to the note store
  (`$ATLAS_ROOT/oauth_state.json`) — plain file, not a database, consistent
  with the rest of this project. Pending GitHub-redirect state is in-memory
  only; a mid-login restart just means retrying.
- `authorize()` redirects the user's browser to GitHub's real login rather
  than showing any login UI of our own. GitHub's callback
  (`/oauth/github/callback` in `app.py`) exchanges the code, checks the
  resulting username against `ATLAS_GITHUB_ALLOWED_USER`, and only then
  mints our own authorization code and redirects back to the original MCP
  client's `redirect_uri`.
- `server.py` wires this in **conditionally**: `ATLAS_PUBLIC_URL`,
  `ATLAS_GITHUB_CLIENT_ID`, `ATLAS_GITHUB_CLIENT_SECRET`,
  `ATLAS_GITHUB_ALLOWED_USER` all unset (the default) means FastMCP gets no
  `auth_server_provider` at all, and the original `/mcp/<ATLAS_TOKEN>/`
  path-secret scheme runs exactly as before. Setting all four switches the
  same instance to OAuth on a fixed `/mcp` path instead. One instance, one
  mode at a time — FastMCP's own auth middleware applies uniformly to
  whichever mount it's given, so there's no way to run both simultaneously
  on the same process. Reverting is an env-var change + redeploy, not a
  code change.
- `issuer_url`/`resource_server_url` must include the `/mcp` mount prefix
  (`f"{ATLAS_PUBLIC_URL}/mcp"`), not the bare domain — FastMCP mounts
  `/authorize`, `/token`, `/register`, `/revoke` relative to wherever its
  own ASGI app is mounted in `app.py`. Missed this on the first pass
  (caught by testing the discovery metadata against the actual routes
  before ever pointing a real OAuth client at it) — worth calling out here
  since it's an easy mistake to reintroduce if this ever gets refactored.

### What's deliberately NOT changed

The REST facade (`/api/*`) keeps its existing static Bearer (`ATLAS_TOKEN`)
scheme for now. No concrete evidence yet that ChatGPT's Custom GPT Actions
flow has the same OAuth-discovery-required behavior Claude's connector
does — REST already works today, confirmed via a 401 on unauthenticated
`/api/projects` and a 200 on `/openapi.json`. Revisit only if a concrete
ChatGPT error surfaces, same standard of evidence this decision itself was
made on.

## Consequences

- The Apache `Require ip 160.79.104.0/21` restriction on `/mcp/` has to
  come off once this is confirmed working: the OAuth `/authorize` step is a
  browser redirect originating from the user's own IP, not Anthropic's
  range, so keeping that restriction would block the login step itself.
  Sequencing: verify the full flow first using the vhost's existing
  commented-out home-IP escape hatch, *then* remove the allowlist entirely
  — not the other way around, so the old path-secret scheme (which does
  still rely partly on that IP restriction as a layered control) isn't
  weakened before its replacement is confirmed live.
- `$ATLAS_ROOT/oauth_state.json` is a new sensitive file (holds issued
  tokens) — lives directly under `$ATLAS_ROOT` (a sibling of `projects/`),
  which for the Docker deployment is `./data`, already excluded wholesale
  by `.gitignore`'s `data/` entry. Same trust tier as the note store itself.
- New direct dependency: `httpx` (used for the GitHub token exchange and
  user-identity lookup) — already a transitive dependency of `mcp` itself,
  but declaring it directly since we now import it ourselves rather than
  relying on it staying transitively available.
