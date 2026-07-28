# atlas-mcp

A shared note/knowledge layer for every LLM you use. Markdown files on your
server, exposed as an MCP server (Claude) and a REST+OpenAPI API (ChatGPT
Actions, scripts, local models). See `ATLAS_SPEC.md` for the design.

Status: **working first test** — protocol handshake, all six tools, resources,
prompt, REST facade and cross-client write/read verified locally.

## Run locally

```bash
pip install -r requirements.txt
export ATLAS_TOKEN=$(openssl rand -base64 24 | tr -d '/+=')
export ATLAS_ROOT=./data ATLAS_GIT=1
python -m atlas_mcp.app          # prints the MCP URL, listens on :8787
python tests/test_store.py       # store unit tests
python tests/test_e2e.py         # full MCP + REST round trip (server must run)
```

`ATLAS_GIT=1` commits every write to `$ATLAS_ROOT` — run `git init` there first.

## Deploy on your server

```bash
docker compose up -d             # app on :8787, bind-mounts ./data
```

Put it behind TLS on a subdomain. Apache vhost, systemd unit, ufw script,
fail2ban jail and backup script are in `deploy/`; the deployment order and the
acceptance criteria for each step are in `TODO.md`. Read `SECURITY.md` first.

Two things Anthropic's docs make non-negotiable:

- **The server must be reachable from the public internet.** Claude connects to
  your MCP server from Anthropic's cloud, not from your phone or laptop — this
  holds for claude.ai, Desktop, Cowork and the mobile apps alike. A server on
  your LAN, behind Tailscale or behind a VPN will not connect.
- If it sits behind a firewall, allowlist Anthropic's published IP ranges
  (platform.claude.com/docs/en/api/ip-addresses) rather than opening it wide.

## Add it to Claude

1. On **claude.ai** (web or desktop — not the phone): Customize → Connectors →
   "+" → *Add custom connector*.
2. URL: `https://atlas.example.de/mcp/<ATLAS_TOKEN>/` (trailing slash).
3. Add. Connectors are account-level, so once added it appears in the **iOS and
   Android apps** too — enable it per conversation via the "+" → Connectors
   toggle. Adding a *custom* connector is a web/desktop action; using it is not.
4. In a chat: *"Use the Atlas: what's the state of candlebot?"*

## Add it to ChatGPT / anything else

Custom GPT → Actions → import `https://atlas.example.de/openapi.json`, auth
type Bearer, paste the same `ATLAS_TOKEN`. Local agents can either speak MCP at
the same URL or just read `$ATLAS_ROOT/projects/*.md` off disk.

## Security

Short version: everything the connector can read is transmitted to a third-party
model provider on every read, so classification comes before cryptography.
Projects carry a `sensitivity` label; the internet-facing process runs at
`internal` clearance and records above it are invisible to it — not filtered
in the response, but excluded inside the store. Writes containing identifiers
(IBAN, card, e-mail, phone, tax id, keys, tokens, JWT, DOB) are rejected. An
optional metadata-only audit log records tool, project and outcome, never
content. Full threat model and policy in `SECURITY.md`.

## Auth: what this test does, and the upgrade path

Claude's connector dialog only accepts a URL plus optional OAuth client
ID/secret — there is no field for a static bearer token. So the first test uses
an unguessable path segment as the credential (`/mcp/<48-bit-plus-secret>/`)
and a Bearer header for the REST side. That is adequate for a personal server
over TLS with IP allowlisting, and inadequate as a permanent answer: the secret
appears in server logs and cannot be rotated per client.

Upgrade path, in order of effort:

1. Keep the secret path, add fail2ban + Anthropic IP allowlist. (30 min)
2. Front it with an OAuth proxy (e.g. `fastmcp`'s `OAuthProxy` against GitHub
   or your own Authentik/Keycloak). Claude then runs a normal OAuth flow and
   you can revoke per client. (an evening)
3. Full OAuth 2.1 with dynamic client registration in-process, per MCP spec
   2025-06-18. (a weekend; only worth it if others use the server)

## Seed and render

```bash
python -m atlas_mcp.seed import seed/PROJECT_ATLAS.seed.md   # 43 projects, idempotent
python -m atlas_mcp.seed render PROJECT_ATLAS.md             # derived single-file view
```

`seed/PROJECT_ATLAS.seed.md` is one file containing every project file, split on
`<!-- project: id -->` markers. Import skips ids that already exist, so it can
never overwrite corrections (`--force` overrides). Everything in the seed is
reconstructed from conversation memory and carries `confidence: unverified` —
fix entries in the store, not in the seed.

`render` regenerates `PROJECT_ATLAS.md` (dashboard + summaries) from the store.
That file is derived: never edit it. Run it from cron if you want a pasteable
document for contexts without connectors.

## Layout

```
atlas_mcp/store.py    file store: frontmatter, atomic writes, search, git
atlas_mcp/server.py   MCP tools, resources, prompt, shared instructions
atlas_mcp/app.py      ASGI app: /mcp/<token>/, /api, /openapi.json, /healthz
atlas_mcp/seed.py     seed import + single-file render
deploy/               apache vhost, systemd unit, ufw, fail2ban, backups
data/projects/*.md    your notes — the actual product
seed/                 bootstrap seed (one file, all projects)
tests/                store unit tests + protocol-level e2e
```
