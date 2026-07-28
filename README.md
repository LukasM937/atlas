# atlas-mcp

A shared note/knowledge layer for every LLM you use. Markdown files on your
server, exposed as an MCP server (Claude) and a REST+OpenAPI API (ChatGPT
Actions, scripts, local models). See `ATLAS_SPEC.md` for the design.

Status: **working first test** — protocol handshake, all six tools, resources,
prompt, REST facade and cross-client write/read verified locally.

## Run locally

```bash
python3 -m venv .venv
source .venv/bin/activate              # Windows: .venv\Scripts\activate
python3 -m pip install -r requirements.txt
export ATLAS_TOKEN=$(openssl rand -base64 24 | tr -d '/+=')
export ATLAS_ROOT=./data ATLAS_GIT=1
python3 -m atlas_mcp.app          # prints the MCP URL, listens on :8787
python3 tests/test_store.py      # store unit tests
python3 tests/test_e2e.py        # full MCP + REST round trip (server must run)
```

`ATLAS_GIT=1` commits every write to `$ATLAS_ROOT` — run `git init` there first.

**Troubleshooting:**
- `error: externally-managed-environment` from pip means you're not inside
  the venv — run `source .venv/bin/activate` (you should see `(.venv)` in
  your prompt) rather than forcing the install with `--break-system-packages`
  or `sudo`.
- Packages installed but `atlas_mcp.app` still reports one as missing
  usually means `pip`/`python3` on your PATH resolve to two different
  Python installs. Always invoke both through the same interpreter —
  `python3 -m pip install ...` and `python3 -m atlas_mcp.app` — rather than
  the bare `pip`/`python` commands, and this can't happen.

## Deploy on your server

```bash
sudo ./deploy/setup.sh --domain atlas.example.com [--email <your-email>]
```

Builds and starts the app via Docker Compose (`docker-compose.yml`, app on
:8787 loopback-only, bind-mounts `./data`), generates an Apache vhost for the
given domain from `deploy/apache/atlas.conf.template`, bootstraps a TLS cert
via certbot if none exists yet, then checks connectivity — local first, then
this host's own view of the public hostname. Idempotent, safe to re-run
(e.g. after `git pull`). Does not touch `ufw` or install `fail2ban` — see
what it prints at the end for those as manual, reviewed steps, especially if
this host runs anything else (its ufw rules are almost certainly not just
about this app).

Read `SECURITY.md` first. The systemd unit, ufw script, fail2ban jail and
backup script in `deploy/` are for a single-purpose, non-Docker host instead
of the Compose path above; the deployment order and acceptance criteria for
each are in `TODO.md`.

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
2. URL:
   - GitHub OAuth mode (see Auth below): `https://atlas.example.de/mcp` — no
     secret in the URL; Claude will redirect you through GitHub login on add.
   - Path-secret mode (fallback): `https://atlas.example.de/mcp/<ATLAS_TOKEN>/`
     (trailing slash).
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

## Auth

Two schemes for the MCP endpoint, controlled by whether four env vars are
set (`ATLAS_PUBLIC_URL`, `ATLAS_GITHUB_CLIENT_ID`, `ATLAS_GITHUB_CLIENT_SECRET`,
`ATLAS_GITHUB_ALLOWED_USER` — see `deploy/atlas.env.example`):

- **Unset (default): path-secret.** An unguessable path segment as the
  credential (`/mcp/<48-bit-plus-secret>/`). Originally assumed adequate on
  its own; in practice both Claude and ChatGPT's connector setup attempt
  OAuth discovery/registration regardless and fail outright if none exists.
  Kept as a fallback, not a recommended steady state — see
  `docs/ADR-001-auth.md`.
- **Set: GitHub-backed OAuth**, on a fixed `/mcp` path (no secret in the
  URL). A real OAuth 2.1 + PKCE + dynamic client registration flow, proxied
  to GitHub for the actual login — GitHub here only proves identity;
  `ATLAS_GITHUB_ALLOWED_USER` is the single account allowed through.
  Full reasoning, and why not the standalone `fastmcp` package's
  `OAuthProxy`, in `docs/ADR-001-auth.md`.

REST (`/api/*`) is unaffected either way — still a static Bearer
(`ATLAS_TOKEN`), which has worked fine for ChatGPT Actions/scripts so far;
revisit only if that changes.

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
