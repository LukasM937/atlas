# atlas-mcp

A personal note/knowledge layer shared across every LLM you use. Markdown
files on your own server, exposed to Claude over MCP and to ChatGPT/scripts
over REST — every assistant reads and writes the same live store instead of
each holding its own stale copy. See `ATLAS_SPEC.md` for the design,
`SECURITY.md` for the threat model.

Status: deployed and working — MCP (GitHub-authenticated OAuth), REST, and
the full portfolio of projects all live and verified against real Claude and
ChatGPT sessions.

---

## Before you start: the one hard requirement

**Your server must be reachable over HTTPS from the public internet.**
Claude and ChatGPT connect to your MCP/REST endpoint from *their own cloud
infrastructure*, not from your phone or laptop. A server on your LAN, behind
Tailscale, or behind a VPN-only connection will not work, full stop —
there's no way around this, it's how the connector model works on both
platforms.

If you don't already have a public server, the cheapest path is:

1. **A small always-on Linux box at home.** A Raspberry Pi is the obvious
   choice (this project was built and is run on one) — cheap, low power,
   plenty for this workload. Any Debian-based box works the same way.
2. **A domain name.** Any registrar works. [do.de](https://www.do.de) (a
   German provider — usable regardless of where you live, the interface is
   just in German) is what this project actually uses, and includes free
   dynamic DNS, which you'll need next. Pick whichever registrar you like;
   nothing here depends on that specific one.
3. **Dynamic DNS.** Home internet connections almost never have a static
   public IP, so your domain needs to keep pointing at whatever IP you
   currently have. Most registrars (do.de included) offer a DDNS client or a
   simple cron-friendly update URL — set it up once, forget about it.
4. **Port forwarding on your router.** Forward ports 80 and 443 to your
   Pi's LAN IP. This step is entirely specific to your router's make and
   model — check its admin page for "port forwarding" or "virtual server."
   Nobody can write generic instructions for this part; you're on your own
   for your specific router.

Once your domain resolves to your home's public IP and 80/443 reach the Pi,
everything below just works.

**Apache2 vs. nginx**: `deploy/` ships an Apache vhost, for no deeper reason
than that's what this project happened to start with. For this exact job —
one TLS-terminating reverse proxy in front of one backend, with a couple of
path-based access rules — Apache2 and nginx are functionally equivalent.
If you already run nginx and would rather not add Apache, porting
`deploy/apache/atlas.conf.template` (`ProxyPass`/`<Location>` → `proxy_pass`/
`location`) is straightforward; nobody's written that config yet, so budget
some time if you go that route.

---

## Quick start: local dev (no server yet)

Useful for trying the store/tools out, or developing against it. Claude and
ChatGPT can't reach this — see the requirement above.

```bash
git clone <this repo>
cd atlas
python3 -m venv .venv
source .venv/bin/activate              # Windows: .venv\Scripts\activate
python3 -m pip install -r requirements.txt
export ATLAS_TOKEN=$(openssl rand -base64 24 | tr -d '/+=')
export ATLAS_ROOT=./data ATLAS_GIT=1
python3 -m atlas_mcp.app          # prints the MCP URL, listens on :8787
python3 tests/test_store.py       # store unit tests
python3 tests/test_e2e.py         # full MCP + REST round trip (server must run)
```

`ATLAS_GIT=1` commits every write to `$ATLAS_ROOT` — run `git init` there
first, or just leave it unset for local experiments.

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

---

## Deploy for real

### 1. Prerequisites on the server

```bash
sudo apt update
sudo apt install -y apache2 certbot python3-certbot-apache docker.io docker-compose-plugin git
```

### 2. Get the code and bring it up

```bash
git clone <this repo> ~/atlas   # or wherever you keep it
cd ~/atlas
sudo ./deploy/setup.sh --domain your.domain.example --email <your-email>
```

`deploy/setup.sh` is idempotent — safe to re-run any time (e.g. after
`git pull`). In one pass it:

- generates `.env` with a fresh `ATLAS_TOKEN` if one doesn't exist yet;
- builds and starts the app via Docker Compose (bound to `127.0.0.1:8787`
  only — never exposed directly);
- issues a TLS certificate via certbot if none exists for the domain yet;
- writes and enables the Apache vhost from `deploy/apache/atlas.conf.template`;
- checks connectivity: local direct to the backend, local through Apache
  with the correct SNI, and this host's own view of the public hostname.

It does **not** touch `ufw` or install `fail2ban` — those are left as manual
steps (printed at the end) since your host may run other things with their
own firewall rules already.

`--email` is only used the first time a certificate is issued (for Let's
Encrypt renewal reminders); harmless to omit or to pass on every run.

---

## Connect Claude and ChatGPT

Both work the same way, via the same OAuth-protected MCP endpoint. Recommend
setting up OAuth even if it feels like the extra step — see why below.

### Set up GitHub OAuth (recommended, ~5 minutes)

MCP needs *some* auth mechanism, and both Claude's and ChatGPT's connector
setup insist on a real OAuth flow — they attempt registration/discovery
regardless of what URL you give them, and fail outright (not gracefully) if
the server doesn't speak OAuth at all. This project proxies that OAuth flow
to GitHub: GitHub only proves *who you are*, one specific GitHub account is
allow-listed as the only one that gets in. Full reasoning in
`docs/ADR-001-auth.md`.

1. GitHub → Settings → Developer settings → OAuth Apps → **New OAuth App**
   (or go straight to
   [github.com/settings/applications/new](https://github.com/settings/applications/new)).
2. Fill in:
   - **Application name**: anything, e.g. `Atlas MCP`
   - **Homepage URL**: `https://your.domain.example`
   - **Authorization callback URL**: `https://your.domain.example/oauth/github/callback`
3. Register. Copy the **Client ID**, generate a **Client Secret** and copy
   it too (shown once).
4. On the server, add to `.env` (next to the `ATLAS_TOKEN` line
   `deploy/setup.sh` already created):
   ```
   ATLAS_PUBLIC_URL=https://your.domain.example
   ATLAS_GITHUB_CLIENT_ID=<the client id>
   ATLAS_GITHUB_CLIENT_SECRET=<the client secret>
   ATLAS_GITHUB_ALLOWED_USER=<your GitHub username>
   ```
5. Re-run `sudo ./deploy/setup.sh --domain your.domain.example` to rebuild
   and pick up the new environment.

Then, in **Claude** (claude.ai, web or desktop — not the phone): Customize →
Connectors → "+" → *Add custom connector* → URL `https://your.domain.example/mcp`
(no secret in the URL) → Add. Claude redirects you through GitHub login;
once your allow-listed account approves, the connector attaches. It then
also shows up in the iOS/Android apps (toggle per-conversation via "+" →
Connectors).

In **ChatGPT**: Settings → Connectors → *Add connector* → same URL,
`https://your.domain.example/mcp`. Same GitHub login step.

Test in either: *"Use the Atlas: give me an overview of my projects."*

### Fallback: skip OAuth, use a path secret instead

Leave the four `ATLAS_GITHUB_*`/`ATLAS_PUBLIC_URL` variables unset and the
server falls back to an unguessable path segment as the credential instead:
`https://your.domain.example/mcp/<ATLAS_TOKEN>/` (trailing slash matters).

This was the original design and is kept for a reason (see
`docs/ADR-001-auth.md`), but **in practice it's not reliable** — both
Claude's and ChatGPT's connector UIs try to negotiate OAuth regardless of
what you paste in, and error out instead of falling back gracefully. Treat
this as an emergency/offline fallback, not the default.

### REST, for scripts or a Custom GPT's Actions

`/api/*` always uses a plain Bearer token (the same `ATLAS_TOKEN`),
independent of whichever MCP scheme above is active:

Custom GPT → Actions → import `https://your.domain.example/openapi.json`,
auth type Bearer, paste `ATLAS_TOKEN`. Or just `curl -H "Authorization:
Bearer $ATLAS_TOKEN" https://your.domain.example/api/projects`.

---

## Environment variables

All read from `.env` next to `docker-compose.yml` (Docker deployment) or
`/etc/atlas/atlas.env` (systemd deployment, see `deploy/systemd/`).

| Variable | Required? | Purpose |
|---|---|---|
| `ATLAS_TOKEN` | yes | Bearer token for `/api/*`; also the MCP path secret in fallback auth mode. |
| `ATLAS_ROOT` | yes (has a default) | Where the store lives. `/data` for Docker (bind-mounted), `./data` for local dev. |
| `ATLAS_GIT` | no | `1` to git-commit every write inside `$ATLAS_ROOT`. |
| `ATLAS_MAX_SENSITIVITY` | no | Clearance of this process — records above it are invisible, not just hidden. Default `internal`; do not raise it on the internet-facing instance. |
| `ATLAS_AUDIT_LOG` | no | Path for a metadata-only audit log (tool, project id, outcome — never content). Unset disables it. |
| `ATLAS_PUBLIC_URL` | only for OAuth | Your server's public HTTPS origin, e.g. `https://your.domain.example`. |
| `ATLAS_GITHUB_CLIENT_ID` | only for OAuth | From the GitHub OAuth App. |
| `ATLAS_GITHUB_CLIENT_SECRET` | only for OAuth | From the GitHub OAuth App. Keep this out of git — it already is, `.env` is gitignored. |
| `ATLAS_GITHUB_ALLOWED_USER` | only for OAuth | The one GitHub username allowed to authenticate. |

The four OAuth variables are all-or-nothing: set all four to enable it, leave
all four unset for the fallback scheme. See `deploy/atlas.env.example` for a
copy-pasteable template.

---

## Security

Short version: everything a connector can read is transmitted to a
third-party model provider on every read, so classification comes before
cryptography. Projects carry a `sensitivity` label; the internet-facing
process runs at `internal` clearance and anything above it is invisible to
it — excluded inside the store, not just filtered from the response. Writes
containing identifiers (IBAN, card, e-mail, phone, tax id, keys, tokens,
JWT, DOB) are rejected outright. An optional metadata-only audit log records
tool, project and outcome, never content. Full threat model and policy in
`SECURITY.md`; the OAuth design specifically in `docs/ADR-001-auth.md`.

---

## Seed and render

```bash
python -m atlas_mcp.seed import seed/PROJECT_ATLAS.seed.md   # bootstrap, idempotent
python -m atlas_mcp.seed render PROJECT_ATLAS.md              # derived single-file view
```

`import` reads a single file containing every project, split on
`<!-- project: id -->` markers, and skips ids that already exist — a
re-import can never overwrite corrections you've since made (`--force`
overrides that). `render` regenerates `PROJECT_ATLAS.md` (dashboard +
summaries) from the live store; that file is derived — never hand-edit it.

---

## Layout

```
atlas_mcp/store.py       file store: frontmatter, atomic writes, search, git
atlas_mcp/server.py      MCP tools, resources, prompt, OAuth wiring
atlas_mcp/app.py         ASGI app: /mcp, /oauth/github/callback, /api, /openapi.json, /healthz
atlas_mcp/github_oauth.py  GitHub-backed OAuth authorization server provider
atlas_mcp/seed.py        seed import + single-file render
deploy/                  setup.sh, apache vhost template, systemd unit, ufw, fail2ban, backups
docs/                    ADR-001-auth.md (OAuth design), REVIEW.md (security review)
data/projects/*.md       your notes — the actual product (gitignored, never committed)
seed/                    bootstrap seed (one file, all projects)
tests/                   store unit tests + protocol-level e2e
```

---

## Troubleshooting

- **`ModuleNotFoundError: mcp.server.fastmcp`** after a fresh install: a
  breaking `mcp` 2.0.0 release removed the API this project is built on.
  `requirements.txt` pins `mcp<2.0` already — if you still hit this, your
  environment (or Docker image) is stale; reinstall/rebuild.
- **Connector fails to attach in Claude/ChatGPT with no useful error**:
  almost always an auth/discovery problem, not a store problem. Set up
  OAuth (above) rather than debugging the path-secret fallback further —
  see `docs/ADR-001-auth.md` for the specific failure modes this project
  actually hit (and fixed) getting OAuth working.
- **`421 Invalid Host header`**: the app's DNS-rebinding protection doesn't
  recognize your domain. Confirm `ATLAS_PUBLIC_URL` matches exactly what
  clients connect to (scheme + host, no trailing slash).
- **You add a new env var and the app doesn't see it (Docker deployment)**:
  variables in `.env` are used by `docker compose` for `${VAR}`
  interpolation in `docker-compose.yml`, but are **not** auto-injected into
  the container — every variable the app reads must be listed explicitly
  under `environment:` in `docker-compose.yml`, or it's silently empty.
- **`docker compose exec atlas git ...` fails with "dubious ownership"**:
  already handled for you (`git config --system --add safe.directory /data`
  is baked into the `Dockerfile`) — if you hit this anyway, your image is
  stale; rebuild.
- **`deploy/setup.sh`'s final "outgoing" check fails or times out**: often
  just NAT hairpin/loopback — many home routers can't route a request back
  in through their own public IP. Doesn't mean external clients can't reach
  you; confirm once from a genuinely separate network (e.g. your phone on
  cellular) before worrying.
