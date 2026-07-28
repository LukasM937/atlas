# SECURITY.md

Target posture: handle the store as you would clinical records — least
privilege, classification before storage, auditability, and no control claimed
that is not actually in place.

## The control that matters most, stated first

**Everything readable by the connector is transmitted to a third-party model
provider on every read.** Not stored insecurely — *transmitted, by design*.
TLS, disk encryption, firewalls and OAuth all protect the path between your
disk and Anthropic's (or OpenAI's) infrastructure. None of them protect
anything after that.

In a clinical setting this is the point where you would stop and ask whether
the record should be in the system at all. Same answer here: for this store,
**data minimisation is the primary control and cryptography is secondary.**
A note that must not reach a US cloud provider does not belong in the Atlas at
any classification level — it belongs in your Nextcloud, and the Atlas holds a
pointer to it.

## Threat model

| # | Threat | Realistic? | Primary control |
|---|---|---|---|
| T1 | Note content reaching a model provider | **certain, by design** | classification + data minimisation (§ policy) |
| T2 | Internet scan finds the endpoint | certain | IP allowlist, secret path → OAuth, ufw |
| T3 | Token disclosed via logs, screenshot, browser history | likely | log redaction, Phase 4 auth, rotation runbook |
| T4 | Prompt injection in note content steering another assistant | plausible | notes are data, tools are narrow, no shell/network tools in the server |
| T5 | Compromise of the web host | plausible | localhost bind, unprivileged service user, systemd sandbox, code read-only to service |
| T6 | Backup or disk leaves the building | plausible | encrypted backups; full-disk encryption if the host allows it |
| T7 | Assistant destroys notes | likely eventually | append-only default write, git history in the store repo |
| T8 | Third-party personal data stored without basis | plausible | PII tripwire on write + policy |

Out of scope, stated honestly: a compromise of the model provider, a
compromise of your Claude account, and anything you paste into a chat directly.

## Classification

Set per project in frontmatter as `sensitivity:`.

| Level | Meaning | Served to models? |
|---|---|---|
| `public` | could sit on a public GitHub README | yes |
| `internal` | ordinary project notes, no identifiers (**default**) | yes |
| `confidential` | anything identifying, contractual, health-related, or about another person | **no** — invisible to the network instance |
| `secret` | credentials, keys, legal exposure | **no**, and should not be here at all |

Enforcement is not cosmetic. The public-facing process runs with
`ATLAS_MAX_SENSITIVITY=internal`; records above that rank are excluded inside
`AtlasStore` itself, so they never reach a tool, a search index, a resource
read or an error message. Unknown labels rank as most restricted (fail closed).
A local CLI with `ATLAS_MAX_SENSITIVITY=secret` reads the same directory.

### Policy — what must never be written

- Names, addresses, phone numbers, e-mail addresses, dates of birth — yours or
  anyone else's.
- Anything about Johanna, the children, colleagues, correspondents, or
  interview subjects. Third-party data has no consent basis here.
- Health data (`health-data-analysis` keeps its methodology, not its numbers).
- Account numbers, IBANs, credentials, keys, tokens.
- Contract or legal detail beyond "there is a contract, filed at X".
- Note on `deutschland-thesis`: political opinion is special-category data
  under GDPR Art. 9. It is your own and published anyway, so `internal` is
  defensible — but the FOI correspondence, constituency contacts and any
  named individuals are `confidential` and stay out.

A write containing an identifier is **rejected at the store level** with an
explanation. The tripwire covers IBANs, card-like numbers, e-mail addresses,
German phone numbers, tax/social-insurance patterns, private keys, API tokens,
JWTs and date-of-birth markers. It is deliberately noisy — a false positive
costs one rephrase; a false negative is a disclosure that cannot be recalled.

## Controls in place (code)

- Clearance gate in `AtlasStore`, fail-closed, covering read, list, search,
  resource read and write.
- PII tripwire on every write.
- Metadata-only audit log (`ATLAS_AUDIT_LOG`): timestamp, tool, project id,
  outcome. No content.
- Append-only default write; the destructive tool is separate and annotated.
- `extra="forbid"` on every tool input; ids slugified before touching the path.
- Store writes are atomic (`os.replace`) under an flock, so a crash mid-write
  cannot truncate a note.

## Controls applied on the host — see TODO.md phases 2–4

Two deployment paths exist; **the actual deployed instance uses the first.**

- **Docker Compose** (`docker-compose.yml`, `deploy/setup.sh`): containment is
  Docker's own container isolation, not a systemd sandbox — there is no
  dedicated system user or `ProtectSystem=strict` here, do not assume there
  is. `127.0.0.1:8787` bind and secrets via `.env` (0600, gitignored) still
  hold. This is what's live on the current host, which also runs several
  other services (Nextcloud AIO, Signal API, Open WebUI, Ollama...) — its
  `ufw` ruleset is managed for all of them, not just this app.
- **systemd** (`deploy/systemd/atlas.service`, not currently deployed
  anywhere): dedicated system user, systemd sandbox (`ProtectSystem=strict`,
  `PrivateTmp`, `NoNewPrivileges`, restricted syscalls), code read-only to the
  service user, secrets in a root-owned `EnvironmentFile`. Use this path on a
  single-purpose host instead of Docker.

Network (either path): `Require ip 160.79.104.0/21` on `/mcp/` (Anthropic's
published outbound range — verify before applying, it can change); `/api` and
`/openapi.json` are public by design (§ REST decision below); Apache
terminating TLS 1.2/1.3 with HSTS; `/healthz` restricted to localhost; split
access logs so the token-bearing path is never written to disk. `fail2ban` on
401/403 bursts is written (`deploy/fail2ban/`) but **not yet installed** on
the live host — not currently a real control there, only a planned one.

Data: store mode 0700; encrypted off-box backups with a tested restore; git
history in the store repo as the tamper-evident record.

Auth: Phase 4 implemented, rolling out. GitHub-backed OAuth (identity check
only — one allow-listed username, no authorization scope beyond that) is
available on a fixed `/mcp` path when `ATLAS_PUBLIC_URL`/`ATLAS_GITHUB_*` are
set; see `docs/ADR-001-auth.md`. The original secret-path scheme
(`/mcp/<token>/`) remains the default until OAuth is confirmed working from
a real client, since it turned out to be required for basic connectivity,
not just an optional hardening step — both Claude and ChatGPT's connector
setup attempt OAuth discovery and fail outright without it. Once confirmed,
the Anthropic IP allowlist on `/mcp/` comes off (it would otherwise block
the OAuth login step itself, which is a browser redirect from the user's own
IP, not Anthropic's range) and the path-secret scheme is retired.

## What is deliberately *not* claimed

- No at-rest encryption unless Phase 2.2 concludes it is actually feasible on
  this host. Encryption at rest protects a powered-off disk, not a compromised
  running server, and writing it into a policy without implementing it is
  worse than not having it.
- No protection against a compromised Claude or ChatGPT account.
- No multi-user model, no per-record access control beyond the four levels.

## If you think the store leaked

1. Disconnect the connector in Claude and revoke it at the provider.
2. Rotate `ATLAS_TOKEN` (or the OAuth client), reload Apache, re-add.
3. `git log` in the store repo — every write is a commit, so the diff is the
   exposure.
4. Read the audit log for the window.
5. Decide, per record, whether the classification was wrong; fix the
   classification before restoring service.
