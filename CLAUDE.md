# CLAUDE.md

Project Atlas: a personal note store exposed to LLM assistants over MCP and
REST. `ATLAS_SPEC.md` explains the design, `SECURITY.md` the threat model,
`TODO.md` the current work.

## Commands

```bash
python tests/test_store.py                    # unit + security tests
python -m atlas_mcp.app                       # dev server on :8787
ATLAS_BASE=http://127.0.0.1:8787 python tests/test_e2e.py   # protocol round trip
python -m atlas_mcp.seed import seed/PROJECT_ATLAS.seed.md  # bootstrap (idempotent)
python -m atlas_mcp.seed render PROJECT_ATLAS.md            # derived view
python tests/test_tenants.py                  # multi-tenant registry/isolation tests
python tests/test_rest_auth.py                # REST auth (OAuth mode): OAuth token resolves+isolates, static token rejected
python tests/test_rest_auth_fallback.py       # REST auth (no OAuth): static token still the sole credential
python tests/test_invite_route.py             # invite flow redirects through the one registered GitHub callback; consent page; leftover-tenant refusal
python tests/test_oauth.py                    # OAuth provider: consent, GitHub-id-bound tenancy, token lifecycle/revocation, ingress caps
python -m atlas_mcp.invite                    # mint a single-use invite link (OAuth mode)
```

Environment: `ATLAS_ROOT` (store dir), `ATLAS_TOKEN`, `ATLAS_GIT=1`,
`ATLAS_MAX_SENSITIVITY` (clearance of this process), `ATLAS_AUDIT_LOG`.

## Invariants — do not weaken these without an explicit instruction

1. **Fail closed.** Unknown sensitivity labels rank as the most restricted
   level. Any new read path must go through `store.load` / `store.all` /
   `store.filter`, never `Path.read_text` on `projects/`.
2. **The PII tripwire is on the write path, in the store, not in the tools.**
   Do not add a bypass flag, do not narrow the patterns to make a test pass.
   If a pattern is genuinely wrong, fix the pattern and add a test for both
   the true positive and the false positive.
3. **Notes and code are separate repositories.** Nothing under `data/` is ever
   committed to the code repo. No test fixture may contain real note content.
4. **No secrets in the repo.** Tokens come from the environment. The literal
   `testtoken123` appears only as a default in tests against localhost.
5. **Audit records metadata only** — tool name, project id, timestamp,
   outcome. Never note content, never full request bodies.
6. **Errors must not leak.** No filesystem paths, no stack traces, no
   "project exists but you may not read it" distinctions in responses to
   unauthenticated callers.
7. **Derived files are derived.** `PROJECT_ATLAS.md` is generated; never hand-
   edit it, never make it authoritative.

## Style

- Python 3.11+, standard library first. Current runtime deps: `mcp`, `pyyaml`,
  `starlette`, `uvicorn`. Adding a dependency needs a line in the commit
  message explaining why the stdlib was not enough.
- Pydantic models for every tool input, with `extra="forbid"` and real
  constraints. Field descriptions are read by models — write them for a reader
  who has never seen the codebase.
- Tool errors are instructions, not apologies: say what was wrong and what to
  call instead.
- Type hints throughout. No `Any` in signatures without a comment.
- Tests are plain asserts in `tests/*.py`, runnable without pytest.

## Conventions

- Tool names are prefixed `atlas_`; snake_case; verb-first.
- New tools need: an annotation block (`readOnlyHint`, `destructiveHint`,
  `idempotentHint`), an entry in `ATLAS_SPEC.md`'s tool table, and a test.
- Any write tool must be either append-only or explicitly marked destructive.
  When in doubt, make it append-only.
- Commit messages: `area: imperative summary`. One concern per commit.

## When working on the deployed server

- Never restart the service without checking `journalctl -u atlas -n 50` first.
- Never widen the Apache IP allowlist to debug. Log the real source addresses,
  report them, and ask.
- Never `chmod` the store or its parent to anything looser than `0700`.
- Config changes to Apache: `apache2ctl configtest` before `systemctl reload`.
- If something must be disabled to make progress, write it in `TODO.md` under
  a `RISK ACCEPTED` heading with the date, rather than leaving it silently off.
