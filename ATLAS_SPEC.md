# Project Atlas — shared note layer for all LLM instances

Version 2.0 · Owner: Lukas Mührke

## What changed vs. the v1.0 draft

The v1.0 draft was a *document* you paste into each assistant. That has three
failure modes: every assistant holds a different copy, nobody can write back,
and the copy rots the moment you edit one of them.

v2.0 keeps the same vocabulary (status, priority, sections, log) but inverts
the architecture: **the notes live once, on your server, and every assistant
reads and writes the same files over a protocol.** The markdown document
becomes a rendering of the store, not the store itself.

```
                    ~/atlas/projects/*.md          <- source of truth (git)
                              |
                        atlas-mcp (one process)
                              |
          +-------------------+--------------------+
          |                   |                    |
     /mcp/<secret>        /api + OpenAPI       filesystem
          |                   |                    |
   Claude (web, desktop,  ChatGPT Actions,    local LLMs, RAG,
   iOS/Android, Code)     n8n, curl, cron     grep, Obsidian
```

## Design rules

1. **Plain files, not a database.** One markdown file per project, YAML
   frontmatter for machine-readable metadata, markdown body for humans. Git
   gives you history, branches and blame for free. No migration ever needed.
2. **Append-only by default.** `atlas_append_entry` is the primary write; it
   cannot destroy content. Section rewrites are a separate, explicitly
   destructive tool. This is what makes multi-agent writing safe.
3. **Attribution on every entry.** Each log line carries a date, a kind and an
   author (`claude`, `chatgpt`, `local`, `lukas`). You can always see which
   model claimed what.
4. **One contract for all assistants.** `atlas://instructions` (MCP resource,
   and the server's `instructions` field) carries the behavioural rules —
   don't invent completed work, search before advising, record the *why* of a
   decision. Every client gets the same rules automatically.
5. **Protocol, not prompt.** MCP for Claude and agents, REST+OpenAPI for
   everything else. Both hit the same store object; neither is privileged.

## Vocabulary

| Field | Values |
|---|---|
| `status` | concept · active · advanced · completed · production · archived |
| `priority` | S (critical) · A · B · C · D (idea archive) |
| `completion` | 0–100 |
| entry `kind` | decision · note · log · question · result · idea |

Sections per project: Summary, Motivation, Goal, Current State, Technical
Design, Research, Business, Roadmap, plus the append-only Log.

## Tool surface (MCP)

| Tool | Write? | Purpose |
|---|---|---|
| `atlas_list_projects` | no | filtered portfolio list |
| `atlas_get_project` | no | one project, selected sections + recent log |
| `atlas_search` | no | ranked full-text across all files |
| `atlas_overview` | no | counts per status/priority, stalest projects |
| `atlas_upsert_project` | destructive | create, or rewrite metadata / one section |
| `atlas_append_entry` | safe | dated, attributed log entry |

Resources: `atlas://instructions`, `atlas://index`, `atlas://project/{id}`.
Prompt: `atlas_review` (quarterly review over the portfolio).

## Deliberate non-goals for v2.0

- No vector search. Full-text over a few hundred files is fast and exact; add
  embeddings only when the corpus outgrows grep.
- No web UI. The files are the UI (Obsidian, `nvim`, GitHub).
- No multi-user model. Single owner, single token.

## Roadmap

- v2.1 — OAuth 2.1 + dynamic client registration, replacing the secret path.
- v2.2 — `atlas_link_projects` (typed edges) and a graph resource; the v1.0
  "detect related projects" goal needs explicit edges to be answerable.
- v2.3 — nightly render of `PROJECT_ATLAS.md` from the store, committed to git,
  so a single pasteable document still exists for contexts without connectors.
- v2.4 — embeddings + `atlas_similar` once >200 projects.

## Appendix: on the proposed repository layout

The parallel proposal was a git repo with `projects/*.md` plus sibling
directories `papers/ patents/ datasets/ architecture/ notes/ assets/` and
hand-maintained `DASHBOARD.md`, `IDEAS.md`, `RESEARCH.md`, `STARTUPS.md`,
`CHANGELOG.md`. Assessment:

**Adopt: one file per project, in git.** Correct, and already how the store
works. A single 300-page `project.md` cannot be partially loaded, cannot be
diffed usefully, and forces every RAG query to pull the whole thing.

**Reject: hand-maintained index files.** `DASHBOARD.md`, `IDEAS.md`,
`STARTUPS.md` and `CHANGELOG.md` all restate facts that already live in the
project files (status, priority, completion, potential). Two writable copies of
the same fact diverge — usually within a week, and always silently. These are
*views*, so they are generated: `python -m atlas_mcp.seed render`. The
`Ideenfriedhof` is not a file either, it is `status: archived`. `CHANGELOG.md`
is `git log`.

**Restructure: the artefact directories.** `projects/` splits by project;
`papers/ datasets/ notes/ assets/` split by artefact type. Mixing both axes
means one project's material is scattered across six directories with nothing
enforcing the link. Two better options:

- Keep `projects/` flat and put pointers in frontmatter (`links:` to the git
  repo, the Nextcloud folder, the dataset path). The Atlas indexes work; it
  does not host it. Notes go in the project's Log, where they are dated and
  attributed.
- If a project genuinely needs local assets, promote it to a directory:
  `projects/candlebot/index.md` + `figures/`. Same file, one level down.

`papers/` is the one defensible exception, because a paper can belong to
several projects — but then it needs its own ids and a `papers:` list in
project frontmatter, otherwise it is just an unindexed folder. Deferred to
v2.2 along with typed project links.

**Net rule: exactly one writable location per fact.** Everything else is
rendered.
