"""Import a seed file into the store, and render the store back to one file.

    python -m atlas_mcp.seed import seed/PROJECT_ATLAS.seed.md [--force]
    python -m atlas_mcp.seed render PROJECT_ATLAS.md

Import is non-destructive by default: existing projects are skipped, so a
re-import can never overwrite notes you have since corrected. Render produces a
derived document — never edit it, it is regenerated from the store.
"""

from __future__ import annotations

import re
import sys
from datetime import date
from pathlib import Path

from .store import PRIORITY, AtlasStore, Project, _split_frontmatter

MARKER = re.compile(r"^<!-- project:\s*([a-z0-9\-]+)\s*-->\s*$", re.MULTILINE)


def import_seed(store: AtlasStore, seed_path: str | Path, force: bool = False) -> tuple[int, int]:
    text = Path(seed_path).read_text(encoding="utf-8")
    parts = MARKER.split(text)
    if len(parts) < 3:
        raise SystemExit("No '<!-- project: id -->' markers found in the seed file.")
    added = skipped = 0
    for pid, chunk in zip(parts[1::2], parts[2::2]):
        if store.exists(pid) and not force:
            skipped += 1
            continue
        meta, body = _split_frontmatter(chunk.strip())
        store.save(Project(id=pid, meta=meta, body=body), f"atlas: seed {pid}")
        added += 1
    return added, skipped


def render(store: AtlasStore) -> str:
    ps = store.all()
    rank = {s: i for i, s in enumerate(PRIORITY)}
    ps.sort(key=lambda p: (rank.get(p.meta.get("priority", "D"), 9), p.id))
    cats: dict[str, list[Project]] = {}
    for p in ps:
        cats.setdefault(p.meta.get("category", "unsorted"), []).append(p)

    out = [
        "# Project Atlas",
        "",
        f"> GENERATED FILE — rendered from the Atlas store on {date.today().isoformat()}.",
        "> Do not edit; edit the store (or ask any assistant to) and re-render.",
        "",
        f"{len(ps)} projects across {len(cats)} categories.",
        "",
        "## Dashboard",
        "",
        "| Project | Category | Status | Prio | % | Confidence |",
        "|---|---|---|---|---|---|",
    ]
    for p in ps:
        m = p.meta
        out.append(
            f"| `{p.id}` {m.get('name','')} | {m.get('category','')} | {m.get('status','')} "
            f"| {m.get('priority','')} | {m.get('completion',0)} | {m.get('confidence','—')} |"
        )
    out += ["", "## Projects", ""]
    for cat in sorted(cats):
        out.append(f"### {cat}")
        out.append("")
        for p in cats[cat]:
            out.append(f"#### {p.meta.get('name', p.id)} (`{p.id}`)")
            out.append("")
            out.append(p.section("Summary") or "_no summary_")
            log = [l for l in p.section("Log").splitlines() if l.strip().startswith("- ")]
            if log:
                out.append("")
                out.append("Recent log:")
                out += log[-3:]
            out.append("")
    return "\n".join(out)


def main(argv: list[str]) -> int:
    import os

    store = AtlasStore(os.environ.get("ATLAS_ROOT", "./data"),
                       git=os.environ.get("ATLAS_GIT", "0") == "1")
    if len(argv) < 2:
        print(__doc__)
        return 1
    if argv[1] == "import":
        added, skipped = import_seed(store, argv[2], "--force" in argv)
        print(f"imported {added}, skipped {skipped} (already present)")
    elif argv[1] == "render":
        target = Path(argv[2] if len(argv) > 2 else "PROJECT_ATLAS.md")
        target.write_text(render(store), encoding="utf-8")
        print(f"rendered {len(store.all())} projects -> {target}")
    else:
        print(__doc__)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
