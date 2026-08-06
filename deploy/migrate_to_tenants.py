#!/usr/bin/env python3
"""One-off migration: move a pre-multi-tenant store into tenants/<slug>/.

Before: $ATLAS_ROOT/projects/*.md, $ATLAS_ROOT/.git
After:  $ATLAS_ROOT/tenants/<slug>/projects/*.md, .../tenants/<slug>/.git

Moves .git alongside projects/ (not just the notes) so existing commit
history — the incident-response trail SECURITY.md relies on — survives the
move intact. Git repos are self-contained relative to their working tree,
so relocating both together is safe; the history is not tied to the old
absolute path.

Usage:
    python deploy/migrate_to_tenants.py --root ./data --username lukasm937 --dry-run
    python deploy/migrate_to_tenants.py --root ./data --username lukasm937
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from atlas_mcp.store import slugify


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", required=True, help="Current ATLAS_ROOT, e.g. ./data")
    ap.add_argument("--username", required=True, help="GitHub username the existing store belongs to")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    root = Path(args.root).expanduser().resolve()
    slug = slugify(args.username)
    src_projects = root / "projects"
    src_git = root / ".git"
    dest = root / "tenants" / slug

    if not src_projects.is_dir():
        # Two possibilities: fully done already, or projects/ moved but the
        # .git rename after it failed partway (seen in practice: the
        # container runs ATLAS_GIT commits as root with no USER directive,
        # so .git ends up root-owned on the host and a non-root os.rename
        # of it can fail with EACCES even though projects/ — owned the same
        # way — moved fine moments earlier; parent-dir permissions can
        # differ in effect from object ownership depending on the
        # filesystem). Tell them which case this is instead of a blanket
        # "already migrated?" that's actively misleading in the second case.
        if dest.is_dir() and src_git.is_dir() and not (dest / ".git").exists():
            raise SystemExit(
                f"Partial migration detected: {dest / 'projects'} exists but "
                f"{src_git} was never moved (likely a permissions error on "
                f"the first attempt). Finish it by hand, then rerun to verify:\n"
                f"    sudo mv {src_git} {dest / '.git'}\n"
                f"    sudo chown -R $(id -un):$(id -gn) {dest}"
            )
        raise SystemExit(f"No {src_projects} — nothing to migrate (already fully migrated?).")
    if dest.exists():
        raise SystemExit(f"{dest} already exists — refusing to overwrite.")

    count = len(list(src_projects.glob("*.md")))
    print(f"Source: {src_projects} ({count} project file(s))")
    print(f"Git history: {'present at ' + str(src_git) if src_git.is_dir() else 'none'}")
    print(f"Destination: {dest}")

    if args.dry_run:
        print("Dry run — nothing moved.")
        return

    dest.mkdir(parents=True)
    os.rename(src_projects, dest / "projects")
    if src_git.is_dir():
        os.rename(src_git, dest / ".git")

    moved = len(list((dest / "projects").glob("*.md")))
    print(f"Moved. {moved} project file(s) now at {dest / 'projects'}.")
    if moved != count:
        print(f"WARNING: count mismatch (expected {count}, found {moved}) — verify manually.", file=sys.stderr)


if __name__ == "__main__":
    main()
