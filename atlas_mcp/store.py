"""File-backed store for Project Atlas.

One markdown file per project: YAML frontmatter (machine-readable metadata) +
markdown body (human-readable, git-diffable). No database, no lock-in — the
directory is the source of truth and can be git-versioned, grepped, or fed to
any RAG pipeline.
"""

from __future__ import annotations

import fcntl
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import yaml

# --- vocabulary (kept in sync with PROJECT_ATLAS.md) -------------------------

STATUS = ["concept", "active", "advanced", "completed", "production", "archived"]
PRIORITY = ["S", "A", "B", "C", "D"]
ENTRY_KINDS = ["decision", "note", "log", "question", "result", "idea"]

SECTIONS = [
    "Summary",
    "Motivation",
    "Goal",
    "Current State",
    "Technical Design",
    "Research",
    "Business",
    "Roadmap",
]

SLUG_RE = re.compile(r"[^a-z0-9]+")


def slugify(text: str) -> str:
    return SLUG_RE.sub("-", text.strip().lower()).strip("-")[:64]


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class AtlasError(ValueError):
    """Raised with an actionable message the model can act on."""


@dataclass
class Project:
    id: str
    meta: dict[str, Any] = field(default_factory=dict)
    body: str = ""

    @property
    def name(self) -> str:
        return self.meta.get("name", self.id)

    def section(self, title: str) -> str:
        """Return the text of a '## Title' section, or ''."""
        pattern = re.compile(
            rf"^##\s+{re.escape(title)}\s*$(.*?)(?=^##\s+|\Z)",
            re.MULTILINE | re.DOTALL,
        )
        m = pattern.search(self.body)
        return m.group(1).strip() if m else ""

    def set_section(self, title: str, text: str) -> None:
        pattern = re.compile(
            rf"^##\s+{re.escape(title)}\s*$(.*?)(?=^##\s+|\Z)",
            re.MULTILINE | re.DOTALL,
        )
        block = f"## {title}\n\n{text.strip()}\n\n"
        if pattern.search(self.body):
            self.body = pattern.sub(block, self.body, count=1)
        else:
            # insert before the append-only Log section if present
            if "\n## Log\n" in self.body:
                head, log = self.body.split("\n## Log\n", 1)
                self.body = f"{head.rstrip()}\n\n{block}## Log\n{log}"
            else:
                self.body = f"{self.body.rstrip()}\n\n{block}"

    def to_markdown(self) -> str:
        fm = yaml.safe_dump(self.meta, sort_keys=False, allow_unicode=True).strip()
        return f"---\n{fm}\n---\n\n{self.body.strip()}\n"

    def summary_line(self) -> str:
        m = self.meta
        return (
            f"- `{self.id}` **{self.name}** — {m.get('status','?')} / "
            f"prio {m.get('priority','?')} / {m.get('completion',0)}% "
            f"[{m.get('category','uncategorised')}] — upd {m.get('updated','?')[:10]}"
        )


class AtlasStore:
    def __init__(self, root: str | Path, git: bool = False) -> None:
        self.root = Path(root).expanduser().resolve()
        self.projects_dir = self.root / "projects"
        self.projects_dir.mkdir(parents=True, exist_ok=True)
        self.git = git

    # --- io ---------------------------------------------------------------

    def _path(self, project_id: str) -> Path:
        pid = slugify(project_id)
        if not pid:
            raise AtlasError("Empty project id. Use a slug like 'my-project'.")
        return self.projects_dir / f"{pid}.md"

    def exists(self, project_id: str) -> bool:
        return self._path(project_id).exists()

    def load(self, project_id: str) -> Project:
        path = self._path(project_id)
        if not path.exists():
            known = ", ".join(p.id for p in self.all()[:20]) or "(none yet)"
            raise AtlasError(
                f"No project '{slugify(project_id)}'. Known ids: {known}. "
                f"Use atlas_upsert_project to create it."
            )
        raw = path.read_text(encoding="utf-8")
        meta, body = _split_frontmatter(raw)
        return Project(id=path.stem, meta=meta, body=body)

    def save(self, project: Project, message: str = "") -> Path:
        project.meta["updated"] = utcnow()
        path = self._path(project.id)
        _atomic_write(path, project.to_markdown())
        if self.git:
            self._commit(path, message or f"atlas: update {project.id}")
        return path

    def all(self) -> list[Project]:
        out = []
        for p in sorted(self.projects_dir.glob("*.md")):
            try:
                meta, body = _split_frontmatter(p.read_text(encoding="utf-8"))
                out.append(Project(id=p.stem, meta=meta, body=body))
            except Exception:  # a broken file must not kill the whole listing
                out.append(Project(id=p.stem, meta={"name": p.stem, "status": "broken"}))
        return out

    # --- queries ----------------------------------------------------------

    def filter(
        self,
        status: str | None = None,
        priority: str | None = None,
        category: str | None = None,
        tag: str | None = None,
    ) -> list[Project]:
        def keep(p: Project) -> bool:
            m = p.meta
            if status and m.get("status") != status:
                return False
            if priority and m.get("priority") != priority:
                return False
            if category and m.get("category") != category:
                return False
            if tag and tag not in (m.get("tags") or []):
                return False
            return True

        rank = {s: i for i, s in enumerate(PRIORITY)}
        return sorted(
            (p for p in self.all() if keep(p)),
            key=lambda p: (rank.get(p.meta.get("priority", "D"), 9), p.meta.get("updated", "")),
        )

    def search(self, query: str, limit: int = 10) -> list[tuple[Project, str, int]]:
        """Naive but dependency-free ranked full-text search over all files."""
        terms = [t for t in re.split(r"\s+", query.lower()) if t]
        if not terms:
            raise AtlasError("Empty query. Pass at least one search term.")
        hits: list[tuple[Project, str, int]] = []
        for p in self.all():
            body = p.body.replace("_tbd_", "")
            hay = f"{p.name}\n{yaml.safe_dump(p.meta, allow_unicode=True)}\n{body}".lower()
            score = sum(hay.count(t) for t in terms)
            if not score:
                continue
            if p.name.lower() in terms or slugify(p.name) == slugify(query):
                score += 50
            hits.append((p, _snippet(body, terms), score))
        hits.sort(key=lambda h: -h[2])
        return hits[:limit]

    # --- git --------------------------------------------------------------

    def _commit(self, path: Path, message: str) -> None:
        try:
            subprocess.run(["git", "add", str(path)], cwd=self.root, check=True,
                           capture_output=True, timeout=15)
            subprocess.run(["git", "commit", "-m", message], cwd=self.root,
                           check=False, capture_output=True, timeout=15)
        except Exception:
            pass  # notes must never be lost because git misbehaves


# --- helpers ---------------------------------------------------------------


def _split_frontmatter(raw: str) -> tuple[dict[str, Any], str]:
    if raw.startswith("---"):
        _, fm, body = raw.split("---", 2)
        meta = yaml.safe_load(fm) or {}
        if not isinstance(meta, dict):
            raise AtlasError("Frontmatter must be a YAML mapping.")
        return meta, body.strip()
    return {}, raw.strip()


def _atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lock = path.with_suffix(path.suffix + ".lock")
    with open(lock, "w") as lf:
        fcntl.flock(lf, fcntl.LOCK_EX)
        try:
            fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(text)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, path)
        finally:
            fcntl.flock(lf, fcntl.LOCK_UN)


def _snippet(body: str, terms: Iterable[str], width: int = 220) -> str:
    low = body.lower()
    for t in terms:
        i = low.find(t)
        if i >= 0:
            start = max(0, i - width // 3)
            return " ".join(body[start:start + width].split()) + "…"
    return " ".join(body[:width].split()) + "…"


def new_project_body(summary: str = "") -> str:
    parts = [f"## {s}\n\n{summary if s == 'Summary' else '_tbd_'}\n" for s in SECTIONS]
    return "\n".join(parts) + "\n## Log\n"


def make_entry(kind: str, text: str, author: str = "llm") -> str:
    if kind not in ENTRY_KINDS:
        raise AtlasError(f"kind must be one of {ENTRY_KINDS}, got '{kind}'.")
    stamp = date.today().isoformat()
    return f"\n- **{stamp} · {kind}** ({author}): {text.strip()}\n"
