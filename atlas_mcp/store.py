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
import threading
import time
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import yaml

# --- vocabulary (kept in sync with PROJECT_ATLAS.md) -------------------------

STATUS = ["concept", "active", "advanced", "completed", "production", "archived"]
# ordered least -> most restricted; anything unrecognised is treated as "secret"
SENSITIVITY = ["public", "internal", "confidential", "secret"]
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

# Every save() re-scans, re-dumps, rewrites and fsyncs the whole body (and
# with git on, stores a fresh blob of it), and every read re-parses the whole
# store. Notes are sentences, not archives: bound the per-project size, the
# project count and the search cost at the sink so no ingress can grow them
# without limit. Reference large material elsewhere instead of pasting it in.
MAX_BODY_CHARS = 256 * 1024
MAX_PROJECTS = 500
MAX_SEARCH_TERMS = 16
MAX_QUERY_CHARS = 512
# git history is a per-save record, but each commit stores a full blob, so
# commits are throttled per file (the file itself is written on every save).
GIT_MIN_COMMIT_INTERVAL = 60.0

SLUG_RE = re.compile(r"[^a-z0-9]+")


def slugify(text: str) -> str:
    return SLUG_RE.sub("-", text.strip().lower()).strip("-")[:64]


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class AtlasError(ValueError):
    """Raised with an actionable message the model can act on."""


class AtlasDenied(AtlasError):
    """Raised when a record exists but is above the server's clearance."""


# Ingress tripwire. Patterns that must never enter a store that gets shipped to
# a third-party model. Deliberately noisy: a false positive costs one rephrase,
# a false negative costs a disclosure.
# Regex hygiene (CWE-1333): this runs on every write, so no pattern may
# backtrack quadratically. Unbounded runs are either possessive and only
# started at a run boundary (lookbehind), or bounded. Each has a timing test.
PII_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("IBAN", re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}\b")),
    ("credit card", re.compile(r"\b(?:\d[ -]?){13,19}\b")),
    ("German tax/social id", re.compile(r"\b\d{2} ?\d{6} ?\d{3}\b")),
    ("email address", re.compile(
        r"(?<![\w.+-])[\w.+-]++@(?:[\w-]++\.)++[A-Za-z]{2,}")),
    ("phone number", re.compile(r"(?:\+49|0049|\b0)[\d /-]{8,30}\d\b")),
    ("private key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("API token", re.compile(r"\b(?:sk-|ghp_|gho_|xox[baprs]-|AKIA|AIza)[A-Za-z0-9_\-]{10,}")),
    ("JWT", re.compile(
        r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{10,}+\.[A-Za-z0-9_-]{10,}+\.[A-Za-z0-9_-]{10,}+")),
    ("date of birth", re.compile(r"\b(?:geb\.?|geboren am|DOB)[: ]+\d", re.I)),
]


def _meta_strings(meta: dict[str, Any]) -> str:
    """All caller-writable frontmatter text, for the tripwire. Frontmatter is
    serialized into the stored file and replicated to model providers exactly
    like the body, so it must be scanned too. Server-generated timestamps are
    excluded (digit runs in them are not identifiers)."""
    out: list[str] = []

    def walk(v: Any) -> None:
        if isinstance(v, str):
            out.append(v)
        elif isinstance(v, dict):
            for k, x in v.items():
                out.append(str(k))
                walk(x)
        elif isinstance(v, (list, tuple, set)):
            for x in v:
                walk(x)

    walk({k: v for k, v in meta.items() if k not in ("created", "updated")})
    return "\n".join(out)


def scan_pii(text: str) -> list[str]:
    """Return the names of tripwire patterns found in text."""
    return sorted({name for name, rx in PII_PATTERNS if rx.search(text)})


def sensitivity_rank(value: Any) -> int:
    """Fail closed: unknown labels rank as the most restricted level.
    Only a *missing* label defaults to internal; an explicit blank or
    falsy one ("", 0, []) is unknown, not "internal"."""
    try:
        return SENSITIVITY.index("internal" if value is None else value)
    except ValueError:
        return len(SENSITIVITY) - 1


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
    def __init__(
        self,
        root: str | Path,
        git: bool = False,
        max_sensitivity: str = "internal",
        pii_guard: bool = True,
    ) -> None:
        self.root = Path(root).expanduser().resolve()
        self.projects_dir = self.root / "projects"
        self.projects_dir.mkdir(parents=True, exist_ok=True)
        self.git = git
        # Records above this level are invisible to every read path on this
        # instance. Set per process, so an internet-facing server and a local
        # CLI can point at the same directory with different clearances.
        self.max_rank = sensitivity_rank(max_sensitivity)
        self.pii_guard = pii_guard
        # Serializes load-modify-save sequences (tools run in worker threads
        # so a slow store never blocks the event loop; see server.py).
        self.write_lock = threading.RLock()
        self._last_commit: dict[str, float] = {}

    def _visible(self, project: "Project") -> bool:
        return sensitivity_rank(project.meta.get("sensitivity")) <= self.max_rank

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
        try:
            meta, body = _split_frontmatter(raw)
        except AtlasError:
            # Fail closed: a record whose classification cannot be read
            # reliably is neither shown nor writable/deletable through here.
            raise AtlasDenied(
                f"Project '{path.stem}' has unreadable frontmatter and is not served "
                f"by this instance. Repair or remove it locally."
            ) from None
        project = Project(id=path.stem, meta=meta, body=body)
        if not self._visible(project):
            raise AtlasDenied(
                f"Project '{project.id}' is classified "
                f"'{meta.get('sensitivity')}' and is not served by this instance. "
                f"Read it locally instead."
            )
        return project

    def save(self, project: Project, message: str = "") -> Path:
        if len(project.body) > MAX_BODY_CHARS:
            raise AtlasError(
                f"Refused: the body of '{project.id}' would exceed {MAX_BODY_CHARS} "
                "characters. Trim the Log or split the project, and reference large "
                "material instead of pasting it in."
            )
        if self.pii_guard:
            found = sorted(set(scan_pii(project.body)) | set(scan_pii(_meta_strings(project.meta))))
            if found:
                raise AtlasError(
                    "Refused: the text contains " + ", ".join(found) + ". "
                    "The Atlas is replicated to third-party model providers on "
                    "every read, so identifiers must not be stored here. "
                    "Reference the record instead (e.g. 'see Nextcloud/contracts/2026-03')."
                )
        if not self._visible(project):
            raise AtlasDenied(
                f"Refused: sensitivity '{project.meta.get('sensitivity')}' exceeds "
                f"this instance's clearance ('{SENSITIVITY[self.max_rank]}')."
            )
        project.meta.setdefault("sensitivity", "internal")
        project.meta["updated"] = utcnow()
        path = self._path(project.id)
        with self.write_lock:
            if not path.exists() and sum(1 for _ in self.projects_dir.glob("*.md")) >= MAX_PROJECTS:
                raise AtlasError(
                    f"Refused: this Atlas already holds {MAX_PROJECTS} projects. "
                    "Delete or merge old ones before creating new ones."
                )
            _atomic_write(path, project.to_markdown())
            if self.git:
                self._commit(path, message or f"atlas: update {project.id}")
        return path

    def delete(self, project_id: str) -> str:
        # load() enforces existence and the clearance gate, so a project you
        # cannot see cannot be deleted through this path either.
        # (load() also fails closed on unparseable frontmatter, so a record
        # whose classification cannot be read is not deletable here either.)
        with self.write_lock:
            project = self.load(project_id)
            path = self._path(project_id)
            path.unlink(missing_ok=True)
            if self.git:
                # `git add` on a removed path stages the deletion; git keeps history.
                self._commit(path, f"atlas: delete {project.id}", force=True)
        return project.id

    def all(self) -> list[Project]:
        out = []
        for p in sorted(self.projects_dir.glob("*.md")):
            try:
                meta, body = _split_frontmatter(p.read_text(encoding="utf-8"))
                project = Project(id=p.stem, meta=meta, body=body)
                if self._visible(project):
                    out.append(project)
            except Exception:  # a broken file must not kill the whole listing,
                # but it must not leak its contents either
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
        if len(query) > MAX_QUERY_CHARS:
            raise AtlasError(f"Query too long. Keep it under {MAX_QUERY_CHARS} characters.")
        terms = [t for t in re.split(r"\s+", query.lower()) if t]
        if not terms:
            raise AtlasError("Empty query. Pass at least one search term.")
        if len(terms) > MAX_SEARCH_TERMS:
            raise AtlasError(
                f"Too many search terms ({len(terms)}). Use at most {MAX_SEARCH_TERMS}."
            )
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

    def _commit(self, path: Path, message: str, force: bool = False) -> None:
        now = time.monotonic()
        if not force and now - self._last_commit.get(path.name, -1e9) < GIT_MIN_COMMIT_INTERVAL:
            return  # file is already on disk; the next commit picks it up
        self._last_commit[path.name] = now
        try:
            subprocess.run(["git", "add", str(path)], cwd=self.root, check=True,
                           capture_output=True, timeout=15)
            subprocess.run(["git", "commit", "-m", message], cwd=self.root,
                           check=False, capture_output=True, timeout=15)
        except Exception:
            pass  # notes must never be lost because git misbehaves


# --- helpers ---------------------------------------------------------------


def _split_frontmatter(raw: str) -> tuple[dict[str, Any], str]:
    """Split '---' fenced YAML frontmatter from the body.

    Fences must be whole lines. A '---' *inside* a value must never end the
    frontmatter early: that would drop later keys (notably `sensitivity`) and
    make a classified record look unclassified. Anything unparseable raises.
    """
    if not raw.startswith("---"):
        return {}, raw.strip()
    lines = raw.split("\n")
    if lines[0].rstrip() != "---":
        raise AtlasError("Malformed frontmatter opening fence.")
    for i in range(1, len(lines)):
        if lines[i].rstrip() == "---":
            try:
                meta = yaml.safe_load("\n".join(lines[1:i])) or {}
            except yaml.YAMLError:
                raise AtlasError("Frontmatter is not valid YAML.") from None
            if not isinstance(meta, dict):
                raise AtlasError("Frontmatter must be a YAML mapping.")
            return meta, "\n".join(lines[i + 1:]).strip()
    raise AtlasError("Unterminated frontmatter.")


def _atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lockdir = path.parent / ".locks"
    lockdir.mkdir(exist_ok=True)
    lock = lockdir / (path.name + ".lock")
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
