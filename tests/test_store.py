import os, sys, tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from atlas_mcp.store import AtlasStore, Project, new_project_body, make_entry, slugify

def main():
    d = tempfile.mkdtemp()
    s = AtlasStore(d)
    p = Project(id="demo-widget", meta={"name":"demo-widget","status":"active","priority":"S","completion":40,"tags":["demo"]}, body=new_project_body("Fictional test fixture, not a real project."))
    s.save(p)
    q = s.load("demo-widget")
    assert q.meta["status"] == "active", q.meta
    assert "fixture" in q.section("Summary")
    q.set_section("Goal", "Reach 100% test coverage on the store module.")
    q.body = q.body.rstrip() + "\n" + make_entry("decision", "Use a temp dir per test run to avoid cross-test pollution.", "claude")
    s.save(q)
    r = s.load("demo-widget")
    assert "coverage" in r.section("Goal")
    assert "temp dir" in r.section("Log")
    assert "fixture" in r.section("Summary"), "set_section must not clobber siblings"
    hits = s.search("coverage")
    assert hits and hits[0][0].id == "demo-widget", hits
    assert s.filter(status="active")[0].id == "demo-widget"
    assert slugify("Pizza Ofen Mosaik!") == "pizza-ofen-mosaik"
    try:
        s.load("nope"); raise SystemExit("should have raised")
    except Exception as e:
        assert "No project" in str(e)
    print("store tests: OK")

main()

def test_no_traversal():
    from atlas_mcp.store import AtlasError as _AtlasError
    d = tempfile.mkdtemp()
    s = AtlasStore(d)
    projects_dir = s.projects_dir.resolve()
    for bad_id in ("../../etc/passwd", "..%2f..%2fx", "a/b"):
        resolved = s._path(bad_id).resolve()
        assert resolved.parent == projects_dir, (bad_id, resolved)
    try:
        s._path(""); raise SystemExit("empty id must raise, not resolve to projects/.md")
    except _AtlasError:
        pass
    print("path traversal tests: OK")

test_no_traversal()

def security():
    import tempfile
    from atlas_mcp.store import AtlasStore, Project, AtlasDenied, scan_pii, new_project_body
    d = tempfile.mkdtemp()
    full = AtlasStore(d, max_sensitivity="secret")
    pub = AtlasStore(d, max_sensitivity="internal")

    # 1. PII tripwire blocks writes
    bad = Project(id="leak", meta={"name":"leak"}, body=new_project_body("Contact alex at foo.bar@example.com"))
    try:
        full.save(bad); raise SystemExit("PII guard failed to fire")
    except Exception as e:
        assert "email address" in str(e), e
    assert "IBAN" in scan_pii("IBAN DE89 3704 0044 0532 0130 00")
    assert "API token" in scan_pii("token sk-abcdefghijklmnop")
    assert scan_pii("A perfectly ordinary sentence about foiling trimarans.") == []
    assert scan_pii("Sharpe 1.1 out of sample on the 2023 slice; 300x300 mm at 300 km/h") == []

    # 2. classified records are invisible to the low-clearance instance
    sec = Project(id="vault", meta={"name":"vault","sensitivity":"confidential"}, body=new_project_body("x"))
    full.save(sec)
    assert full.load("vault").id == "vault"
    try:
        pub.load("vault"); raise SystemExit("clearance gate failed")
    except AtlasDenied:
        pass
    assert [p.id for p in pub.all()] == []
    assert [p.id for p in full.all()] == ["vault"]
    assert pub.search("vault") == []

    # 3. unknown classification fails closed
    weird = Project(id="odd", meta={"name":"odd","sensitivity":"banana"}, body=new_project_body("y"))
    full.save(weird)
    try:
        pub.load("odd"); raise SystemExit("unknown label must fail closed")
    except AtlasDenied:
        pass

    # 4. default classification is applied on write
    ok = Project(id="fine", meta={"name":"fine"}, body=new_project_body("Nothing identifying here."))
    pub.save(ok)
    assert pub.load("fine").meta["sensitivity"] == "internal"
    print("security tests: OK")

security()


def hardening():
    import time
    from atlas_mcp import store as st
    from atlas_mcp.store import AtlasError, AtlasDenied, AtlasStore, Project, scan_pii, new_project_body, _split_frontmatter

    # 1. '---' inside a meta value must not truncate frontmatter and drop `sensitivity`
    d = tempfile.mkdtemp()
    full = AtlasStore(d, max_sensitivity="secret")
    pub = AtlasStore(d, max_sensitivity="internal")
    for name in ("a\n---\nb", "x --- y", "---", "line\n---"):
        full.save(Project(id="vault", meta={"name": name, "sensitivity": "secret"}, body=new_project_body("x")))
        got = full.load("vault")
        assert got.meta["sensitivity"] == "secret" and got.meta["name"] == name, (name, got.meta)
        for op in (lambda: pub.load("vault"), lambda: pub.delete("vault")):
            try:
                op(); raise SystemExit(f"low-clearance access to secret record via name={name!r}")
            except AtlasDenied:
                pass
        assert [p.id for p in pub.all()] == []
        assert pub.search("vault") == []
    assert full.exists("vault"), "low-clearance delete must not have removed the record"
    # unparseable frontmatter fails closed instead of reading as unclassified
    (full.projects_dir / "bad.md").write_text("---\nname: [unclosed\n---\nbody\n")
    (full.projects_dir / "open.md").write_text("---\nname: x\nsensitivity: secret\nno closing fence\n")
    for pid in ("bad", "open"):
        for store in (full, pub):
            try:
                store.load(pid); raise SystemExit("malformed frontmatter must not load")
            except AtlasDenied:
                pass
    try:
        _split_frontmatter("---\nname: x\n"); raise SystemExit("unterminated must raise")
    except AtlasError:
        pass
    # explicit blank/falsy classification is unknown -> most restricted
    assert st.sensitivity_rank("") == 3 and st.sensitivity_rank(0) == 3 and st.sensitivity_rank(None) == 1

    # 2. tripwire covers frontmatter values, not just the body
    for meta in ({"name": "mail a@example.com"}, {"name": "ok", "tags": ["call +49 170 1234567"]},
                 {"name": "ok", "links": ["sk-abcdefghijklmnop"]}):
        try:
            full.save(Project(id="m", meta=meta, body=new_project_body("fine"))); raise SystemExit(f"meta not scanned: {meta}")
        except AtlasError as e:
            assert "Refused" in str(e)
    full.save(Project(id="m", meta={"name": "ok"}, body=new_project_body("fine")))  # timestamps don't trip it

    # 3. tripwire regexes stay linear on adversarial input (each used to be quadratic)
    n = 200_000
    # shapes with many \b start points per unbounded run (the old patterns took
    # ~1 s at 20 KB and grew quadratically)
    poison = {
        "email": "a." * (n // 2), "email2": "a." * (n // 2) + "x@" + "b." * (n // 2),
        "email3": "a@" * (n // 2),
        "phone": "0049" * (n // 4) + "x", "phone2": "0 " * (n // 2) + "x",
        "jwt": "eyJ-" * (n // 4), "jwt2": "eyJ" + "a" * n, "jwt3": ("eyJaaaaaaaaaaaa." * (n // 16)),
    }
    for label, text in poison.items():
        t = time.perf_counter(); scan_pii(text); dt = time.perf_counter() - t
        assert dt < 1.0, f"{label}: {dt:.2f}s for {n} chars -- regex is superlinear again"
    # ...without losing detection (true positives, incl. multi-label domains)
    assert "email address" in scan_pii("x@mail.example.co.uk") and "email address" in scan_pii("x " + "a" * 100 + "@b.com")
    assert "phone number" in scan_pii("tel 0170 1234567") and "phone number" in scan_pii("+49 30 123456 78")
    # assembled at runtime so no JWT-shaped literal trips the repo's secret scanner
    fake_jwt = ".".join(["eyJ" + "a" * 17, "eyJ" + "b" * 17, "c" * 16])
    assert "JWT" in scan_pii(fake_jwt)
    assert scan_pii("v1.2.3 released; see foo.bar for details") == []

    # 4. size caps at the sink
    big = Project(id="big", meta={"name": "big"}, body="x " * (st.MAX_BODY_CHARS // 2 + 10))
    try:
        full.save(big); raise SystemExit("oversized body accepted")
    except AtlasError as e:
        assert "exceed" in str(e)
    for q in ("a " * (st.MAX_SEARCH_TERMS + 1), "a" * (st.MAX_QUERY_CHARS + 1)):
        try:
            full.search(q); raise SystemExit("unbounded search accepted")
        except AtlasError:
            pass
    old = st.MAX_PROJECTS; st.MAX_PROJECTS = len(list(full.projects_dir.glob("*.md")))
    try:
        full.save(Project(id="one-too-many", meta={"name": "n"}, body=new_project_body("fine"))); raise SystemExit("project cap")
    except AtlasError:
        pass
    finally:
        st.MAX_PROJECTS = old

    # 5. git commits are throttled per file (history is a record, not a blob sink)
    g = AtlasStore(tempfile.mkdtemp(), git=True)
    calls = []
    g._commit_orig = g._commit
    import subprocess
    real_run = subprocess.run
    subprocess.run = lambda *a, **k: calls.append(a[0][:2]) or real_run(["true"])
    try:
        for i in range(5):
            g.save(Project(id="p", meta={"name": f"n{i}"}, body=new_project_body("fine")))
    finally:
        subprocess.run = real_run
    assert len([c for c in calls if c[1] == "commit"]) == 1, calls
    print("hardening tests: OK")


hardening()
