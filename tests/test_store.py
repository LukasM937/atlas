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
