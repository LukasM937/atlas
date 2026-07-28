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
    assert "OHLCV" in q.section("Summary")
    q.set_section("Goal", "Beat buy-and-hold on risk-adjusted returns out of sample.")
    q.body = q.body.rstrip() + "\n" + make_entry("decision", "Use walk-forward CV because k-fold leaks time.", "claude")
    s.save(q)
    r = s.load("demo-widget")
    assert "buy-and-hold" in r.section("Goal")
    assert "walk-forward" in r.section("Log")
    assert "OHLCV" in r.section("Summary"), "set_section must not clobber siblings"
    hits = s.search("walk-forward")
    assert hits and hits[0][0].id == "demo-widget", hits
    assert s.filter(status="active")[0].id == "demo-widget"
    assert slugify("Pizza Ofen Mosaik!") == "pizza-ofen-mosaik"
    try:
        s.load("nope"); raise SystemExit("should have raised")
    except Exception as e:
        assert "No project" in str(e)
    print("store tests: OK")

main()
