import os, sys, tempfile, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from atlas_mcp.tenants import TenantRegistry, InviteRegistry, get_store_for
from atlas_mcp.store import Project, new_project_body


def test_tenant_registry():
    d = tempfile.mkdtemp()
    path = os.path.join(d, "tenants.json")
    reg = TenantRegistry(path)
    assert not reg.is_allowed("alice", 1)
    reg.add("alice", 1)
    assert reg.is_allowed("alice", 1)
    assert not reg.is_allowed("bob", 2)
    assert reg.list() == ["alice"]
    # a recycled username (same string, different immutable GitHub id) must fail
    assert not reg.is_allowed("alice", 999), "recycled username must not inherit the tenant"
    assert not reg.is_allowed("alice", None)
    # legacy/bootstrap entry (no id yet) is claimed by the first login, then bound
    reg.add("owner")
    assert not reg.is_allowed("owner", None)
    assert reg.is_allowed("owner", 7)
    assert not reg.is_allowed("owner", 8), "first login binds the identity"
    # removal by editing the file takes effect at once, and add() cannot undo it
    import json
    data = json.load(open(path)); del data["alice"]; json.dump(data, open(path, "w"))
    assert not reg.has("alice") and not reg.is_allowed("alice", 1)
    reg.add("carol", 3)
    assert not reg.has("alice"), "add() must not write a stale snapshot back"
    print("tenant registry: OK")


def test_invite_registry():
    d = tempfile.mkdtemp()
    reg = InviteRegistry(os.path.join(d, "invites.json"))
    token = reg.create()
    assert reg.redeem(token) is True
    assert reg.redeem(token) is False, "an invite must not be redeemable twice"

    expired = reg.create(ttl_seconds=-1)
    assert reg.redeem(expired) is False, "an expired invite must not redeem"
    print("invite registry: OK")


def test_invite_registry_cross_process():
    # Simulates the real deployment shape: `python -m atlas_mcp.invite` mints
    # in one process, the running server redeems in another. Two separate
    # InviteRegistry objects pointed at the same file, standing in for that.
    d = tempfile.mkdtemp()
    path = os.path.join(d, "invites.json")
    minter = InviteRegistry(path)
    server = InviteRegistry(path)

    token = minter.create()
    assert server.is_valid(token), "the 'server' instance must see an invite minted by another instance"
    assert server.redeem(token) is True
    assert minter.is_valid(token) is False, "redeeming via one instance must be visible to the other"
    print("invite registry cross-process: OK")


def test_isolation():
    d = tempfile.mkdtemp()
    alice = get_store_for("alice", d)
    bob = get_store_for("bob", d)
    assert alice.root != bob.root

    alice.save(Project(id="secret-project", meta={"name": "secret-project"}, body=new_project_body("alice's plan")))
    assert alice.exists("secret-project")
    assert not bob.exists("secret-project"), "bob's store must not see alice's project"
    try:
        bob.load("secret-project")
        raise SystemExit("bob loaded alice's project -- cross-tenant leak")
    except Exception as e:
        assert "No project" in str(e)
    assert bob.all() == []
    assert bob.search("alice") == []
    print("tenant isolation: OK")


test_tenant_registry()
test_invite_registry()
test_invite_registry_cross_process()
test_isolation()
